"""Own the native companion handle and bounded files; never adopt a PID from disk."""

import hashlib
import json
import logging
import os
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.application_catalog import ApplicationCatalog
from app.application_integrity import native_inventory
from app.application_policy import (
    CT_MASK,
    CT_PENDING,
    CT_VALID,
    EPOCH_SHIFT,
    active,
    queue_patch,
    resolve_policy,
)
from app.application_preflight import (
    competing_nft_datapath,
    read_nft_ruleset,
    verify_iptables_queue,
)
from app.compiler import FirewallError
from app.list_filters import FieldSpec, compile_expression, parse_expression
from app.models import Configuration

log = logging.getLogger(__name__)
FLOW_SCHEMA = {
    "application_id": FieldSpec("text"),
    "source": FieldSpec("ipv4"),
    "destination": FieldSpec("ipv4"),
    "protocol": FieldSpec("enum", options=("tcp", "udp")),
    "classification_state": FieldSpec(
        "enum", options=("pending", "detected", "unknown", "unsupported")
    ),
    "decision": FieldSpec("enum", options=("allow", "block", "probe", "fallback")),
    "state": FieldSpec("text"),
    "interface": FieldSpec("text"),
    "packets": FieldSpec("number"),
    "bytes": FieldSpec("number"),
}


class NativeFlow(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    id: str = Field(min_length=1, max_length=80)
    application_id: str = Field(default="", max_length=80)
    source: str = Field(max_length=15)
    destination: str = Field(max_length=15)
    source_port: int = Field(default=0, ge=0, le=65535)
    destination_port: int = Field(default=0, ge=0, le=65535)
    protocol: Literal["tcp", "udp"]
    in_interface: str = Field(default="", max_length=15)
    out_interface: str = Field(default="", max_length=15)
    connection_state: str = Field(default="UNKNOWN", max_length=32, pattern=r"^[A-Z_]+$")
    classification_state: Literal["pending", "detected", "unknown", "unsupported"] = "unknown"
    decision: Literal["allow", "block", "probe", "fallback"] = "fallback"
    counters_complete: Literal[False] = False
    counter_source: Literal["classification", "capture"] = "classification"
    interface_basis: Literal["capture", "netfilter"] = "netfilter"
    translated_destination: str = Field(default="", max_length=15)
    translated_port: int = Field(default=0, ge=0, le=65535)
    method: str = Field(default="unknown", max_length=64)
    reason: str = Field(default="", max_length=128)
    rule_id: str = Field(default="", max_length=40)
    protocol_name: str = Field(default="", max_length=100)
    packets: int = Field(default=0, ge=0, le=2**64 - 1)
    bytes: int = Field(default=0, ge=0, le=2**64 - 1)
    first_seen: float = Field(ge=0, allow_inf_nan=False)
    last_seen: float = Field(ge=0, allow_inf_nan=False)

    @field_validator("source", "destination")
    @classmethod
    def address(cls, value: str) -> str:
        import ipaddress

        return str(ipaddress.IPv4Address(value))


class NativeStatus(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    schema_version: Literal[1] = Field(default=1, alias="schema")
    generation: str = Field(pattern=r"^[a-f0-9]{64}$")
    healthy: bool
    packets: int = Field(default=0, ge=0, le=2**64 - 1)
    flows: int = Field(default=0, ge=0, le=2**32 - 1)
    updated_at: float = Field(ge=0, allow_inf_nan=False)
    error: str = Field(default="", max_length=300)


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ApplicationRuntime:
    def __init__(
        self,
        data_dir: Path,
        catalog: ApplicationCatalog,
        *,
        demo: bool = False,
        binary: Path | None = None,
    ) -> None:
        self.catalog, self.directory, self.demo = catalog, catalog.directory, demo
        # The stock updater preserves this directory across data rollback.
        self.epoch_registry = data_dir / "updates/application-epoch.json"
        self.binary = binary or Path(__file__).parent / "native/bin/omr-app-supervisor"
        self.require_inventory = binary is None
        self.process: subprocess.Popen[bytes] | None = None
        self.lock = threading.RLock()
        self.config = Configuration()
        self.policy: dict[str, Any] | None = None
        self.error = ""
        self.cached_capabilities: dict[str, Any] = {}
        self.capabilities_at = 0.0
        self.binary_identity: tuple[tuple[int, int, int, int, int], ...] | None = None
        self.inventory_files: list[Path] = []
        self.receipt_identity = ""
        self.epochs: dict[str, int] = {}
        self.history = self.directory / "events.sqlite3"
        with closing(sqlite3.connect(self.history)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,"
                "event_key TEXT UNIQUE NOT NULL,time REAL NOT NULL,payload TEXT NOT NULL)"
            )
        self.last_events = 0.0

    def _json_file(self, path: Path, limit: int) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise ValueError("Native application state file is missing or exceeds its limit")
        with path.open("rb") as stream:
            value = json.loads(stream.read(limit + 1))
        if not isinstance(value, dict):
            raise ValueError("Invalid native application state")
        return value

    def _command(self, *arguments: str) -> dict[str, Any]:
        mode = self.binary.stat()
        if (
            not stat.S_ISREG(mode.st_mode)
            or self.binary.is_symlink()
            or mode.st_mode & 0o022
            or mode.st_uid not in (0, os.geteuid())
            or not os.access(self.binary, os.X_OK)
        ):
            raise ValueError("The application companion is not an owned executable")
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run(
                [str(self.binary), *arguments],
                stdout=output,
                stderr=errors,
                timeout=5,
                check=False,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
            output.seek(0)
            raw = output.read(262145)
        if result.returncode or len(raw) > 262144:
            raise ValueError("The native application companion failed validation")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise ValueError("Unsupported application companion protocol")
        return value

    def capabilities(self) -> dict[str, Any]:
        from app.third_party_license import load_acceptance

        receipt = None
        receipt_error = ""
        if not self.demo:
            try:
                receipt = load_acceptance()
            except (OSError, ValueError) as exc:
                receipt_error = str(exc)
        receipt_identity = hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        identity_parts = []
        for path in [
            self.binary,
            self.binary.parent.parent / "manifest.json",
            *self.inventory_files,
        ]:
            try:
                info = path.stat()
                identity_parts.append(
                    (info.st_mtime_ns, info.st_size, info.st_ino, info.st_uid, info.st_mode)
                )
            except OSError:
                identity_parts.append((-1, -1, -1, -1, -1))
        identity = tuple(identity_parts)
        if (
            self.cached_capabilities
            and identity == self.binary_identity
            and receipt_identity == self.receipt_identity
            and time.monotonic() - self.capabilities_at < 30
        ):
            return dict(self.cached_capabilities)
        try:
            if self.demo:
                raise ValueError(
                    "Demo mode does not inspect host packets or simulate application detection"
                )
            if receipt is None:
                raise ValueError(receipt_error or "nDPI license acceptance is required")
            inventory_digest = ""
            if (self.binary.parent.parent / "manifest.json").exists():
                inventory_digest, self.inventory_files = native_inventory(self.binary)
            elif self.require_inventory:
                raise ValueError("The installed native companion inventory is missing")
            raw = self._command("capabilities", "--json", "--license-profile", receipt["profile"])
            engine = raw.get("engine", {})
            protocols = raw.get("protocols", [])
            if (
                not isinstance(engine, dict)
                or not isinstance(protocols, list)
                or len(protocols) > 2048
                or any(
                    not isinstance(item, dict)
                    or not isinstance(item.get("name"), str)
                    or len(item["name"]) > 100
                    for item in protocols
                )
            ):
                raise ValueError("Invalid native engine capabilities")
            layout_valid = (
                all(
                    raw.get(key) == value
                    for key, value in {
                        "ct_mask": CT_MASK,
                        "ct_valid_bit": CT_VALID,
                        "ct_pending_bit": CT_PENDING,
                        "ct_epoch_shift": EPOCH_SHIFT,
                    }.items()
                )
                and raw.get("ct_metadata") == "NFQA_CT/CTA_MARK_MASK"
            )
            digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
            verified = False
            allow = False
            try:
                proof_path = self.directory / "kernel-proof.json"
                proof = self._json_file(proof_path, 8192)
                if proof_path.stat().st_mode & 0o077 or proof_path.stat().st_uid != os.geteuid():
                    raise ValueError("The kernel proof must be private")
                verified = (
                    proof.get("schema") == 1
                    and bool(inventory_digest)
                    and proof.get("native_inventory_sha256") == inventory_digest
                    and proof.get("engine_license_profile") == receipt["profile"]
                    and proof.get("binary_sha256") == digest
                    and proof.get("kernel_release") == os.uname().release
                    and all(
                        proof.get(key) is True
                        for key in (
                            "first_syn",
                            "mask_preservation",
                            "failure_recovery",
                            "application_block",
                        )
                    )
                )
                allow = verified and proof.get("application_allow") is True
            except (OSError, ValueError):
                pass  # An absent/obsolete proof disables enforcement, never enables it.
            result = {
                "available": raw.get("available") is True,
                "observe": raw.get("observe") is True,
                "enforce": raw.get("enforce") is True and verified and layout_valid,
                "allow_over_port_deny": allow and layout_valid,
                "kernel_verified": verified and layout_valid,
                "engine": engine,
                "protocols": protocols,
                "error": ""
                if verified
                else "Enforcement requires the target-kernel namespace proof; Observe is available",
                "binary_sha256": digest,
                "native_inventory_sha256": inventory_digest,
                "license_profile": receipt["profile"],
            }
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
            result = {
                "available": False,
                "observe": False,
                "enforce": False,
                "allow_over_port_deny": False,
                "kernel_verified": False,
                "engine": {"name": "ndpi", "version": "", "profile": "unavailable"},
                "protocols": [],
                "license_profile": "lgpl-only",
                "error": str(exc)[:300],
            }
        self.receipt_identity = receipt_identity
        self.cached_capabilities, self.capabilities_at, self.binary_identity = (
            result,
            time.monotonic(),
            identity,
        )
        return dict(result)

    def policy_for(self, config: Configuration) -> dict[str, Any]:
        settings = config.applications
        capabilities = self.capabilities()
        key = hashlib.sha256(
            json.dumps(
                {
                    # NAT and every routing/link dependency can change a flow's
                    # post-DNAT destination or current ingress/egress scope.
                    "configuration": config.model_dump(mode="json"),
                    "binary_sha256": capabilities.get("binary_sha256", ""),
                    "native_inventory_sha256": capabilities.get("native_inventory_sha256", ""),
                    "license_profile": capabilities.get("license_profile", "lgpl-only"),
                    "engine": capabilities.get("engine", {}),
                    "protocols": capabilities.get("protocols", []),
                    "enforce": capabilities.get("enforce", False),
                    "allow_over_port_deny": capabilities.get("allow_over_port_deny", False),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        if not settings.enabled:
            return resolve_policy(
                config,
                self.catalog.entries(settings.catalog_version, capabilities),
                1,
                engine_license_profile=capabilities.get("license_profile", "lgpl-only"),
            )
        if key not in self.epochs:
            registry = self.epoch_registry
            registry.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            legacy = self.directory / "epoch.json"
            previous = self._json_file(registry, 8192) if registry.exists() else {}
            older = self._json_file(legacy, 8192) if legacy.exists() else {}
            values = [previous.get("last", 0), older.get("last", 0)]
            if any(type(value) is not int or not 0 <= value <= 65535 for value in values):
                raise ValueError("Invalid durable application epoch registry")
            epoch = max(values) + 1
            if epoch > 65535:
                raise ValueError(
                    "Application epoch space requires an explicit drained metadata reset"
                )
            atomic_json(registry, {"last": epoch})
            if len(self.epochs) >= 64:
                self.epochs.pop(next(iter(self.epochs)))
            self.epochs[key] = epoch
        return resolve_policy(
            config,
            self.catalog.entries(settings.catalog_version, capabilities),
            self.epochs[key],
            engine_license_profile=capabilities.get("license_profile", "lgpl-only"),
        )

    def validate_config(self, config: Configuration) -> None:
        self.policy_for(config)

    def check(self, config: Configuration) -> None:
        policy = self.policy_for(config)
        if not config.applications.enabled:
            return
        capabilities = self.capabilities()
        if active(config) and not capabilities["enforce"]:
            raise FirewallError(str(capabilities["error"]))
        if active(config) and not self.demo:
            # A later connmark writer could forge or erase a profile; NOTRACK removes
            # the original tuple and cannot satisfy the mandatory metadata contract.
            import shlex

            from app.firewall import LinuxDriver

            table = ""
            for line in LinuxDriver.run(["iptables-save"]).splitlines():
                if line.startswith("*"):
                    table = line[1:]
                if not line.startswith("-A "):
                    continue
                tokens = shlex.split(line)
                verify_iptables_queue(tokens, allow_owned_mangle=table == "mangle")
                target = tokens[tokens.index("-j") + 1] if "-j" in tokens else ""
                if (
                    target in ("CONNMARK", "NOTRACK")
                    or "--notrack" in tokens
                    or "--helper" in tokens
                ):
                    raise FirewallError(
                        "Foreign connmark writers/NOTRACK/CT helpers conflict "
                        "with application enforcement"
                    )
            competing_nft_datapath(read_nft_ruleset())
            helper_setting = Path("/proc/sys/net/netfilter/nf_conntrack_helper")
            if helper_setting.exists() and helper_setting.read_text().strip() != "0":
                raise FirewallError(
                    "Automatic conntrack helpers are incompatible with Applications"
                )
        if active(config) and not capabilities["enforce"]:
            raise FirewallError(str(capabilities["error"]))
        if not capabilities["available"]:
            if active(config):
                raise FirewallError("Application enforcement requires the native companion")
            return
        path = self.directory / "check-policy.json"
        atomic_json(path, policy)
        try:
            self._command("validate", "--policy", str(path), "--json")
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(str(exc)) from exc

    def epoch_for(self, config: Configuration) -> int | None:
        return int(self.policy_for(config)["epoch"]) if active(config) else None

    def mangle_snapshot(self) -> str:
        if self.demo:
            return "*mangle\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
        from app.firewall import LinuxDriver

        return LinuxDriver.run(["iptables-save", "-t", "mangle"])

    def mangle_apply(
        self, snapshot: str, config: Configuration, epoch: int | None, *, test: bool = False
    ) -> None:
        if self.demo:
            return
        from app.firewall import LinuxDriver

        payload = queue_patch(snapshot, config, epoch)
        arguments = ["iptables-restore", "--noflush", "--wait", "5"]
        if test:
            arguments.append("--test")
        LinuxDriver.run(arguments, payload)

    def snapshot(self, previous: Configuration) -> dict[str, Any]:
        return {"configuration": previous.model_dump(mode="json")}

    def apply(self, target: Configuration) -> None:
        with self.lock:
            self.stop()
            self.config = target.model_copy(deep=True)
            self.policy = self.policy_for(target)
            self.error = ""
            if not target.applications.enabled:
                return
            try:
                capabilities = self.capabilities()
                if not capabilities["available"]:
                    raise ValueError("Native application companion is unavailable")
                if active(target) and not capabilities["enforce"]:
                    raise ValueError("Application enforcement proof or license is no longer valid")
                path = self.directory / "policy.json"
                atomic_json(path, self.policy)
                for name in ("status.json", "flows.json"):
                    (self.directory / name).unlink(missing_ok=True)
                self.process = subprocess.Popen(
                    [
                        str(self.binary),
                        "run",
                        "--policy",
                        str(path),
                        "--state-dir",
                        str(self.directory),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    env={"PATH": os.defpath, "LC_ALL": "C"},
                )
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    if self.process.poll() is not None:
                        raise ValueError("The application companion stopped during startup")
                    try:
                        state = self._json_file(self.directory / "status.json", 32768)
                        if (
                            state.get("generation") == self.policy["generation"]
                            and state.get("healthy") is True
                            and time.time() - float(state.get("updated_at", 0)) < 5
                        ):
                            return
                    except (OSError, ValueError):
                        pass  # Startup is bounded; the previous state may not yet exist.
                    time.sleep(0.02)
                raise ValueError("The application companion did not become ready")
            except (OSError, ValueError) as exc:
                self.error = str(exc)
                self.stop()
                if active(target):
                    raise FirewallError(str(exc)) from exc

    def rollback(self, snapshot: dict[str, Any]) -> None:
        self.apply(Configuration.model_validate(snapshot["configuration"]))

    def stop(self) -> None:
        with self.lock:
            process, self.process = self.process, None
            if process is None or process.poll() is not None:
                return
            try:
                process.terminate()
            except ProcessLookupError:
                process.wait(timeout=2)
                return
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def status(self) -> dict[str, Any]:
        capabilities = self.capabilities()
        native: dict[str, Any] = {}
        if self.process and self.process.poll() is None:
            try:
                native = NativeStatus.model_validate(
                    self._json_file(self.directory / "status.json", 32768)
                ).model_dump()
                if (
                    self.policy is None
                    or native.get("generation") != self.policy["generation"]
                    or time.time() - float(native.get("updated_at", 0)) > 5
                ):
                    raise ValueError("Native application heartbeat is stale")
            except (OSError, ValueError) as exc:
                self.error = str(exc)
                native = {}
        profile_valid = bool(
            self.policy
            and self.policy.get("engine_license_profile") == capabilities.get("license_profile")
        )
        healthy = bool(
            native.get("healthy") is True
            and capabilities["available"]
            and profile_valid
            and (not active(self.config) or capabilities["enforce"])
        )
        if native.get("healthy") is True and not healthy:
            self.error = (
                "Application engine license, profile, integrity or proof changed; reapply required"
            )
        engine = {
            **capabilities["engine"],
            "available": capabilities["available"],
            "capabilities": {
                key: capabilities[key] for key in ("observe", "enforce", "allow_over_port_deny")
            },
        }
        return {
            "enabled": self.config.applications.enabled,
            "mode": self.config.applications.mode,
            "available": capabilities["available"],
            "healthy": healthy,
            "engine": engine,
            "error": self.error or (capabilities["error"] if not capabilities["available"] else ""),
            "enforcement_error": capabilities["error"],
            "catalog": self.catalog.status(self.config.applications.catalog_version),
            "rules_count": len(self.config.applications.rules),
            "packets": int(native.get("packets", 0)),
            "flows": int(native.get("flows", 0)),
            "generation": self.policy.get("generation", "") if self.policy else "",
            "kernel_verified": capabilities["kernel_verified"],
            "demo": self.demo,
        }

    def connections(self, expression: str = "", offset: int = 0, limit: int = 50) -> dict[str, Any]:
        if not 0 <= offset <= 10000 or not 1 <= limit <= 500:
            raise ValueError("Invalid application monitor pagination")
        predicate = compile_expression(parse_expression(expression, FLOW_SCHEMA), FLOW_SCHEMA)
        rows = []
        status = self.status()
        if status["healthy"]:
            try:
                document = self._json_file(self.directory / "flows.json", 2 * 1024 * 1024)
                if (
                    document.get("generation") != status["generation"]
                    or not isinstance(document.get("items"), list)
                    or len(document["items"]) > 500
                ):
                    raise ValueError("Invalid native flow snapshot")
                for item in document["items"]:
                    flow = NativeFlow.model_validate(item).model_dump(mode="json")
                    flow.update(state=flow["connection_state"], interface=flow["in_interface"])
                    if predicate(flow):
                        rows.append(flow)
            except (OSError, ValueError) as exc:
                status["healthy"], status["error"] = False, str(exc)[:300]
        return {
            "items": rows[offset : offset + limit],
            "total": len(rows),
            "offset": offset,
            "limit": limit,
            "available": status["healthy"],
            "error": status["error"],
            "timestamp": time.time(),
            "counters_scope": "analyzed",
            "demo": self.demo,
        }

    def events(self, offset: int = 0, limit: int = 50) -> dict[str, Any]:
        if not 0 <= offset <= 10000 or not 1 <= limit <= 500:
            raise ValueError("Invalid application event pagination")
        with closing(sqlite3.connect(self.history)) as db:
            total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            rows = db.execute(
                "SELECT payload FROM events ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
        return {
            "items": [json.loads(row[0]) for row in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    def maintain(self) -> None:
        if not self.config.applications.enabled:
            return
        if time.monotonic() - self.last_events >= 1:
            self.last_events = time.monotonic()
            flows = self.connections(limit=500)["items"]
            with closing(sqlite3.connect(self.history)) as db, db:
                for flow in flows:
                    key = hashlib.sha256(
                        json.dumps(
                            [
                                self.policy.get("generation") if self.policy else "",
                                flow["id"],
                                flow["classification_state"],
                                flow["decision"],
                            ]
                        ).encode()
                    ).hexdigest()
                    db.execute(
                        "INSERT OR IGNORE INTO events(event_key,time,payload) VALUES(?,?,?)",
                        (key, time.time(), json.dumps(flow)),
                    )
                db.execute(
                    "DELETE FROM events WHERE id NOT IN "
                    "(SELECT id FROM events ORDER BY id DESC LIMIT 10000)"
                )
        settings = self.config.applications
        if (
            settings.catalog_auto_update
            and time.time() - self.catalog.last_check > settings.catalog_check_hours * 3600
        ):
            try:
                self.catalog.sync(True)
            except ValueError as exc:
                log.info("Application catalog check deferred: %s", exc)

    def close(self) -> None:
        self.stop()
        self.catalog.close()
