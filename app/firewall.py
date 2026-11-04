"""Firewall adapters and the durable apply/confirm/rollback state machine."""

import hmac
import logging
import os
import secrets
import shutil
import subprocess
import threading
import time
from typing import Any, Protocol

from app.compiler import FirewallError, counters, patch, rollback_patch
from app.models import Configuration
from app.runtime import RouterRuntime
from app.storage import Store
from app.transitions import validate_link_removals

log = logging.getLogger(__name__)
EMPTY_NAT = (
    "*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n"
    ":OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n"
)


class Driver(Protocol):
    def snapshot(self, with_counters: bool = False) -> str: ...
    def restore(self, payload: str, test: bool = False) -> None: ...


class LinuxDriver:
    def __init__(self) -> None:
        save = shutil.which("iptables-save")
        restore = shutil.which("iptables-restore")
        if not save or not restore:
            raise RuntimeError("Linux mode requires iptables-save and iptables-restore")
        self.save_bin = save
        self.restore_bin = restore

    @staticmethod
    def run(args: list[str], payload: str | None = None) -> str:
        try:
            result = subprocess.run(
                args,
                input=payload,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(
                "iptables command failed or exceeded the 15-second timeout"
            ) from exc
        if result.returncode:
            # Only administrator-supplied network configuration reaches this diagnostic.
            detail = result.stderr.strip()[:500]
            raise FirewallError(f"iptables rejected the operation: {detail}")
        return result.stdout

    def snapshot(self, with_counters: bool = False) -> str:
        args = [self.save_bin, "-t", "nat"]
        if with_counters:
            args.append("-c")
        return (
            "\n".join(
                line for line in self.run(args).splitlines() if line and not line.startswith("#")
            )
            + "\n"
        )

    def restore(self, payload: str, test: bool = False) -> None:
        args = [self.restore_bin, "--noflush", "--wait", "5"]
        if test:
            args.append("--test")
        self.run(args, payload)


class DemoDriver:
    """In-memory table emulator. Never executes a system command."""

    def __init__(self, config: Configuration) -> None:
        self.table = EMPTY_NAT
        self.restore(patch(self.table, config))

    def snapshot(self, with_counters: bool = False) -> str:
        return self.table

    def restore(self, payload: str, test: bool = False) -> None:
        if test:
            return
        lines = self.table.splitlines()
        for line in payload.splitlines():
            if line.startswith(":"):
                chain = line.split()[0][1:]
                lines = [item for item in lines if not item.startswith(f"-A {chain} ")]
                if not any(item.startswith(f":{chain} ") for item in lines):
                    lines.insert(1, line)
            elif line.startswith("-A "):
                lines.insert(lines.index("COMMIT"), line)
            elif line.startswith("-D "):
                target = "-A " + line[3:]
                lines = [item for item in lines if item != target]
        self.table = "\n".join(lines) + "\n"


class Conflict(Exception):
    pass


class FirewallService:
    def __init__(
        self,
        store: Store,
        driver: Driver,
        confirm_seconds: int = 60,
        runtime: RouterRuntime | None = None,
    ) -> None:
        self.store = store
        self.driver = driver
        self.confirm_seconds = confirm_seconds
        self.lock = threading.RLock()
        self.runtime = runtime

    def config(self) -> Configuration:
        return Configuration.model_validate(self.store.read("config"))

    def check_revision(self, revision: int) -> None:
        if revision != self.store.read("revision"):
            raise Conflict("Configuration changed in another session. Refresh before trying again.")
        if self.store.read("pending"):
            raise Conflict("Confirm or roll back the pending application first")

    def save(self, config: Configuration, revision: int) -> dict[str, Any]:
        with self.lock:
            self.check_revision(revision)
            try:
                validate_link_removals(self.config(), config)
            except ValueError as exc:
                raise Conflict(str(exc)) from exc
            self.store.write(
                {"config": config.model_dump(mode="json"), "revision": revision + 1},
                "saved",
                f"{len(config.rules)} NAT, {len(config.filter_rules)} filter rules; "
                f"revision {revision + 1}",
            )
            return self.state()

    def discard(self, revision: int) -> dict[str, Any]:
        with self.lock:
            self.check_revision(revision)
            self.store.write(
                {"config": self.store.read("applied"), "revision": revision + 1},
                "discarded",
                "Draft restored to the last confirmed configuration",
            )
            return self.state()

    def preview(self) -> dict[str, Any]:
        with self.lock:
            target = self.config()
            previous = Configuration.model_validate(self.store.read("applied"))
            payload = patch(self.driver.snapshot(), target)
            self.driver.restore(payload, test=True)
            router: dict[str, Any] = {}
            if self.runtime:
                self.runtime.check(previous, target)
                router = self.runtime.preview(previous, target)
            return {"script": payload, "valid": True, "router": router}

    def apply(self, revision: int) -> dict[str, Any]:
        with self.lock:
            self.check_revision(revision)
            return self._apply_target(self.config(), revision)

    def _apply_target(
        self, config: Configuration, revision: int, event: str = "applying"
    ) -> dict[str, Any]:
        with self.lock:
            previous = Configuration.model_validate(self.store.read("applied"))
            snapshot = self.driver.snapshot()
            payload = patch(snapshot, config)
            self.driver.restore(payload, test=True)
            router_snapshot: dict[str, Any] = {}
            if self.runtime:
                self.runtime.check(previous, config)
                router_snapshot = self.runtime.snapshot(previous)
            pending = {
                "snapshot": snapshot,
                "config": config.model_dump(mode="json"),
                "deadline": time.time() + self.confirm_seconds,
                "token": secrets.token_urlsafe(32),
                "error": None,
                "attempts": 0,
                "next_retry": 0,
                "router_snapshot": router_snapshot,
            }
            # Commit recovery data before touching the kernel.
            self.store.write({"pending": pending}, event, f"Revision {revision}")
            try:
                if self.runtime:
                    self.runtime.apply(previous, config)
                self.driver.restore(payload)
            except (FirewallError, OSError) as exc:
                try:
                    self.rollback("Apply failed; previous managed router settings restored")
                except FirewallError as recovery_error:
                    raise FirewallError(f"Apply failed: {exc}; recovery: {recovery_error}") from exc
                self.store.write({"runtime_error": str(exc)}, "apply_failed", str(exc))
                raise FirewallError(str(exc)) from exc
            pending["deadline"] = time.time() + self.confirm_seconds
            self.store.write(
                {"pending": pending, "runtime_error": None},
                "applied",
                "Waiting for connectivity confirmation",
            )
            return self.state()

    def restore_confirmed(self) -> None:
        """Reconcile the last confirmed router state after a Linux service/host restart."""
        with self.lock:
            if self.store.read("pending"):
                return
            confirmed = Configuration.model_validate(self.store.read("applied"))
            state = self._apply_target(confirmed, self.store.read("revision"), "restoring")
            self.confirm(state["pending"]["token"])

    def confirm(self, token: str) -> dict[str, Any]:
        with self.lock:
            pending = self.store.read("pending")
            if not pending:
                raise Conflict("There is no pending application")
            if time.time() >= pending["deadline"]:
                self.rollback("Confirmation deadline expired")
                raise Conflict("Confirmation deadline expired; previous rules restored")
            if not hmac.compare_digest(token, pending["token"]):
                raise Conflict("Invalid confirmation token")
            if pending.get("error"):
                raise Conflict("Rollback needs attention; confirmation is unavailable")
            self.store.write(
                {"applied": pending["config"], "pending": None, "runtime_error": None},
                "confirmed",
                "Managed router configuration confirmed",
            )
            return self.state()

    def rollback(self, reason: str = "Manually rolled back") -> dict[str, Any]:
        with self.lock:
            pending = self.store.read("pending")
            if not pending:
                raise Conflict("There is no pending application")
            errors: list[str] = []
            try:
                payload = rollback_patch(self.driver.snapshot(), pending["snapshot"])
                self.driver.restore(payload, test=True)
                self.driver.restore(payload)
            except (FirewallError, OSError) as exc:
                errors.append(f"NAT recovery: {exc}")
            if self.runtime and pending.get("router_snapshot"):
                try:
                    self.runtime.rollback(pending["router_snapshot"])
                except (FirewallError, OSError) as exc:
                    errors.append(str(exc))
            if errors:
                detail = "; ".join(errors)[:1500]
                pending["error"] = detail
                pending["attempts"] = pending.get("attempts", 0) + 1
                pending["next_retry"] = time.time() + min(2 ** min(pending["attempts"], 5), 30)
                self.store.write(
                    {"pending": pending, "runtime_error": detail}, "rollback_failed", detail
                )
                raise FirewallError(detail)
            self.store.write({"pending": None, "runtime_error": None}, "rolled_back", reason)
            return self.state()

    def recover(self, startup: bool = False) -> None:
        with self.lock:
            pending = self.store.read("pending")
            if pending and pending.get("error"):
                if pending.get("attempts", 0) >= 5:
                    return
                if not startup and time.time() < pending.get("next_retry", 0):
                    return
            if pending and (startup or time.time() >= pending["deadline"] or pending.get("error")):
                self.rollback(
                    "Recovered after restart" if startup else "Confirmation deadline expired"
                )

    def state(self) -> dict[str, Any]:
        with self.lock:
            config = self.store.read("config")
            pending = self.store.read("pending")
            return {
                "config": config,
                "revision": self.store.read("revision"),
                "dirty": config != self.store.read("applied"),
                "runtime_error": self.store.read("runtime_error"),
                "pending": {key: pending[key] for key in ("deadline", "token", "error")}
                if pending
                else None,
            }

    def statistics(self) -> dict[str, dict[str, int]]:
        with self.lock:
            values = counters(self.driver.snapshot(with_counters=True))
            if self.runtime:
                values.update(self.runtime.counters())
            return values

    def network_status(self) -> dict[str, Any]:
        with self.lock:
            return self.runtime.status() if self.runtime else {}
