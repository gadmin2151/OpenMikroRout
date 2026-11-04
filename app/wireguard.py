"""Ownership-scoped WireGuard configuration and encrypted runtime recovery."""

import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from app.compiler import FirewallError
from app.links import OWNER_PREFIX, LinkDriver, ownership
from app.network_models import NetworkConfiguration
from app.wireguard_profiles import kernel_profile
from app.wireguard_vault import WireGuardVault

MAX_WG_OUTPUT = 1_048_576
WG_MARK_PREFIX = 0x4F4D0000


class WireGuardError(FirewallError):
    pass


class WireGuardCommand(Protocol):
    def __call__(self, arguments: list[str], payload: str | None = None) -> str: ...


def wireguard_mark(table: int) -> int:
    return WG_MARK_PREFIX | (table - 20000 + 1)


def atomic_state(path: Path, value: dict[str, Any]) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
            temporary = stream.name
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def execute_wireguard(arguments: list[str], payload: str | None = None) -> str:
    try:
        result = subprocess.run(
            arguments,
            input=payload,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WireGuardError("WireGuard command failed or exceeded its timeout") from exc
    if result.returncode or len(result.stdout.encode()) > MAX_WG_OUTPUT:
        # wg diagnostics may contain the rejected private key. Never echo stderr.
        raise WireGuardError(
            "WireGuard rejected the operation; check tools, kernel and key settings"
        )
    return result.stdout


def resolve_ipv4(host: str) -> str:
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    binary = shutil.which("getent")
    if not binary:
        raise WireGuardError("IPv4 endpoint resolution requires the system getent utility")
    try:
        result = subprocess.run(
            [binary, "ahostsv4", host],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[:32]:
                return str(ipaddress.IPv4Address(line.split()[0]))
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        pass
    raise WireGuardError("Cannot resolve the WireGuard endpoint to IPv4")


def parse_wireguard_status(name: str, output: str, now: float) -> dict[str, Any]:
    try:
        lines = output.splitlines()
        header = lines[0].split("\t")
        if len(header) != 4 or len(lines) > 257:
            raise ValueError("Invalid WireGuard output")
        peers = []
        for line in lines[1:]:
            row = line.split("\t")
            if len(row) != 8:
                raise ValueError("Invalid WireGuard peer output")
            last = int(row[4])
            age = max(0, now - last) if last and last <= now + 5 else None
            peers.append(
                {
                    "public_key": row[0],
                    "endpoint": "" if row[2] == "(none)" else row[2],
                    "allowed_ips": [] if row[3] == "(none)" else row[3].split(","),
                    "latest_handshake": last or None,
                    "handshake_age_seconds": age,
                    "rx_bytes": int(row[5]),
                    "tx_bytes": int(row[6]),
                    "persistent_keepalive": 0 if row[7] == "off" else int(row[7]),
                    "connected": age is not None and age <= 180,
                }
            )
        return {
            "name": name,
            "public_key": header[1],
            "listen_port": int(header[2]),
            "peers": peers,
        }
    except (ValueError, IndexError) as exc:
        raise WireGuardError("WireGuard returned an invalid status response") from exc


class LinuxWireGuardDriver:
    def __init__(
        self,
        data_dir: Path,
        initial: NetworkConfiguration,
        links: LinkDriver,
        vault: WireGuardVault,
        *,
        runner: WireGuardCommand = execute_wireguard,
        resolver: Callable[[str], str] = resolve_ipv4,
    ) -> None:
        self.directory = data_dir
        self.path = data_dir / "wireguard-state.json"
        self.config = initial
        self.links, self.vault, self.runner, self.resolver = links, vault, runner, resolver
        self.binary = shutil.which("wg")
        self.transaction: str | None = None
        self.prepared: dict[str, str] = {}
        self.prepared_at = 0.0

    def _state(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "managed": {}, "endpoints": {}, "intent": None}
        try:
            if self.path.is_symlink() or self.path.stat().st_size > MAX_WG_OUTPUT:
                raise ValueError("Invalid WireGuard state file")
            value = json.loads(self.path.read_text())
            if (
                not isinstance(value, dict)
                or value.get("version") != 1
                or not isinstance(value.get("endpoints"), dict)
            ):
                raise ValueError("Invalid WireGuard state")
            return value
        except (OSError, ValueError) as exc:
            raise WireGuardError("WireGuard ownership state cannot be read") from exc

    def _live(self) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in self.links.status().get("links", [])}

    def _wg(self, *arguments: str, payload: str | None = None) -> str:
        if not self.binary:
            raise WireGuardError("Install wireguard-tools before applying WireGuard settings")
        return self.runner([self.binary, *arguments], payload)

    def _resolved(self, target: NetworkConfiguration) -> dict[str, str]:
        enabled = {item.name for item in target.wireguard_interfaces if item.enabled}
        hosts = {
            peer.endpoint_host
            for peer in target.wireguard_peers
            if peer.enabled and peer.interface in enabled and peer.endpoint_host
        }
        if len(hosts) > 32:
            raise WireGuardError("At most 32 distinct WireGuard endpoint hostnames are supported")
        previous = self._state()["endpoints"]
        result: dict[str, str] = {}
        deadline = time.monotonic() + 10
        for host in sorted(hosts):
            if time.monotonic() > deadline:
                raise WireGuardError("WireGuard endpoint resolution exceeded its time budget")
            try:
                result[host] = str(ipaddress.IPv4Address(self.resolver(host)))
            except WireGuardError:
                # Preserve boot availability during an upstream DNS outage. The
                # peer public key still authenticates a cached or roaming endpoint.
                if host not in previous:
                    raise
                result[host] = str(ipaddress.IPv4Address(previous[host]))
        self.prepared, self.prepared_at = result, time.monotonic()
        return result

    def snapshot(self, previous: NetworkConfiguration) -> dict[str, Any]:
        self.transaction = secrets.token_hex(16)
        observed = {}
        for name, link in self._live().items():
            if link.get("kind") == "wireguard" and str(link.get("alias", "")).startswith(
                OWNER_PREFIX
            ):
                observed[name] = {
                    "alias": link["alias"],
                    "sealed": self.vault.seal_runtime(name, self._wg("showconf", name)),
                }
        return {
            "version": 1,
            "transaction": self.transaction,
            "interfaces": observed,
            "state": self._state(),
            "configuration": previous.model_dump(mode="json"),
        }

    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        if not target.wireguard_interfaces and not previous.wireguard_interfaces:
            return
        if not self.binary:
            raise WireGuardError("Install wireguard-tools before applying WireGuard settings")
        try:
            self.vault.validate(target)
            endpoints = self._resolved(target)
            for interface in target.wireguard_interfaces:
                kernel_profile(interface, target.wireguard_peers, self.vault, endpoints)
        except (ValueError, RuntimeError) as exc:
            raise WireGuardError(
                "WireGuard keys or configuration are unavailable; check its private backup"
            ) from exc

    def preview(
        self, previous: NetworkConfiguration, target: NetworkConfiguration
    ) -> dict[str, Any]:
        return {
            "interfaces": [
                {
                    "name": item.name,
                    "public_key": item.public_key,
                    "listen_port": item.listen_port,
                    "enabled": item.enabled,
                    "peer_count": sum(
                        peer.enabled and peer.interface == item.name
                        for peer in target.wireguard_peers
                    ),
                    "keys": "hidden",
                }
                for item in target.wireguard_interfaces
            ],
            "note": "WireGuard secrets are encrypted; no private keys appear in this preview.",
        }

    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        if self.transaction is None:
            raise WireGuardError("A WireGuard recovery snapshot is required")
        if not target.wireguard_interfaces and not previous.wireguard_interfaces:
            return
        live = self._live()
        for interface in target.wireguard_interfaces:
            link = live.get(interface.name)
            if (
                not link
                or link.get("kind") != "wireguard"
                or link.get("alias") != ownership(interface)
            ):
                raise WireGuardError("WireGuard interface ownership cannot be verified")
        endpoints = (
            self.prepared if time.monotonic() - self.prepared_at < 15 else self._resolved(target)
        )
        state = self._state()
        state.update(
            {
                "managed": {item.name: str(item.id) for item in target.wireguard_interfaces},
                "endpoints": {**state["endpoints"], **endpoints},
                "intent": {
                    "transaction": self.transaction,
                    "target": target.model_dump(mode="json"),
                },
            }
        )
        atomic_state(self.path, state)
        try:
            for interface in target.wireguard_interfaces:
                profile = kernel_profile(
                    interface,
                    target.wireguard_peers if interface.enabled else [],
                    self.vault,
                    endpoints,
                    fwmark=wireguard_mark(interface.routing_table)
                    if interface.route_allowed_ips
                    else 0,
                )
                self._wg("syncconf", interface.name, "/dev/stdin", payload=profile)
        except (ValueError, RuntimeError) as exc:
            raise WireGuardError("Cannot configure WireGuard private material") from exc
        self.config = target

    def rollback(self, snapshot: dict[str, Any]) -> None:
        state = self._state()
        intent = state.get("intent")
        if not intent or intent.get("transaction") != snapshot.get("transaction"):
            return
        live = self._live()
        try:
            for name, record in snapshot["interfaces"].items():
                if (
                    name not in live
                    or live[name].get("alias") != record["alias"]
                    or live[name].get("kind") != "wireguard"
                ):
                    raise WireGuardError("WireGuard ownership changed before recovery")
                self._wg(
                    "syncconf",
                    name,
                    "/dev/stdin",
                    payload=self.vault.open_runtime(name, record["sealed"]),
                )
            target = NetworkConfiguration.model_validate(intent["target"])
            for interface in target.wireguard_interfaces:
                if interface.name not in snapshot["interfaces"] and interface.name in live:
                    if live[interface.name].get("alias") != ownership(interface):
                        raise WireGuardError(
                            "New WireGuard interface ownership changed before recovery"
                        )
                    self._wg("set", interface.name, "private-key", "/dev/null")
            atomic_state(self.path, snapshot["state"])
            self.config = NetworkConfiguration.model_validate(snapshot["configuration"])
        except (OSError, ValueError, RuntimeError) as exc:
            raise WireGuardError(
                "WireGuard recovery failed; keep the private snapshot for retry"
            ) from exc

    def status(self) -> dict[str, Any]:
        if not self.binary:
            return {
                "available": False,
                "demo": False,
                "interfaces": [],
                "error": "Install wireguard-tools",
            }
        live = self._live()
        interfaces = []
        for item in self.config.wireguard_interfaces:
            observed = live.get(item.name)
            if (
                not observed
                or observed.get("kind") != "wireguard"
                or observed.get("alias") != ownership(item)
            ):
                interfaces.append(
                    {"name": item.name, "available": False, "enabled": item.enabled, "peers": []}
                )
                continue
            status = parse_wireguard_status(
                item.name, self._wg("show", item.name, "dump"), time.time()
            )
            status.update({"available": True, "enabled": item.enabled, "role": item.role})
            interfaces.append(status)
        return {"available": True, "demo": False, "interfaces": interfaces, "error": ""}


class DemoWireGuardDriver:
    def __init__(self, initial: NetworkConfiguration, vault: WireGuardVault) -> None:
        self.config, self.vault = initial, vault

    def snapshot(self, previous: NetworkConfiguration) -> dict[str, Any]:
        return {"configuration": self.config.model_dump(mode="json")}

    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        self.vault.validate(target)

    def preview(
        self, previous: NetworkConfiguration, target: NetworkConfiguration
    ) -> dict[str, Any]:
        return {
            "demo": True,
            "interfaces": [item.name for item in target.wireguard_interfaces],
            "keys": "hidden",
        }

    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        self.config = target

    def rollback(self, snapshot: dict[str, Any]) -> None:
        self.config = NetworkConfiguration.model_validate(snapshot["configuration"])

    def status(self) -> dict[str, Any]:
        return {
            "available": True,
            "demo": True,
            "error": "",
            "interfaces": [
                {
                    "name": item.name,
                    "public_key": item.public_key,
                    "listen_port": item.listen_port,
                    "enabled": item.enabled,
                    "available": True,
                    "role": item.role,
                    "peers": [
                        {
                            "public_key": peer.public_key,
                            "endpoint": f"{peer.endpoint_host}:{peer.endpoint_port}"
                            if peer.endpoint_host
                            else "",
                            "allowed_ips": peer.allowed_ips,
                            "latest_handshake": None,
                            "handshake_age_seconds": None,
                            "rx_bytes": 0,
                            "tx_bytes": 0,
                            "persistent_keepalive": peer.persistent_keepalive,
                            "connected": False,
                        }
                        for peer in self.config.wireguard_peers
                        if peer.interface == item.name and peer.enabled
                    ],
                }
                for item in self.config.wireguard_interfaces
            ],
        }
