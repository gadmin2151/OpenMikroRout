"""Explicit source routing for VPN clients, with private tables and durable rollback."""

import json
import secrets
import shlex
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.network_models import NetworkConfiguration
from app.networking import run_command
from app.wireguard import WG_MARK_PREFIX, WireGuardError, atomic_state

FIRST_TABLE, LAST_TABLE = 20000, 20999
FIRST_PRIORITY, LAST_PRIORITY = 9000, 14000
PROTOCOL = 196
Entry = dict[str, Any]


def policy_entries(config: NetworkConfiguration) -> list[Entry]:
    result: list[Entry] = []
    for interface in config.wireguard_interfaces:
        if not interface.route_allowed_ips:
            continue
        prefixes = sorted(
            {
                prefix
                for peer in config.wireguard_peers
                if peer.interface == interface.name
                for prefix in peer.allowed_ips
                if peer.enabled or interface.kill_switch
            }
        )
        if not prefixes and not interface.kill_switch:
            continue
        table = interface.routing_table
        priority = 10000 + (table - FIRST_TABLE) * 4
        for source in interface.route_sources:
            # Honour connected/static LAN routes before the VPN's default route.
            result += [
                {
                    "kind": "rule",
                    "priority": priority,
                    "source": source,
                    "table": 254,
                    "suppress": 0,
                },
                {"kind": "rule", "priority": priority + 1, "source": source, "table": table},
            ]
        for prefix in prefixes:
            if interface.enabled and any(
                peer.enabled and peer.interface == interface.name and prefix in peer.allowed_ips
                for peer in config.wireguard_peers
            ):
                result.append(
                    {
                        "kind": "route",
                        "table": table,
                        "destination": prefix,
                        "device": interface.name,
                        "metric": 10,
                        "type": "unicast",
                    }
                )
        if interface.kill_switch:
            # Keep a default guard even when the last peer/prefix is removed.
            # Connected/static main routes remain exempt through the preceding rule.
            result.append(
                {
                    "kind": "route",
                    "table": table,
                    "destination": "0.0.0.0/0",
                    "device": "",
                    "metric": 32760,
                    "type": "unreachable",
                }
            )
    if result:
        result.insert(
            0,
            {
                "kind": "rule",
                "priority": 9000,
                "source": "all",
                "table": 254,
                "mark": WG_MARK_PREFIX,
                "mask": 0xFFFF0000,
            },
        )
    return result


def entry_key(entry: Entry) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def entry_command(binary: str, operation: str, entry: Entry) -> list[str]:
    if entry["kind"] == "route":
        result = [binary, "-4", "route", operation]
        if entry["type"] != "unicast":
            result.append(entry["type"])
        result += [entry["destination"], "table", str(entry["table"])]
        if entry["device"]:
            result += ["dev", entry["device"]]
        return [*result, "metric", str(entry["metric"]), "proto", str(PROTOCOL)]
    result = [
        binary,
        "-4",
        "rule",
        operation,
        "priority",
        str(entry["priority"]),
        "from",
        entry["source"],
    ]
    if "mark" in entry:
        result += ["fwmark", f"{entry['mark']:#x}/{entry['mask']:#x}"]
    result += ["lookup", str(entry["table"])]
    if "suppress" in entry:
        result += ["suppress_prefixlength", str(entry["suppress"])]
    return [*result, "protocol", str(PROTOCOL)]


def _number(value: Any) -> int:
    if value in ("main", "default", "local"):
        return {"main": 254, "default": 253, "local": 255}[value]
    return int(str(value), 0) if str(value).startswith("0x") else int(value)


def observed_entries(rules: list[Entry], routes: list[Entry]) -> list[Entry]:
    result: list[Entry] = []
    for row in rules:
        priority = int(row.get("priority", -1))
        if 0 < priority < FIRST_PRIORITY:
            raise WireGuardError(
                "Existing high-priority IP rules can bypass VPN source routing; "
                "review their order before enabling this policy"
            )
        table = _number(row.get("table", 0))
        if not (FIRST_PRIORITY <= priority < LAST_PRIORITY or FIRST_TABLE <= table <= LAST_TABLE):
            continue
        allowed = {
            "priority",
            "src",
            "table",
            "protocol",
            "fwmark",
            "fwmask",
            "suppress_prefixlen",
            "suppress_prefixlength",
        }
        if set(row) - allowed or str(row.get("protocol", "")) != str(PROTOCOL):
            raise WireGuardError(
                "WireGuard routing priorities/tables conflict with foreign IP rules"
            )
        item: Entry = {
            "kind": "rule",
            "priority": priority,
            "source": row.get("src", "all"),
            "table": table,
        }
        if "fwmark" in row:
            item.update(mark=_number(row["fwmark"]), mask=_number(row.get("fwmask", 0xFFFFFFFF)))
        if "suppress_prefixlen" in row or "suppress_prefixlength" in row:
            item["suppress"] = row.get("suppress_prefixlen", row.get("suppress_prefixlength"))
        result.append(item)
    for row in routes:
        table = _number(row.get("table", 254))
        if not FIRST_TABLE <= table <= LAST_TABLE:
            continue
        allowed = {"type", "dst", "table", "protocol", "scope", "dev", "metric", "flags"}
        if (
            set(row) - allowed
            or set(row.get("flags", [])) - {"linkdown"}
            or str(row.get("protocol", "")) != str(PROTOCOL)
            or row.get("type", "unicast") not in ("unicast", "unreachable")
        ):
            raise WireGuardError("WireGuard routing tables contain foreign routes")
        result.append(
            {
                "kind": "route",
                "table": table,
                "destination": "0.0.0.0/0"
                if row.get("dst", "default") == "default"
                else row["dst"],
                "device": row.get("dev", ""),
                "metric": int(row.get("metric", 0)),
                "type": row.get("type", "unicast"),
            }
        )
    return result


class LinuxWireGuardRouting:
    def __init__(self, data_dir: Path, *, runner: Callable[[list[str]], str] = run_command) -> None:
        self.path = data_dir / "wireguard-routes.json"
        self.runner, self.binary = runner, shutil.which("ip") or "ip"
        self.transaction: str | None = None

    def _state(self) -> Entry:
        if not self.path.exists():
            return {"version": 1, "entries": [], "intent": None}
        try:
            if self.path.is_symlink() or self.path.stat().st_size > 1048576:
                raise ValueError("Invalid routing state")
            value = json.loads(self.path.read_text())
            if not isinstance(value, dict) or value.get("version") != 1:
                raise ValueError("Invalid routing state")
            return value
        except (ValueError, OSError) as exc:
            raise WireGuardError("WireGuard routing ownership state cannot be read") from exc

    def _observed(self, state: Entry) -> list[Entry]:
        try:
            rules = json.loads(self.runner([self.binary, "-4", "-N", "-j", "rule", "show"]))
            routes = json.loads(
                self.runner([self.binary, "-4", "-N", "-j", "route", "show", "table", "all"])
            )
            observed = observed_entries(rules, routes)
            known = [*state["entries"], *(state.get("intent") or {}).get("target", [])]
            if any(
                entry_key(item) not in {entry_key(entry) for entry in known} for item in observed
            ):
                raise WireGuardError("WireGuard routing ownership cannot be verified")
            return observed
        except (ValueError, TypeError, KeyError) as exc:
            raise WireGuardError("Cannot inspect IPv4 policy routing safely") from exc

    def snapshot(self, previous: NetworkConfiguration) -> Entry:
        self.transaction = secrets.token_hex(16)
        state = self._state()
        # With no managed policy, do not reserve or inspect another administrator's tables.
        active = bool(policy_entries(previous) or state["entries"] or state.get("intent"))
        return {
            "version": 1,
            "transaction": self.transaction,
            "state": state,
            "entries": self._observed(state) if active else [],
        }

    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        if policy_entries(previous) or policy_entries(target) or self._state()["entries"]:
            self._observed(self._state())

    def preview(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> Entry:
        before = {entry_key(item): item for item in policy_entries(previous)}
        after = {entry_key(item): item for item in policy_entries(target)}
        commands = [
            entry_command(self.binary, "del", item)
            for key, item in before.items()
            if key not in after
        ]
        commands += [
            entry_command(self.binary, "add", item)
            for key, item in after.items()
            if key not in before
        ]
        return {
            "commands": commands,
            "script": "\n".join(shlex.join(item) for item in commands),
            "note": "Only selected sources use VPN; the host main default route is preserved.",
        }

    def _reconcile(self, current: list[Entry], target: list[Entry]) -> None:
        before = {entry_key(item): item for item in current}
        after = {entry_key(item): item for item in target}
        # Remove stale selectors before their tables; build routes before new selectors.
        for kind in ("rule", "route"):
            for key, item in before.items():
                if key not in after and item["kind"] == kind:
                    self.runner(entry_command(self.binary, "del", item))
        for kind in ("route", "rule"):
            for key, item in after.items():
                if key not in before and item["kind"] == kind:
                    self.runner(entry_command(self.binary, "add", item))

    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        if self.transaction is None:
            raise WireGuardError("A routing recovery snapshot is required")
        state = self._state()
        desired = policy_entries(target)
        if not (desired or state["entries"] or state.get("intent")):
            return
        observed = self._observed(state)
        state["intent"] = {"transaction": self.transaction, "target": desired}
        atomic_state(self.path, state)
        self._reconcile(observed, desired)
        state["entries"] = desired
        atomic_state(self.path, state)

    def rollback(self, snapshot: Entry) -> None:
        state = self._state()
        if (state.get("intent") or {}).get("transaction") != snapshot.get("transaction"):
            return
        self._reconcile(self._observed(state), snapshot["entries"])
        atomic_state(self.path, snapshot["state"])

    def status(self) -> Entry:
        return {
            "tables": sorted(
                {entry["table"] for entry in self._state()["entries"] if entry["kind"] == "route"}
            )
        }


class DemoWireGuardRouting:
    def __init__(self, initial: NetworkConfiguration) -> None:
        self.config = initial

    def snapshot(self, previous: NetworkConfiguration) -> Entry:
        return {"configuration": self.config.model_dump(mode="json")}

    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        pass

    def preview(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> Entry:
        return {"demo": True, "entries": policy_entries(target)}

    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        self.config = target

    def rollback(self, snapshot: Entry) -> None:
        self.config = NetworkConfiguration.model_validate(snapshot["configuration"])

    def status(self) -> Entry:
        return {
            "tables": sorted(
                {item["table"] for item in policy_entries(self.config) if item["kind"] == "route"}
            )
        }
