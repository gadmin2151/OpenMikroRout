"""Explicit source routing for VPN clients, with private tables and durable rollback."""

import ipaddress
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
GUARD_MAIN_PRIORITY, GUARD_DENY_PRIORITY = 9500, 9501
Entry = dict[str, Any]


def protected_sources(config: NetworkConfiguration) -> list[str]:
    return [
        source
        for interface in config.wireguard_interfaces
        if interface.route_allowed_ips and interface.kill_switch
        for source in interface.route_sources
    ]


def guard_entries(sources: list[str]) -> list[Entry]:
    """Device-independent confinement, including the documented main-route exceptions."""
    networks = list(ipaddress.collapse_addresses(ipaddress.IPv4Network(s) for s in sources))
    if not networks:
        return []
    result: list[Entry] = [
        {
            "kind": "rule",
            "priority": 9000,
            "source": "all",
            "table": 254,
            "mark": WG_MARK_PREFIX,
            "mask": 0xFFFF0000,
        }
    ]
    for network in networks:
        # Install the deny first; an interrupted install may block an exception, never leak.
        result += [
            {
                "kind": "rule",
                "priority": GUARD_DENY_PRIORITY,
                "source": str(network),
                "action": "unreachable",
            },
            {
                "kind": "rule",
                "priority": GUARD_MAIN_PRIORITY,
                "source": str(network),
                "table": 254,
                "suppress": 0,
            },
        ]
    return result


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
    if entry.get("action") == "unreachable":
        result.append("unreachable")
    else:
        result += ["lookup", str(entry["table"])]
    if "suppress" in entry:
        result += ["suppress_prefixlength", str(entry["suppress"])]
    return [*result, "protocol", str(PROTOCOL)]


def _number(value: Any) -> int:
    if value in ("main", "default", "local"):
        return {"main": 254, "default": 253, "local": 255}[value]
    return int(str(value), 0) if str(value).startswith("0x") else int(value)


def reconciliation_commands(
    binary: str, current: list[Entry], target: list[Entry]
) -> list[list[str]]:
    before = {entry_key(item): item for item in current}
    after = {entry_key(item): item for item in target}
    commands = [
        entry_command(binary, "del", item)
        for kind in ("rule", "route")
        for key, item in before.items()
        if key not in after and item["kind"] == kind
    ]
    return commands + [
        entry_command(binary, "add", item)
        for kind in ("route", "rule")
        for key, item in after.items()
        if key not in before and item["kind"] == kind
    ]


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
        if priority == 0:
            # Only the kernel's unconditional local-table lookup may precede confinement.
            if set(row) == {"priority", "src", "table"} and row["src"] == "all" and table == 255:
                continue
            raise WireGuardError("Foreign priority-zero IP rules can bypass VPN source routing")
        if not (FIRST_PRIORITY <= priority < LAST_PRIORITY or FIRST_TABLE <= table <= LAST_TABLE):
            continue
        allowed = {
            "priority",
            "src",
            "srclen",
            "table",
            "protocol",
            "fwmark",
            "fwmask",
            "suppress_prefixlen",
            "suppress_prefixlength",
            "action",
        }
        if set(row) - allowed or str(row.get("protocol", "")) != str(PROTOCOL):
            raise WireGuardError(
                "WireGuard routing priorities/tables conflict with foreign IP rules"
            )
        source = row.get("src", "all")
        if source != "all":
            source = str(
                ipaddress.IPv4Network(
                    source if "/" in source else f"{source}/{row.get('srclen', 32)}", strict=False
                )
            )
        item: Entry = {
            "kind": "rule",
            "priority": priority,
            "source": source,
        }
        if str(row.get("action")) in ("unreachable", "7") and priority == GUARD_DENY_PRIORITY:
            item["action"] = "unreachable"
        elif "action" in row:
            raise WireGuardError("WireGuard routing priorities contain a foreign rule action")
        else:
            item["table"] = table
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
        route_type = {"1": "unicast", "7": "unreachable"}.get(
            str(row.get("type", "unicast")), row.get("type", "unicast")
        )
        if (
            set(row) - allowed
            or set(row.get("flags", [])) - {"linkdown"}
            or str(row.get("protocol", "")) != str(PROTOCOL)
            or route_type not in ("unicast", "unreachable")
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
                "type": route_type,
            }
        )
    return result


class LinuxWireGuardRouting:
    def __init__(self, data_dir: Path, *, runner: Callable[[list[str]], str] = run_command) -> None:
        self.path = data_dir / "wireguard-routes.json"
        self.runner, self.binary = runner, shutil.which("ip") or "ip"
        self.transaction: str | None = None
        self.hold_guards = False

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
            known = [
                *state["entries"],
                *state.get("guards", []),
                *(state.get("intent") or {}).get("target", []),
            ]
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
        active = bool(
            policy_entries(previous)
            or state["entries"]
            or state.get("intent")
            or state.get("guards")
        )
        return {
            "version": 1,
            "transaction": self.transaction,
            "state": state,
            "entries": self._observed(state) if active else [],
            "protected_sources": protected_sources(previous),
        }

    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        if policy_entries(previous) or policy_entries(target) or self._state()["entries"]:
            self._observed(self._state())

    def preview(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> Entry:
        before, after = policy_entries(previous), policy_entries(target)
        guards = guard_entries([*protected_sources(previous), *protected_sources(target)])
        present = {entry_key(item) for item in before}
        commands = [
            entry_command(self.binary, "add", item)
            for item in guards
            if entry_key(item) not in present
        ]
        commands += reconciliation_commands(self.binary, [*before, *guards], [*after, *guards])
        commands += reconciliation_commands(self.binary, [*after, *guards], after)
        return {
            "commands": commands,
            "script": "\n".join(shlex.join(item) for item in commands),
            "note": (
                "Protected sources are temporarily blocked while policy changes; specific main "
                "routes and WireGuard transport remain exempt. The host main default is preserved."
            ),
        }

    def _reconcile(self, current: list[Entry], target: list[Entry]) -> None:
        # The durable source guards remain installed throughout replacement.
        for command in reconciliation_commands(self.binary, current, target):
            self.runner(command)

    def _install_guards(self, state: Entry, sources: list[str]) -> list[Entry]:
        observed = self._observed(state)
        # Preserve exact interrupted selectors as ownership evidence until recovery succeeds.
        guards = list(
            {
                entry_key(item): item
                for item in [*state.get("guards", []), *guard_entries(sources)]
            }.values()
        )
        state["guards"] = guards
        atomic_state(self.path, state)
        present = {entry_key(item) for item in observed}
        for item in guards:
            if entry_key(item) not in present:
                self.runner(entry_command(self.binary, "add", item))
        return guards

    def restore_guards(self, config: NetworkConfiguration) -> None:
        """Early boot/startup: no interface, endpoint, NAT or default-route mutation."""
        sources = protected_sources(config)
        state = self._state()
        if sources or state.get("guards"):
            self._install_guards(state, sources)

    def protect(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        if self.transaction is None:
            raise WireGuardError("A routing recovery snapshot is required")
        state = self._state()
        desired = policy_entries(target)
        if not (desired or state["entries"] or state.get("intent") or state.get("guards")):
            return
        observed = self._observed(state)
        state["entries"] = observed
        sources = [*protected_sources(previous), *protected_sources(target)]
        state["intent"] = {
            "transaction": self.transaction,
            "target": desired,
            "protected_sources": sources,
        }
        atomic_state(self.path, state)
        self.hold_guards = True
        self._install_guards(state, sources)

    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        automatic = not self.hold_guards
        if automatic:
            self.protect(previous, target)
        state = self._state()
        if not state.get("intent"):
            return
        self._reconcile(self._observed(state), [*policy_entries(target), *state.get("guards", [])])
        if automatic:
            self.finalize()

    def finalize(self) -> None:
        state = self._state()
        if not state.get("intent"):
            return
        desired = state["intent"]["target"]
        self._reconcile(self._observed(state), desired)
        state.update(entries=desired, guards=[])
        atomic_state(self.path, state)
        self.hold_guards = False

    def protect_rollback(self, snapshot: Entry) -> None:
        state = self._state()
        if (state.get("intent") or {}).get("transaction") != snapshot.get("transaction"):
            return
        self.hold_guards = True
        # Persist ownership of both sides before restoring entries absent from the target.
        state["intent"]["target"] = list(
            {
                entry_key(item): item for item in [*state["intent"]["target"], *snapshot["entries"]]
            }.values()
        )
        atomic_state(self.path, state)
        self._install_guards(
            state,
            [
                *snapshot.get("protected_sources", []),
                *(state.get("intent") or {}).get("protected_sources", []),
            ],
        )

    def rollback(self, snapshot: Entry) -> None:
        state = self._state()
        if (state.get("intent") or {}).get("transaction") != snapshot.get("transaction"):
            return
        automatic = not self.hold_guards
        if automatic:
            self.protect_rollback(snapshot)
            state = self._state()
        self._reconcile(self._observed(state), [*snapshot["entries"], *state.get("guards", [])])
        if automatic:
            self.finish_rollback(snapshot)

    def finish_rollback(self, snapshot: Entry) -> None:
        state = self._state()
        if (state.get("intent") or {}).get("transaction") != snapshot.get("transaction"):
            return
        self._reconcile(self._observed(state), snapshot["entries"])
        atomic_state(self.path, snapshot["state"])
        self.hold_guards = False

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

    def restore_guards(self, config: NetworkConfiguration) -> None:
        pass

    def protect(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        pass

    def finalize(self) -> None:
        pass

    def protect_rollback(self, snapshot: Entry) -> None:
        pass

    def finish_rollback(self, snapshot: Entry) -> None:
        pass

    def rollback(self, snapshot: Entry) -> None:
        self.config = NetworkConfiguration.model_validate(snapshot["configuration"])

    def status(self) -> Entry:
        return {
            "tables": sorted(
                {item["table"] for item in policy_entries(self.config) if item["kind"] == "route"}
            )
        }
