"""Ownership-scoped Linux bridge, VLAN and dummy-interface lifecycle.

The coordinator calls apply before addresses/DHCP, and finalize afterwards. Recovery
calls prepare_rollback before restoring addresses, then rollback for final cleanup.
No operation flushes interfaces, addresses or routing tables.
"""

import copy
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, TypedDict

from app.compiler import FirewallError
from app.link_models import (
    Bridge,
    LinkConfiguration,
    ManagedLink,
    Vlan,
    WireGuardInterface,
    ordered_links,
    planned_interface_names,
)

OWNER_PREFIX = "OpenMikroRout:link:"
MAX_HOST_LINKS = 4096
COMMAND_TIMEOUT = 10


class LinkDriver(Protocol):
    def snapshot(self, previous: LinkConfiguration) -> dict[str, Any]: ...
    def preview(self, previous: LinkConfiguration, target: LinkConfiguration) -> dict[str, Any]: ...
    def check(self, previous: LinkConfiguration, target: LinkConfiguration) -> None: ...
    def apply(self, previous: LinkConfiguration, target: LinkConfiguration) -> None: ...
    def finalize(self, previous: LinkConfiguration, target: LinkConfiguration) -> None: ...
    def prepare_rollback(self, snapshot: dict[str, Any]) -> None: ...
    def rollback(self, snapshot: dict[str, Any]) -> None: ...
    def status(self) -> dict[str, Any]: ...


class ObservedLink(TypedDict):
    name: str
    kind: str
    alias: str
    master: str | None
    parent: str | None
    vlan_id: int | None
    mtu: int
    up: bool
    stp: bool
    ifindex: int


def link_configuration(config: LinkConfiguration) -> LinkConfiguration:
    return LinkConfiguration(
        bridges=config.bridges,
        vlans=config.vlans,
        virtual_interfaces=config.virtual_interfaces,
        wireguard_interfaces=config.wireguard_interfaces,
    )


def ownership(link: ManagedLink) -> str:
    return f"{OWNER_PREFIX}{link.id}"


def link_kind(link: ManagedLink) -> str:
    if isinstance(link, WireGuardInterface):
        return "wireguard"
    return "bridge" if isinstance(link, Bridge) else "vlan" if isinstance(link, Vlan) else "dummy"


def desired_members(config: LinkConfiguration) -> dict[str, str]:
    return {member: bridge.name for bridge in config.bridges for member in bridge.members}


def parse_links(payload: str) -> dict[str, ObservedLink]:
    try:
        rows = json.loads(payload)
        if not isinstance(rows, list) or len(rows) > MAX_HOST_LINKS:
            raise ValueError("Invalid link collection")
        names = {int(row["ifindex"]): str(row["ifname"]) for row in rows}
        result: dict[str, ObservedLink] = {}
        for row in rows:
            info = row.get("linkinfo", {})
            data = info.get("info_data", {})
            master = row.get("master")
            parent = row.get("link", row.get("link_index"))
            if isinstance(master, int):
                master = names.get(master)
            if isinstance(parent, int):
                parent = names.get(parent)
            name = str(row["ifname"])
            result[name] = {
                "name": name,
                "kind": str(info.get("info_kind", "physical")),
                "alias": str(row.get("ifalias", "")),
                "master": str(master) if master else None,
                "parent": str(parent) if parent else None,
                "vlan_id": int(data["id"]) if info.get("info_kind") == "vlan" else None,
                "mtu": int(row.get("mtu", 1500)),
                "up": "UP" in row.get("flags", []),
                "stp": bool(data.get("stp_state", 0)),
                "ifindex": int(row["ifindex"]),
            }
        return result
    except (KeyError, TypeError, ValueError) as exc:
        raise FirewallError("iproute2 returned an invalid interface snapshot") from exc


class LinuxLinkDriver:
    def __init__(self, data_dir: Path, runner: Callable[[list[str]], str] | None = None) -> None:
        self.data_dir = data_dir
        self.state_path = data_dir / "links-state.json"
        self.ip_bin = shutil.which("ip") or "ip"
        self.runner = runner or self._execute
        self.transaction: str | None = None

    @staticmethod
    def _execute(args: list[str]) -> str:
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
                check=False,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(
                "Interface operation failed or exceeded its 10-second timeout"
            ) from exc
        if result.returncode:
            raise FirewallError(
                f"iproute2 rejected the interface operation: {result.stderr.strip()[:400]}"
            )
        return result.stdout

    def _ip(self, *args: str) -> str:
        return self.runner([self.ip_bin, *args])

    def _links(self) -> dict[str, ObservedLink]:
        return parse_links(self._ip("-j", "-d", "link", "show"))

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"version": 1, "members": {}, "intent": None}
        try:
            data = json.loads(self.state_path.read_text())
            if not isinstance(data, dict) or data.get("version") != 1:
                raise ValueError("Unknown state format")
            if not isinstance(data.get("members"), dict):
                raise ValueError("Invalid membership ledger")
            return data
        except (OSError, ValueError) as exc:
            raise FirewallError("Managed interface ownership state cannot be read") from exc

    def _write_state(self, state: dict[str, Any]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile("w", dir=self.data_dir, delete=False) as stream:
                temporary = stream.name
                os.chmod(temporary, 0o600)
                json.dump(state, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_path)
            temporary = None
            directory = os.open(self.data_dir, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise FirewallError("Managed interface ownership state cannot be saved") from exc
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)

    def snapshot(self, previous: LinkConfiguration) -> dict[str, Any]:
        self.transaction = secrets.token_hex(16)
        return {
            "version": 1,
            "transaction": self.transaction,
            "configuration": link_configuration(previous).model_dump(mode="json"),
            "links": self._links(),
            "state": self._read_state(),
        }

    def _membership_state(
        self, previous: LinkConfiguration, live: dict[str, ObservedLink]
    ) -> dict[str, Any]:
        members: dict[str, Any] = copy.deepcopy(self._read_state()["members"])
        # A valid persisted previous configuration may outlive the ownership ledger
        # (for example after restoring a backup). It proves only those exact relations.
        previous_by_name = {item.name: item for item in previous.bridges}
        for name, bridge in desired_members(previous).items():
            observed = live.get(name)
            owner = live.get(bridge)
            if (
                name not in members
                and observed
                and observed["master"] == bridge
                and owner
                and owner["alias"] == ownership(previous_by_name[bridge])
            ):
                members[name] = {"bridge": bridge, "up_before": observed["up"]}
        return members

    @staticmethod
    def _assert_owner(item: ManagedLink, observed: ObservedLink) -> None:
        if observed["alias"] != ownership(item) or observed["kind"] != link_kind(item):
            raise FirewallError(
                f"Interface {item.name} already exists and is not owned by this configuration"
            )
        if isinstance(item, Vlan) and (
            observed["parent"] != item.parent or observed["vlan_id"] != item.vlan_id
        ):
            raise FirewallError(
                f"VLAN {item.name}: changing parent or VLAN ID requires a new interface name"
            )

    def _check_live(
        self,
        previous: LinkConfiguration,
        target: LinkConfiguration,
        live: dict[str, ObservedLink],
    ) -> None:
        previous_items = {item.name: item for item in ordered_links(previous)}
        target_items = {item.name: item for item in ordered_links(target)}
        ledger = self._membership_state(previous, live)
        for item in previous_items.values():
            if item.name in live:
                self._assert_owner(item, live[item.name])
        for item in ordered_links(target):
            if item.name in live:
                self._assert_owner(item, live[item.name])
            references = (
                item.members
                if isinstance(item, Bridge)
                else ([item.parent] if isinstance(item, Vlan) else [])
            )
            for name in references:
                if name not in live and name not in target_items:
                    raise FirewallError(f"Interface {name} does not exist")
                if name in live and live[name]["kind"] == "wireguard":
                    raise FirewallError("WireGuard cannot be a bridge port or VLAN parent")
                if name in previous_items and name not in target_items:
                    raise FirewallError(
                        f"Interface {name} is still referenced and cannot be removed"
                    )
                parent_mtu = target_items[name].mtu if name in target_items else live[name]["mtu"]
                if item.mtu > parent_mtu:
                    raise FirewallError(f"MTU of {item.name} exceeds the MTU of {name}")
            if isinstance(item, Bridge):
                for name in item.members:
                    observed = live.get(name)
                    if not observed or not observed["master"]:
                        continue
                    master = observed["master"]
                    tracked = ledger.get(name)
                    if not tracked or tracked.get("bridge") != master:
                        raise FirewallError(
                            f"Interface {name} belongs to {master}; its membership is unmanaged"
                        )
                    master_item = previous_items.get(master) or target_items.get(master)
                    if not master_item or master not in live:
                        raise FirewallError(
                            f"Existing bridge membership of {name} cannot be verified"
                        )
                    self._assert_owner(master_item, live[master])

    def check(self, previous: LinkConfiguration, target: LinkConfiguration) -> None:
        self._check_live(previous, target, self._links())

    def preview(self, previous: LinkConfiguration, target: LinkConfiguration) -> dict[str, Any]:
        live = self._links()
        self._check_live(previous, target, live)
        commands: list[list[str]] = []
        for item in ordered_links(target):
            if item.name not in live:
                commands.append(self._create_command(item))
            commands.append(["link", "set", "dev", item.name, "mtu", str(item.mtu)])
            if isinstance(item, Bridge):
                commands.append(
                    [
                        "link",
                        "set",
                        "dev",
                        item.name,
                        "type",
                        "bridge",
                        "stp_state",
                        "1" if item.stp else "0",
                    ]
                )
            commands.append(["link", "set", "dev", item.name, "up" if item.enabled else "down"])
        old_members = desired_members(previous)
        new_members = desired_members(target)
        for member in old_members:
            if old_members[member] != new_members.get(member):
                commands.append(["link", "set", "dev", member, "nomaster"])
        for member, bridge in new_members.items():
            commands.append(["link", "set", "dev", member, "master", bridge])
        removed = [
            item
            for item in reversed(ordered_links(previous))
            if item.name not in planned_interface_names(target)
        ]
        return {
            "commands": [["ip", *command] for command in commands],
            "deferred_commands": [["ip", "link", "delete", "dev", item.name] for item in removed],
            "note": "Only owned links change; stale links are removed after addresses and DHCP.",
        }

    @staticmethod
    def _create_command(item: ManagedLink) -> list[str]:
        command = ["link", "add"]
        if isinstance(item, Vlan):
            command += ["link", item.parent]
        # Request ownership during creation; some kernels silently drop this alias.
        command += [
            "name",
            item.name,
            "alias",
            ownership(item),
            "mtu",
            str(item.mtu),
            "type",
            link_kind(item),
        ]
        if isinstance(item, Vlan):
            command += ["id", str(item.vlan_id)]
        if isinstance(item, Bridge):
            command += ["stp_state", "1" if item.stp else "0"]
        return command

    def _create_link(self, item: ManagedLink) -> None:
        self._ip(*self._create_command(item))
        created = self._links().get(item.name)
        if created is None:
            raise FirewallError(
                f"New interface {item.name} disappeared before ownership verification"
            )
        if not created["alias"]:
            # Only a successful creation may use this fallback. Existing interfaces
            # always pass the normal ownership check and are never adopted here.
            # Validate the new shell before tagging it; a crash in this gap leaves
            # an unowned interface and recovery deliberately fails closed.
            self._assert_owner(item, {**created, "alias": ownership(item)})
            if created["mtu"] != item.mtu or created["up"] or created["master"]:
                raise FirewallError(
                    f"New interface {item.name} changed before ownership verification"
                )
            self._ip("link", "set", "dev", item.name, "alias", ownership(item))
        verified = self._links().get(item.name)
        if verified is None or verified["ifindex"] != created["ifindex"]:
            raise FirewallError(f"New interface {item.name} changed during ownership verification")
        self._assert_owner(item, verified)

    def apply(self, previous: LinkConfiguration, target: LinkConfiguration) -> None:
        if self.transaction is None:
            raise FirewallError("An interface recovery snapshot is required before application")
        live = self._links()
        self._check_live(previous, target, live)
        old_ledger = self._membership_state(previous, live)
        memberships = desired_members(target)
        next_ledger: dict[str, Any] = {}
        for member, bridge in memberships.items():
            observed = live.get(member)
            next_ledger[member] = {
                "bridge": bridge,
                "up_before": old_ledger.get(member, {}).get(
                    "up_before", observed["up"] if observed else False
                ),
            }
        # Persist intent before the first netlink write. A restarted process can
        # identify every touched member and every newly created link from this file.
        state = {
            "version": 1,
            "members": next_ledger,
            "intent": {
                "transaction": self.transaction,
                "target": link_configuration(target).model_dump(mode="json"),
                "touched_members": list(dict.fromkeys([*old_ledger, *memberships])),
            },
        }
        self._write_state(state)
        for item in ordered_links(target):
            current = self._links()
            if item.name not in current:
                self._create_link(item)
            else:
                self._assert_owner(item, current[item.name])
            self._ip("link", "set", "dev", item.name, "mtu", str(item.mtu))
            if isinstance(item, Bridge):
                self._ip(
                    "link",
                    "set",
                    "dev",
                    item.name,
                    "type",
                    "bridge",
                    "stp_state",
                    "1" if item.stp else "0",
                )
            self._ip("link", "set", "dev", item.name, "up" if item.enabled else "down")
        for member, record in old_ledger.items():
            if record["bridge"] == memberships.get(member):
                continue
            current = self._links()
            observed = current.get(member)
            if observed and observed["master"] == record["bridge"]:
                owner = next(
                    (item for item in previous.bridges if item.name == record["bridge"]), None
                )
                if not owner or owner.name not in current:
                    raise FirewallError(
                        f"Ownership of bridge {record['bridge']} cannot be verified"
                    )
                self._assert_owner(owner, current[owner.name])
                self._ip("link", "set", "dev", member, "nomaster")
                if not record["up_before"] and observed["up"]:
                    self._ip("link", "set", "dev", member, "down")
        enabled_bridges = {item.name for item in target.bridges if item.enabled}
        for member, bridge in memberships.items():
            current = self._links()
            if current[member]["master"] != bridge:
                if current[member]["master"]:
                    raise FirewallError(
                        f"Interface {member} acquired another master during application"
                    )
                self._ip("link", "set", "dev", member, "master", bridge)
            if bridge in enabled_bridges and not current[member]["up"]:
                self._ip("link", "set", "dev", member, "up")

    def _assert_empty(self, name: str, current: dict[str, ObservedLink]) -> None:
        if any(link["master"] == name or link["parent"] == name for link in current.values()):
            raise FirewallError(f"Interface {name} still has members or dependent interfaces")
        try:
            addresses = json.loads(self._ip("-j", "address", "show", "dev", name))
            for row in addresses:
                for address in row.get("addr_info", []):
                    parsed = ipaddress.ip_address(address["local"])
                    if parsed.version != 6 or not parsed.is_link_local:
                        raise FirewallError(
                            f"Interface {name} still has an address; remove it first"
                        )
            for family in ("-4", "-6"):
                routes = json.loads(
                    self._ip("-j", family, "route", "show", "table", "all", "dev", name)
                )
                for route in routes:
                    destination = route.get("dst", "default")
                    automatic = route.get("protocol") == "kernel" and destination != "default"
                    if automatic:
                        subnet = ipaddress.ip_network(destination, strict=False)
                        if subnet.version == 6 and (subnet.is_link_local or subnet.is_multicast):
                            continue
                    raise FirewallError(f"Interface {name} still has routes; remove them first")
        except (KeyError, TypeError, ValueError) as exc:
            raise FirewallError("Cannot verify that the interface is safe to remove") from exc

    def finalize(self, previous: LinkConfiguration, target: LinkConfiguration) -> None:
        names = planned_interface_names(target)
        for item in reversed(ordered_links(previous)):
            if item.name in names:
                continue
            current = self._links()
            if item.name not in current:
                continue
            self._assert_owner(item, current[item.name])
            self._assert_empty(item.name, current)
            self._ip("link", "delete", "dev", item.name)

    def _rollback_intent(self, snapshot: dict[str, Any]) -> dict[str, Any] | None:
        intent = self._read_state().get("intent")
        if not isinstance(intent, dict) or intent.get("transaction") != snapshot.get("transaction"):
            return None
        return intent

    def prepare_rollback(self, snapshot: dict[str, Any]) -> None:
        if not self._rollback_intent(snapshot):
            return
        previous = LinkConfiguration.model_validate(snapshot["configuration"])
        before: dict[str, ObservedLink] = snapshot["links"]
        for item in ordered_links(previous):
            if item.name not in before or before[item.name]["alias"] != ownership(item):
                continue
            current = self._links()
            if item.name not in current:
                self._create_link(item)
            else:
                self._assert_owner(item, current[item.name])
            # Restoring addresses on a DOWN shell may not install connected routes;
            # a subsequent gateway-route restore or dnsmasq bind would then fail.
            # Restore administrative state before the coordinator restores L3.
            original = before[item.name]
            self._ip("link", "set", "dev", item.name, "mtu", str(original["mtu"]))
            if isinstance(item, Bridge):
                self._ip(
                    "link",
                    "set",
                    "dev",
                    item.name,
                    "type",
                    "bridge",
                    "stp_state",
                    "1" if original["stp"] else "0",
                )
            self._ip("link", "set", "dev", item.name, "up" if original["up"] else "down")

    def rollback(self, snapshot: dict[str, Any]) -> None:
        intent = self._rollback_intent(snapshot)
        if not intent:
            return
        self.prepare_rollback(snapshot)
        before: dict[str, ObservedLink] = snapshot["links"]
        previous = LinkConfiguration.model_validate(snapshot["configuration"])
        target = LinkConfiguration.model_validate(intent["target"])
        owned_items = {
            item.name: item for item in (*ordered_links(previous), *ordered_links(target))
        }
        for name in intent["touched_members"]:
            current = self._links()
            if name not in current:
                if name in before:
                    raise FirewallError(f"Interface {name} disappeared before membership recovery")
                continue
            original = before.get(name)
            original_master = original["master"] if original else None
            observed = current[name]
            master = observed["master"]
            if original_master and original_master in owned_items and original_master in current:
                self._assert_owner(owned_items[original_master], current[original_master])
            if master and master != original_master:
                owner = owned_items.get(master)
                if not owner or master not in current:
                    raise FirewallError(
                        f"Interface {name} has an unmanaged master; recovery stopped"
                    )
                self._assert_owner(owner, current[master])
                self._ip("link", "set", "dev", name, "nomaster")
                master = None
            if original_master and master != original_master:
                if original_master not in current:
                    raise FirewallError(f"Original master {original_master} is no longer available")
                self._ip("link", "set", "dev", name, "master", original_master)
            if original and observed["up"] != original["up"]:
                self._ip("link", "set", "dev", name, "up" if original["up"] else "down")
        for item in ordered_links(previous):
            original = before.get(item.name)
            if not original or original["alias"] != ownership(item):
                continue
            current = self._links()
            self._assert_owner(item, current[item.name])
            self._ip("link", "set", "dev", item.name, "mtu", str(original["mtu"]))
            if isinstance(item, Bridge):
                self._ip(
                    "link",
                    "set",
                    "dev",
                    item.name,
                    "type",
                    "bridge",
                    "stp_state",
                    "1" if original["stp"] else "0",
                )
            self._ip("link", "set", "dev", item.name, "up" if original["up"] else "down")
        for item in reversed(ordered_links(target)):
            if item.name in before:
                continue
            current = self._links()
            if item.name not in current:
                continue
            self._assert_owner(item, current[item.name])
            self._assert_empty(item.name, current)
            self._ip("link", "delete", "dev", item.name)
        self._write_state(snapshot["state"])

    def status(self) -> dict[str, Any]:
        return {"links": list(self._links().values()), "demo": False}


class DemoLinkDriver:
    """Same lifecycle contract without running ip or changing host networking."""

    def __init__(self, initial: LinkConfiguration | None = None) -> None:
        self.config = link_configuration(initial or LinkConfiguration())

    def snapshot(self, previous: LinkConfiguration) -> dict[str, Any]:
        return {"configuration": self.config.model_dump(mode="json")}

    def check(self, previous: LinkConfiguration, target: LinkConfiguration) -> None:
        link_configuration(target)

    def preview(self, previous: LinkConfiguration, target: LinkConfiguration) -> dict[str, Any]:
        return {"demo": True, "links": link_configuration(target).model_dump(mode="json")}

    def apply(self, previous: LinkConfiguration, target: LinkConfiguration) -> None:
        self.config = link_configuration(target)

    def finalize(self, previous: LinkConfiguration, target: LinkConfiguration) -> None:
        return

    def prepare_rollback(self, snapshot: dict[str, Any]) -> None:
        return

    def rollback(self, snapshot: dict[str, Any]) -> None:
        self.config = LinkConfiguration.model_validate(snapshot["configuration"])

    def status(self) -> dict[str, Any]:
        memberships = desired_members(self.config)
        return {
            "demo": True,
            "links": [
                {
                    "name": item.name,
                    "kind": link_kind(item),
                    "alias": ownership(item),
                    "mtu": item.mtu,
                    "up": item.enabled,
                    "master": memberships.get(item.name),
                    "parent": item.parent if isinstance(item, Vlan) else None,
                    "vlan_id": item.vlan_id if isinstance(item, Vlan) else None,
                    "stp": item.stp if isinstance(item, Bridge) else False,
                }
                for item in ordered_links(self.config)
            ],
        }
