import copy
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.compiler import FirewallError
from app.link_models import (
    Bridge,
    LinkConfiguration,
    VirtualInterface,
    Vlan,
    ordered_links,
)
from app.links import DemoLinkDriver, LinuxLinkDriver, ownership, parse_links


class FakeKernel:
    def __init__(self, preserve_create_alias: bool = False) -> None:
        self.links: dict[str, dict[str, Any]] = {
            "eth0": self.row("eth0", 1, up=True),
            "eth1": self.row("eth1", 2, up=False),
        }
        self.addresses: dict[str, list[dict[str, Any]]] = {}
        self.routes: dict[str, list[dict[str, Any]]] = {}
        self.commands: list[list[str]] = []
        self.fail_when: Callable[[list[str]], bool] | None = None
        self.preserve_create_alias = preserve_create_alias

    @staticmethod
    def row(name: str, index: int, up: bool = False) -> dict[str, Any]:
        return {"ifname": name, "ifindex": index, "flags": ["UP"] if up else [], "mtu": 1500}

    def add_owned(self, item: Bridge | Vlan | VirtualInterface, up: bool = True) -> None:
        row = self.row(item.name, max(row["ifindex"] for row in self.links.values()) + 1, up)
        row["ifalias"] = ownership(item)
        data: dict[str, Any] = {}
        kind = "dummy"
        if isinstance(item, Bridge):
            kind = "bridge"
            data["stp_state"] = int(item.stp)
        elif isinstance(item, Vlan):
            kind = "vlan"
            data["id"] = item.vlan_id
            row["link"] = item.parent
        row["linkinfo"] = {"info_kind": kind, "info_data": data}
        self.links[item.name] = row

    def __call__(self, arguments: list[str]) -> str:
        args = arguments[1:]
        self.commands.append(args)
        if self.fail_when and self.fail_when(args):
            raise FirewallError("Simulated netlink failure")
        if args == ["-j", "-d", "link", "show"]:
            return json.dumps(list(self.links.values()))
        if args[:4] == ["-j", "address", "show", "dev"]:
            return json.dumps([{"addr_info": self.addresses.get(args[4], [])}])
        if args[:2] in (["-j", "-4"], ["-j", "-6"]):
            return json.dumps(self.routes.get(args[-1], []))
        if args[:2] == ["link", "add"]:
            name = args[args.index("name") + 1]
            assert name not in self.links
            kind = args[args.index("type") + 1]
            row = self.row(name, max(item["ifindex"] for item in self.links.values()) + 1)
            if self.preserve_create_alias:
                row["ifalias"] = args[args.index("alias") + 1]
            row["mtu"] = int(args[args.index("mtu") + 1])
            data: dict[str, Any] = {}
            if kind == "vlan":
                parent = args[args.index("link", 1) + 1]
                assert parent in self.links
                row["link"] = parent
                data["id"] = int(args[args.index("id") + 1])
            if kind == "bridge":
                data["stp_state"] = int(args[args.index("stp_state") + 1])
            row["linkinfo"] = {"info_kind": kind, "info_data": data}
            self.links[name] = row
            return ""
        if args[:3] == ["link", "set", "dev"]:
            row = self.links[args[3]]
            operation = args[4]
            if operation == "mtu":
                row["mtu"] = int(args[5])
            elif operation == "alias":
                row["ifalias"] = args[5]
            elif operation == "type":
                assert args[5:7] == ["bridge", "stp_state"]
                row["linkinfo"]["info_data"]["stp_state"] = int(args[7])
            elif operation in ("up", "down"):
                row["flags"] = ["UP"] if operation == "up" else []
            elif operation == "master":
                assert args[5] in self.links
                row["master"] = args[5]
            elif operation == "nomaster":
                row.pop("master", None)
            else:
                raise AssertionError(f"Unknown mutation: {args}")
            return ""
        if args[:3] == ["link", "delete", "dev"]:
            del self.links[args[3]]
            return ""
        raise AssertionError(f"Unexpected command: {args}")


def driver(tmp_path: Path, kernel: FakeKernel) -> LinuxLinkDriver:
    return LinuxLinkDriver(tmp_path, runner=kernel)


@pytest.mark.parametrize("name", ["lo", "bad name", "eth0;reboot", "$(id)", "a" * 16, "eth0+"])
def test_rejects_invalid_link_names(name: str) -> None:
    with pytest.raises(ValidationError):
        Bridge(name=name)


def test_rejects_duplicate_membership_names_and_cycles() -> None:
    with pytest.raises(ValidationError, match="more than one bridge"):
        LinkConfiguration(
            bridges=[Bridge(name="br0", members=["eth0"]), Bridge(name="br1", members=["eth0"])]
        )
    with pytest.raises(ValidationError, match="names must be unique"):
        LinkConfiguration(
            bridges=[Bridge(name="br0")], virtual_interfaces=[VirtualInterface(name="br0")]
        )
    with pytest.raises(ValidationError, match="cycle"):
        LinkConfiguration(
            bridges=[Bridge(name="br0", members=["vlan10"])],
            vlans=[Vlan(name="vlan10", parent="br0", vlan_id=10)],
        )
    with pytest.raises(ValidationError, match="cycle"):
        LinkConfiguration(
            vlans=[
                Vlan(name="one", parent="two", vlan_id=10),
                Vlan(name="two", parent="one", vlan_id=20),
            ]
        )


@pytest.mark.parametrize("tag", [0, 4095, -1])
def test_rejects_invalid_vlan_ids(tag: int) -> None:
    with pytest.raises(ValidationError):
        Vlan(name="vlan0", parent="eth0", vlan_id=tag)


def test_dependency_order_includes_virtual_parent_and_member() -> None:
    config = LinkConfiguration(
        bridges=[Bridge(name="br0", members=["vlan10"])],
        vlans=[Vlan(name="vlan10", parent="dummy0", vlan_id=10)],
        virtual_interfaces=[VirtualInterface(name="dummy0")],
    )
    assert [item.name for item in ordered_links(config)] == ["dummy0", "vlan10", "br0"]


def test_creates_with_verified_ownership_and_restores_membership(tmp_path: Path) -> None:
    kernel = FakeKernel()
    before = copy.deepcopy(kernel.links)
    adapter = driver(tmp_path, kernel)
    target = LinkConfiguration(
        bridges=[Bridge(name="br-lan", members=["eth1"])],
        vlans=[Vlan(name="vlan20", parent="br-lan", vlan_id=20)],
    )
    snapshot = adapter.snapshot(LinkConfiguration())
    adapter.apply(LinkConfiguration(), target)
    assert kernel.links["br-lan"]["ifalias"] == ownership(target.bridges[0])
    create = next(args for args in kernel.commands if args[:2] == ["link", "add"])
    assert create.index("alias") < create.index("type")
    assert [
        "link",
        "set",
        "dev",
        "br-lan",
        "alias",
        ownership(target.bridges[0]),
    ] in kernel.commands
    assert kernel.links["eth1"]["master"] == "br-lan"
    assert "UP" in kernel.links["eth1"]["flags"]
    assert kernel.links["eth0"] == before["eth0"]
    adapter.rollback(snapshot)
    assert kernel.links == before


def test_atomic_create_alias_does_not_need_a_separate_tag_write(tmp_path: Path) -> None:
    kernel = FakeKernel(preserve_create_alias=True)
    adapter = driver(tmp_path, kernel)
    empty = LinkConfiguration()
    target = LinkConfiguration(bridges=[Bridge(name="br0")])
    adapter.snapshot(empty)
    adapter.apply(empty, target)
    assert kernel.links["br0"]["ifalias"] == ownership(target.bridges[0])
    assert not any(
        args[:2] == ["link", "set"] and args[4:5] == ["alias"] for args in kernel.commands
    )


@pytest.mark.parametrize("replacement", ["foreign_alias", "wrong_kind", "wrong_mtu"])
def test_create_alias_fallback_rejects_changed_shell(tmp_path: Path, replacement: str) -> None:
    kernel = FakeKernel()

    def runner(args: list[str]) -> str:
        result = kernel(args)
        if args[1:3] == ["link", "add"]:
            row = kernel.links["br0"]
            if replacement == "foreign_alias":
                row["ifalias"] = "another-owner"
            elif replacement == "wrong_kind":
                row["linkinfo"]["info_kind"] = "dummy"
            else:
                row["mtu"] = 1400
        return result

    adapter = LinuxLinkDriver(tmp_path, runner=runner)
    empty = LinkConfiguration()
    adapter.snapshot(empty)
    with pytest.raises(FirewallError, match="not owned|changed"):
        adapter.apply(empty, LinkConfiguration(bridges=[Bridge(name="br0")]))
    assert not any(
        args[:2] == ["link", "set"] and args[4:5] == ["alias"] for args in kernel.commands
    )
    assert not any(args[:3] == ["link", "delete", "dev"] for args in kernel.commands)


def test_create_alias_fallback_detects_replaced_ifindex(tmp_path: Path) -> None:
    kernel = FakeKernel()

    def runner(args: list[str]) -> str:
        result = kernel(args)
        if args[1:6] == ["link", "set", "dev", "br0", "alias"]:
            kernel.links["br0"]["ifindex"] += 100
        return result

    adapter = LinuxLinkDriver(tmp_path, runner=runner)
    empty = LinkConfiguration()
    adapter.snapshot(empty)
    with pytest.raises(FirewallError, match="changed during ownership"):
        adapter.apply(empty, LinkConfiguration(bridges=[Bridge(name="br0")]))
    assert not any(args[4:5] in (["up"], ["mtu"]) for args in kernel.commands)


def test_existing_untagged_bridge_is_never_adopted(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0")
    kernel.add_owned(bridge)
    kernel.links["br0"].pop("ifalias")
    adapter = driver(tmp_path, kernel)
    empty = LinkConfiguration()
    adapter.snapshot(empty)
    with pytest.raises(FirewallError, match="not owned"):
        adapter.apply(empty, LinkConfiguration(bridges=[bridge]))
    assert not any(args[:2] == ["link", "set"] for args in kernel.commands)


def test_refuses_foreign_interface_and_foreign_membership(tmp_path: Path) -> None:
    kernel = FakeKernel()
    adapter = driver(tmp_path, kernel)
    with pytest.raises(FirewallError, match="not owned"):
        adapter.check(LinkConfiguration(), LinkConfiguration(bridges=[Bridge(name="eth0")]))
    kernel.links["eth1"]["master"] = "foreign0"
    with pytest.raises(FirewallError, match="unmanaged"):
        adapter.check(
            LinkConfiguration(), LinkConfiguration(bridges=[Bridge(name="br0", members=["eth1"])])
        )
    assert not any(args[:2] == ["link", "add"] for args in kernel.commands)


def test_removed_bridge_with_changed_ownership_cannot_detach_ports(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0", members=["eth1"])
    previous = LinkConfiguration(bridges=[bridge])
    adapter = driver(tmp_path, kernel)
    adapter.snapshot(LinkConfiguration())
    adapter.apply(LinkConfiguration(), previous)
    kernel.links["br0"]["ifalias"] = "managed-by-someone-else"
    before = copy.deepcopy(kernel.links)
    adapter.snapshot(previous)
    with pytest.raises(FirewallError, match="not owned"):
        adapter.apply(previous, LinkConfiguration())
    assert kernel.links == before


def test_refuses_vlan_retargeting_and_missing_parent(tmp_path: Path) -> None:
    kernel = FakeKernel()
    vlan = Vlan(name="vlan10", parent="eth0", vlan_id=10)
    kernel.add_owned(vlan)
    adapter = driver(tmp_path, kernel)
    changed = vlan.model_copy(update={"vlan_id": 20})
    with pytest.raises(FirewallError, match="new interface name"):
        adapter.check(LinkConfiguration(vlans=[vlan]), LinkConfiguration(vlans=[changed]))
    with pytest.raises(FirewallError, match="does not exist"):
        adapter.check(
            LinkConfiguration(),
            LinkConfiguration(vlans=[Vlan(name="vlan99", parent="missing", vlan_id=99)]),
        )


def test_partial_apply_is_recoverable_after_process_restart(tmp_path: Path) -> None:
    kernel = FakeKernel()
    before = copy.deepcopy(kernel.links)
    target = LinkConfiguration(bridges=[Bridge(name="br0", members=["eth1"])])
    adapter = driver(tmp_path, kernel)
    snapshot = adapter.snapshot(LinkConfiguration())
    kernel.fail_when = lambda args: args == ["link", "set", "dev", "eth1", "up"]
    with pytest.raises(FirewallError, match="Simulated"):
        adapter.apply(LinkConfiguration(), target)
    assert kernel.links["eth1"]["master"] == "br0"
    kernel.fail_when = None
    driver(tmp_path, kernel).rollback(snapshot)
    assert kernel.links == before


def test_removal_is_deferred_and_address_restore_can_precede_final_rollback(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0")
    kernel.add_owned(bridge)
    kernel.addresses["br0"] = [{"family": "inet", "local": "192.168.50.1"}]
    previous = LinkConfiguration(bridges=[bridge])
    empty = LinkConfiguration()
    adapter = driver(tmp_path, kernel)
    snapshot = adapter.snapshot(previous)
    adapter.apply(previous, empty)
    assert "br0" in kernel.links
    with pytest.raises(FirewallError, match="still has an address"):
        adapter.finalize(previous, empty)
    # The network driver removes its owned address before deferred link deletion.
    kernel.addresses["br0"] = []
    adapter.finalize(previous, empty)
    assert "br0" not in kernel.links
    adapter.prepare_rollback(snapshot)
    assert "br0" in kernel.links
    assert "UP" in kernel.links["br0"]["flags"]
    # The network driver can now restore the original address.
    kernel.addresses["br0"] = [{"family": "inet", "local": "192.168.50.1"}]
    adapter.rollback(snapshot)
    assert kernel.links["br0"]["ifalias"] == ownership(bridge)


def test_prepare_recovery_restores_link_state_before_gateway_routes(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0", stp=False, mtu=1400)
    kernel.add_owned(bridge)
    kernel.links["br0"]["mtu"] = 1400
    previous = LinkConfiguration(bridges=[bridge])
    target = LinkConfiguration(bridges=[bridge.model_copy(update={"enabled": False, "stp": True})])
    adapter = driver(tmp_path, kernel)
    snapshot = adapter.snapshot(previous)
    adapter.apply(previous, target)
    assert "UP" not in kernel.links["br0"]["flags"]
    adapter.prepare_rollback(snapshot)
    assert "UP" in kernel.links["br0"]["flags"]
    assert kernel.links["br0"]["mtu"] == 1400
    assert kernel.links["br0"]["linkinfo"]["info_data"]["stp_state"] == 0


def test_finalize_preserves_foreign_routes_and_new_members(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0")
    kernel.add_owned(bridge)
    previous = LinkConfiguration(bridges=[bridge])
    adapter = driver(tmp_path, kernel)
    adapter.snapshot(previous)
    adapter.apply(previous, LinkConfiguration())
    kernel.routes["br0"] = [{"dst": "10.0.0.0/8", "protocol": "static"}]
    with pytest.raises(FirewallError, match="still has routes"):
        adapter.finalize(previous, LinkConfiguration())
    kernel.routes.clear()
    kernel.links["eth0"]["master"] = "br0"
    with pytest.raises(FirewallError, match="still has members"):
        adapter.finalize(previous, LinkConfiguration())
    assert kernel.links["eth0"]["master"] == "br0"


def test_finalize_preserves_ipv4_link_local_addresses(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0")
    kernel.add_owned(bridge)
    kernel.addresses["br0"] = [{"local": "169.254.1.2", "family": "inet"}]
    adapter = driver(tmp_path, kernel)
    with pytest.raises(FirewallError, match="still has an address"):
        adapter.finalize(LinkConfiguration(bridges=[bridge]), LinkConfiguration())
    assert "br0" in kernel.links


def test_rollback_stops_if_foreign_member_would_be_destroyed(tmp_path: Path) -> None:
    kernel = FakeKernel()
    target = LinkConfiguration(bridges=[Bridge(name="br0", members=["eth1"])])
    adapter = driver(tmp_path, kernel)
    snapshot = adapter.snapshot(LinkConfiguration())
    adapter.apply(LinkConfiguration(), target)
    kernel.links["eth0"]["master"] = "br0"  # Added by another administrator.
    with pytest.raises(FirewallError, match="still has members"):
        adapter.rollback(snapshot)
    assert kernel.links["eth0"]["master"] == "br0"
    assert "br0" in kernel.links
    assert "master" not in kernel.links["eth1"]


def test_existing_unmanaged_membership_is_not_silently_adopted(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0")
    kernel.add_owned(bridge)
    kernel.links["eth1"]["master"] = "br0"
    target = LinkConfiguration(bridges=[bridge.model_copy(update={"members": ["eth1"]})])
    with pytest.raises(FirewallError, match="unmanaged"):
        driver(tmp_path, kernel).check(LinkConfiguration(bridges=[bridge]), target)


def test_old_up_state_is_kept_across_multiple_confirmed_configurations(tmp_path: Path) -> None:
    kernel = FakeKernel()
    bridge = Bridge(name="br0", members=["eth1"])
    previous = LinkConfiguration(bridges=[bridge])
    target = LinkConfiguration(bridges=[bridge.model_copy(update={"members": []})])
    adapter = driver(tmp_path, kernel)
    adapter.snapshot(LinkConfiguration())
    adapter.apply(LinkConfiguration(), previous)
    assert kernel.links["eth1"]["flags"] == ["UP"]
    snapshot = adapter.snapshot(previous)
    adapter.apply(previous, target)
    assert kernel.links["eth1"]["flags"] == []
    adapter.rollback(snapshot)
    assert kernel.links["eth1"]["flags"] == ["UP"]
    assert kernel.links["eth1"]["master"] == "br0"


def test_snapshot_without_our_matching_intent_does_not_change_anything(tmp_path: Path) -> None:
    kernel = FakeKernel()
    adapter = driver(tmp_path, kernel)
    snapshot = adapter.snapshot(LinkConfiguration())
    kernel.links["eth1"]["master"] = "changed-by-admin"
    adapter.rollback(snapshot)
    assert kernel.links["eth1"]["master"] == "changed-by-admin"


def test_parse_parent_and_master_indices() -> None:
    rows = [
        {
            "ifname": "br0",
            "ifindex": 3,
            "mtu": 1500,
            "linkinfo": {"info_kind": "bridge", "info_data": {"stp_state": 1}},
        },
        {
            "ifname": "vlan10",
            "ifindex": 4,
            "master": 3,
            "link_index": 3,
            "linkinfo": {"info_kind": "vlan", "info_data": {"id": 10}},
        },
    ]
    result = parse_links(json.dumps(rows))
    assert result["vlan10"]["master"] == "br0"
    assert result["vlan10"]["parent"] == "br0"
    assert result["br0"]["stp"]
    with pytest.raises(FirewallError, match="invalid"):
        parse_links("not-json")


def test_subprocess_is_bounded_and_failures_are_domain_errors() -> None:
    with (
        patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ip", 10)),
        pytest.raises(FirewallError, match="timeout"),
    ):
        LinuxLinkDriver._execute(["/usr/sbin/ip", "link", "show"])
    with patch(
        "subprocess.run", return_value=subprocess.CompletedProcess("ip", 0, "[]", "")
    ) as run:
        assert LinuxLinkDriver._execute(["/usr/sbin/ip", "-j", "link", "show"]) == "[]"
        assert run.call_args.kwargs["timeout"] == 10
        assert not run.call_args.kwargs.get("shell")


def test_demo_never_executes_a_command() -> None:
    adapter = DemoLinkDriver()
    target = LinkConfiguration(bridges=[Bridge(name="br-lan", members=["eth1"])])
    with patch("subprocess.run") as run:
        snapshot = adapter.snapshot(LinkConfiguration())
        adapter.apply(LinkConfiguration(), target)
        assert adapter.config.bridges[0].name == "br-lan"
        adapter.finalize(LinkConfiguration(), target)
        adapter.prepare_rollback(snapshot)
        adapter.rollback(snapshot)
        assert not adapter.config.bridges
        run.assert_not_called()


@pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("NAT_RUN_KERNEL_TESTS") != "1",
    reason="Opt-in Linux root test confined to a new network namespace",
)
def test_real_link_lifecycle_in_a_new_network_namespace() -> None:
    unshare = shutil.which("unshare")
    assert unshare, "Install util-linux"
    code = """
import tempfile
from pathlib import Path
from app.link_models import Bridge, LinkConfiguration, Vlan, VirtualInterface
from app.links import LinuxLinkDriver
with tempfile.TemporaryDirectory() as directory:
    driver = LinuxLinkDriver(Path(directory))
    driver._ip('link', 'add', 'name', 'eth1', 'type', 'dummy')
    empty = LinkConfiguration()
    target = LinkConfiguration(
        bridges=[Bridge(name='br-lan', members=['eth1'])],
        vlans=[Vlan(name='vlan20', parent='br-lan', vlan_id=20)],
        virtual_interfaces=[VirtualInterface(name='dummy0')],
    )
    initial = driver.snapshot(empty)
    driver.check(empty, target)
    driver.apply(empty, target)
    driver.finalize(empty, target)
    current = driver._links()
    assert current['eth1']['master'] == 'br-lan'
    assert current['vlan20']['parent'] == 'br-lan'
    assert current['vlan20']['vlan_id'] == 20
    assert current['dummy0']['kind'] == 'dummy'
    checkpoint = driver.snapshot(target)
    driver.apply(target, empty)
    driver.finalize(target, empty)
    assert 'br-lan' not in driver._links()
    driver.prepare_rollback(checkpoint)
    assert 'br-lan' in driver._links()
    driver.rollback(checkpoint)
    assert driver._links()['eth1']['master'] == 'br-lan'
    driver.rollback(initial)
    restored = driver._links()
    assert 'br-lan' not in restored and 'vlan20' not in restored
    assert restored['eth1']['master'] is None
    assert not restored['eth1']['up']
"""
    result = subprocess.run(
        [unshare, "--net", sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
