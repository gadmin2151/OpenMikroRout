"""Regressions for server authorization and fail-closed VPN lifecycle transitions."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from test_bootstrap import RecordingDriver, write_state
from test_wireguard import configured
from test_wireguard_runtime import RoutingKernel

from app.bootstrap import BootstrapError, restore_confirmed_filters
from app.compiler import FirewallError
from app.filtering import DemoFilterDriver, filter_patch, filter_rollback
from app.link_models import WireGuardServerAccess
from app.models import Configuration
from app.network_models import NetworkConfiguration
from app.wireguard import WireGuardError
from app.wireguard_filter import access_rules
from app.wireguard_routing import (
    LinuxWireGuardRouting,
    entry_key,
    guard_entries,
    observed_entries,
    policy_entries,
)


def protected(directory: Path) -> NetworkConfiguration:
    _, config = configured(directory)
    config.wireguard_interfaces[0].route_allowed_ips = True
    config.wireguard_interfaces[0].route_sources = ["192.168.10.0/24"]
    config.wireguard_peers[0].allowed_ips = ["0.0.0.0/0"]
    return config


def test_server_boundary_precedes_foreign_accept_and_returns_only_selected_destinations(
    tmp_path: Path,
) -> None:
    network = protected(tmp_path)
    interface = network.wireguard_interfaces[0]
    interface.server_access = WireGuardServerAccess(
        source_network="10.99.0.0/24", access_networks=["172.16.1.0/24"]
    )
    config = Configuration(network=network)
    driver = DemoFilterDriver(Configuration())
    driver._table.table = driver.snapshot().replace(
        "COMMIT", "-A INPUT -j ACCEPT\n-A FORWARD -j ACCEPT\nCOMMIT"
    )
    before = driver.snapshot()
    driver.restore(filter_patch(before, config))
    after = driver.snapshot()
    assert after.index("--comment openmikrorout:wireguard-anchor -j OMR_WG_INPUT") < after.index(
        "-A INPUT -j ACCEPT"
    )
    assert after.index("--comment openmikrorout:wireguard-anchor -j OMR_WG_FORWARD") < after.index(
        "-A FORWARD -j ACCEPT"
    )
    rules = access_rules(config)
    assert len(rules) == 3
    assert "-s 10.99.0.0/24 -d 172.16.1.0/24" in rules[1] and rules[1].endswith("-j RETURN")
    assert rules[0].endswith("-j DROP") and rules[2].endswith("-j DROP")
    assert not any("-j ACCEPT" in line for line in rules)
    driver.restore(filter_rollback(after, before))
    assert "-A INPUT -j ACCEPT" in driver.snapshot()
    assert "wireguard-anchor" not in driver.snapshot()


def test_legacy_server_policy_is_not_inferred_from_client_routes(tmp_path: Path) -> None:
    network = protected(tmp_path)
    network.wireguard_interfaces[0].client_allowed_ips = ["0.0.0.0/0"]
    assert access_rules(Configuration(network=network)) == []


@pytest.mark.parametrize("change", ["table", "source"])
def test_transition_guards_precede_deletion_and_survive_injected_failure(
    tmp_path: Path, change: str
) -> None:
    previous = protected(tmp_path)
    target = previous.model_copy(deep=True)
    if change == "table":
        target.wireguard_interfaces[0].routing_table = 20001
    else:
        target.wireguard_interfaces[0].route_sources = ["192.168.10.0/25"]
    kernel = RoutingKernel()
    kernel.desired = [*policy_entries(previous), *policy_entries(target)]
    routing = LinuxWireGuardRouting(tmp_path, runner=kernel)
    routing.snapshot(NetworkConfiguration())
    routing.apply(NetworkConfiguration(), previous)
    snapshot = routing.snapshot(previous)
    kernel.commands.clear()
    routing.protect(previous, target)
    assert any(item.get("action") == "unreachable" for item in kernel.entries)
    kernel.fail_next_add = True
    with pytest.raises(WireGuardError):
        routing.apply(previous, target)
    first_delete = next(i for i, args in enumerate(kernel.commands) if args[3] == "del")
    assert any("unreachable" in args for args in kernel.commands[:first_delete])
    assert any(item.get("action") == "unreachable" for item in kernel.entries)
    # A fresh process recognizes the durable guard and can complete recovery.
    restarted = LinuxWireGuardRouting(tmp_path, runner=kernel)
    restarted.rollback(snapshot)
    assert {entry_key(item) for item in kernel.entries} == {
        entry_key(item) for item in policy_entries(previous)
    }


def test_boot_guard_needs_no_tunnel_and_survives_filter_startup_failure(tmp_path: Path) -> None:
    network = protected(tmp_path)
    config = Configuration(network=network)
    database = write_state(
        tmp_path, {"applied": config.model_dump(mode="json"), "config": {"untouched": True}}
    )
    before = database.read_bytes()
    kernel = RoutingKernel()
    kernel.desired = policy_entries(network)
    routing = LinuxWireGuardRouting(tmp_path, runner=kernel)
    filters = RecordingDriver()
    filters.reject_test = True
    with pytest.raises(BootstrapError):
        restore_confirmed_filters(tmp_path, filters, routing)
    assert database.read_bytes() == before
    assert {entry_key(item) for item in kernel.entries} == {
        entry_key(item) for item in guard_entries(["192.168.10.0/24"])
    }
    assert all("dev" not in args for args in kernel.commands)
    assert any("suppress_prefixlength" in args for args in kernel.commands)
    assert any("fwmark" in args for args in kernel.commands)
    state = json.loads((tmp_path / "wireguard-routes.json").read_text())
    assert state["guards"]
    restarted = LinuxWireGuardRouting(tmp_path, runner=kernel)
    restarted.restore_guards(network)
    snapshot = restarted.snapshot(network)
    with (
        patch.object(restarted, "_reconcile", side_effect=FirewallError("startup failed")),
        pytest.raises(FirewallError),
    ):
        restarted.apply(network, network)
    restarted.rollback(snapshot)
    assert any(item.get("action") == "unreachable" for item in kernel.entries)


@pytest.mark.parametrize("action", ["unreachable", "7"])
def test_unreachable_rule_json_is_owned_and_foreign_actions_are_rejected(action: str) -> None:
    rows = [
        {
            "priority": 9501,
            "src": "192.168.10.0",
            "srclen": 24,
            "action": action,
            "protocol": "196",
        }
    ]
    assert observed_entries(rows, [])[0]["action"] == "unreachable"
    rows[0]["action"] = "blackhole"
    with pytest.raises(WireGuardError, match="foreign"):
        observed_entries(rows, [])


@pytest.mark.parametrize("table", ["local", "255", 255])
def test_only_canonical_priority_zero_local_rule_is_exempt(table: str | int) -> None:
    assert observed_entries([{"priority": 0, "src": "all", "table": table}], []) == []


@pytest.mark.parametrize(
    "row",
    [
        {"priority": 0, "src": "192.168.10.0/24", "table": "main"},
        {"priority": 0, "src": "all", "table": "main"},
        {"priority": 0, "src": "192.168.10.0/24", "table": "local"},
        {"priority": 0, "src": "all", "table": "local", "fwmark": "0x1"},
        {"priority": 0, "src": "all", "table": "local", "dst": "192.0.2.0/24"},
        {"priority": 0, "src": "all", "table": "local", "iif": "eth0"},
        {"priority": 0, "src": "all", "table": "local", "suppress_prefixlen": 32},
        {"priority": 0, "src": "all", "action": "unreachable"},
        {"priority": 0, "src": "all", "table": "local", "action": "goto", "target": 32766},
        {"priority": 0, "table": "local"},
    ],
)
def test_foreign_priority_zero_rules_are_rejected(row: dict[str, str | int]) -> None:
    with pytest.raises(WireGuardError, match="priority-zero.*bypass"):
        observed_entries([{"priority": 0, "src": "all", "table": "local"}, row], [])
