import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from test_wireguard import configured

from app.links import DemoLinkDriver
from app.network_models import NetworkConfiguration
from app.wireguard import (
    LinuxWireGuardDriver,
    WireGuardError,
    execute_wireguard,
    parse_wireguard_status,
)
from app.wireguard_routing import (
    LinuxWireGuardRouting,
    entry_command,
    entry_key,
    observed_entries,
    policy_entries,
)


def test_runtime_private_snapshot_status_and_rollback_do_not_expose_keys(tmp_path: Path) -> None:
    vault, network = configured(tmp_path)
    interface = network.wireguard_interfaces[0]
    links = DemoLinkDriver(network)
    private = vault.secret(interface.private_key_id, "interface")
    actual = f"[Interface]\nPrivateKey = {private}\nListenPort = 51820\n"
    requests: list[tuple[list[str], str | None]] = []

    def command(arguments: list[str], payload: str | None = None) -> str:
        requests.append((arguments, payload))
        if "showconf" in arguments:
            return actual
        if "dump" in arguments:
            return f"{private}\t{interface.public_key}\t51820\toff\n"
        return ""

    driver = LinuxWireGuardDriver(tmp_path, network, links, vault, runner=command)
    driver.binary = "/usr/bin/wg"
    snapshot = driver.snapshot(network)
    assert private not in json.dumps(snapshot)
    target = network.model_copy(deep=True)
    target.wireguard_peers = []
    driver.check(network, target)
    driver.apply(network, target)
    assert all(private not in " ".join(args) for args, _ in requests)
    assert any(
        args[-1] == "/dev/stdin" and private in (payload or "") for args, payload in requests
    )
    assert private not in json.dumps(driver.status())
    restarted = LinuxWireGuardDriver(tmp_path, target, links, vault, runner=command)
    restarted.binary = driver.binary
    restarted.rollback(snapshot)
    assert requests[-1][1] == actual
    assert restarted.config == network


def test_runtime_refuses_foreign_interface_before_mutating(tmp_path: Path) -> None:
    vault, network = configured(tmp_path)
    links = DemoLinkDriver(network)
    driver = LinuxWireGuardDriver(tmp_path, network, links, vault)
    driver.binary = "/usr/bin/wg"
    driver.transaction = "snapshot-required"
    observed = links.status()
    observed["links"][0]["alias"] = "foreign"
    with (
        patch.object(links, "status", return_value=observed),
        pytest.raises(WireGuardError, match="ownership"),
    ):
        driver.apply(NetworkConfiguration(), network)
    assert not driver.path.exists()


def test_endpoint_resolution_cache_is_scoped_to_enabled_interfaces_and_survives_dns_failure(
    tmp_path: Path,
) -> None:
    vault, network = configured(tmp_path)
    network.wireguard_peers[0].endpoint_host = "vpn.example.com"
    driver = LinuxWireGuardDriver(
        tmp_path,
        network,
        DemoLinkDriver(network),
        vault,
        runner=lambda arguments, payload=None: "",
        resolver=lambda host: "192.0.2.1",
    )
    driver.binary = "/usr/bin/wg"
    driver.snapshot(NetworkConfiguration())
    driver.check(NetworkConfiguration(), network)
    driver.apply(NetworkConfiguration(), network)
    driver.resolver = lambda host: (_ for _ in ()).throw(WireGuardError("DNS unavailable"))
    assert driver._resolved(network) == {"vpn.example.com": "192.0.2.1"}
    network.wireguard_interfaces[0].enabled = False
    assert driver._resolved(network) == {}


def test_wireguard_stderr_and_dump_secret_columns_are_never_returned(tmp_path: Path) -> None:
    vault, network = configured(tmp_path)
    private = vault.secret(network.wireguard_interfaces[0].private_key_id, "interface")
    psk = "SECRET-PSK-DO-NOT-EXPOSE"
    peer = network.wireguard_peers[0]
    output = (
        f"{private}\t{network.wireguard_interfaces[0].public_key}\t51820\toff\n"
        f"{peer.public_key}\t{psk}\t192.0.2.2:51820\t10.99.0.2/32\t1000\t42\t84\t25\n"
    )
    status = parse_wireguard_status("wg-test", output, 1010)
    assert status["peers"][0]["connected"]
    assert private not in str(status) and psk not in str(status)
    assert (
        parse_wireguard_status("wg-test", output.replace("\t25\n", "\toff\n"), 1010)["peers"][0][
            "persistent_keepalive"
        ]
        == 0
    )
    with patch(
        "app.wireguard.subprocess.run",
        return_value=subprocess.CompletedProcess(["wg"], 1, "", private),
    ):
        with pytest.raises(WireGuardError) as failure:
            execute_wireguard(["wg", "syncconf", "wg-test", "/dev/stdin"], private)
        assert private not in str(failure.value)


def test_source_policy_has_endpoint_exemption_scoped_tables_and_fail_closed_routes(
    tmp_path: Path,
) -> None:
    _, network = configured(tmp_path)
    interface = network.wireguard_interfaces[0]
    interface.route_allowed_ips, interface.route_sources = True, ["192.168.10.0/24"]
    network.wireguard_peers[0].allowed_ips = ["0.0.0.0/0"]
    entries = policy_entries(network)
    assert entries[0]["priority"] == 9000 and entries[0]["mask"] == 0xFFFF0000
    routes = [entry for entry in entries if entry["kind"] == "route"]
    assert {item["type"] for item in routes} == {"unicast", "unreachable"}
    assert all(item["table"] == 20000 for item in routes)
    interface.enabled = False
    assert [entry["type"] for entry in policy_entries(network) if entry["kind"] == "route"] == [
        "unreachable"
    ]
    interface.kill_switch = False
    assert not any(entry["kind"] == "route" for entry in policy_entries(network))
    assert all("main" not in entry_command("ip", "add", item) for item in routes)


def test_foreign_policy_table_and_priority_conflicts_are_refused() -> None:
    with pytest.raises(WireGuardError, match="foreign"):
        observed_entries([{"priority": 10000, "src": "all", "table": 254}], [])
    with pytest.raises(WireGuardError, match="foreign"):
        observed_entries(
            [], [{"dst": "default", "dev": "eth0", "table": 20000, "protocol": "static"}]
        )
    assert observed_entries([{"priority": 32766, "src": "all", "table": "main"}], []) == []
    with pytest.raises(WireGuardError, match="bypass"):
        observed_entries([{"priority": 100, "src": "all", "table": "main"}], [])


def test_real_iproute_json_prefix_fields_and_linkdown_flags_are_normalized() -> None:
    rules = [
        {
            "priority": 10000,
            "src": "192.168.10.0",
            "srclen": 24,
            "table": "254",
            "protocol": "196",
            "suppress_prefixlen": 0,
        }
    ]
    routes = [
        {
            "dst": "default",
            "dev": "wg-test",
            "table": "20000",
            "protocol": "196",
            "metric": 10,
            "scope": "link",
            "flags": ["linkdown"],
        }
    ]
    entries = observed_entries(rules, routes)
    assert entries[0]["source"] == "192.168.10.0/24" and entries[0]["suppress"] == 0
    assert entries[1]["destination"] == "0.0.0.0/0" and entries[1]["table"] == 20000


class RoutingKernel:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.fail_next_add = False

    def __call__(self, args: list[str]) -> str:
        if "-j" in args:
            kind = "rule" if "rule" in args else "route"
            rows = []
            for item in self.entries:
                if item["kind"] != kind:
                    continue
                if kind == "route":
                    rows.append(
                        {
                            "table": item["table"],
                            "dst": item["destination"],
                            "dev": item["device"],
                            "metric": item["metric"],
                            "type": item["type"],
                            "protocol": 196,
                        }
                    )
                else:
                    row = {
                        "priority": item["priority"],
                        "src": item["source"],
                        "table": item["table"],
                        "protocol": 196,
                    }
                    if "suppress" in item:
                        row["suppress_prefixlen"] = item["suppress"]
                    if "mark" in item:
                        row.update(fwmark=item["mark"], fwmask=item["mask"])
                    rows.append(row)
            return json.dumps(rows)
        operation = args[3]
        if operation == "add" and self.fail_next_add:
            self.fail_next_add = False
            raise WireGuardError("Injected routing failure")
        for item in self.desired:
            if entry_command(args[0], operation, item) == args:
                if operation == "add":
                    self.entries.append(item)
                else:
                    self.entries = [
                        entry for entry in self.entries if entry_key(entry) != entry_key(item)
                    ]
                return ""
        raise AssertionError(args)

    desired: list[dict[str, Any]] = []


def test_policy_apply_restart_rollback_and_partial_failure_are_durable(tmp_path: Path) -> None:
    _, network = configured(tmp_path)
    network.wireguard_interfaces[0].route_allowed_ips = True
    network.wireguard_interfaces[0].route_sources = ["192.168.10.0/24"]
    kernel = RoutingKernel()
    kernel.desired = policy_entries(network)
    driver = LinuxWireGuardRouting(tmp_path, runner=kernel)
    snapshot = driver.snapshot(NetworkConfiguration())
    driver.check(NetworkConfiguration(), network)
    driver.apply(NetworkConfiguration(), network)
    assert len(kernel.entries) == len(kernel.desired)
    restarted = LinuxWireGuardRouting(tmp_path, runner=kernel)
    restarted.rollback(snapshot)
    assert kernel.entries == []
    snapshot = driver.snapshot(NetworkConfiguration())
    kernel.fail_next_add = True
    with pytest.raises(WireGuardError):
        driver.apply(NetworkConfiguration(), network)
    restarted.rollback(snapshot)
    assert kernel.entries == []


def test_source_policy_rejects_global_or_ambiguous_sources(tmp_path: Path) -> None:
    _, config = configured(tmp_path)
    data = config.model_dump(mode="json")
    data["wireguard_interfaces"][0].update(route_allowed_ips=True, route_sources=["0.0.0.0/0"])
    with pytest.raises(ValueError, match="global host"):
        NetworkConfiguration.model_validate(data)
    data["wireguard_interfaces"][0]["route_sources"] = ["10.0.0.0/8", "10.1.0.0/16"]
    with pytest.raises(ValueError, match="overlap"):
        NetworkConfiguration.model_validate(data)
