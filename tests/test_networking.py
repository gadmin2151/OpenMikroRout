import copy
import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.network_models import NetworkConfiguration
from app.networking import DemoNetworkDriver, LinuxNetworkDriver, NetworkError, dnsmasq_configs


def router_data() -> dict[str, Any]:
    return {
        "addresses": [{"interface": "eth1", "address": "192.168.10.1/24"}],
        "routes": [{"destination": "0.0.0.0/0", "gateway": "203.0.113.1", "interface": "eth0"}],
        "interface_lists": [{"name": "LAN", "members": ["eth1"]}],
        "pools": [{"name": "lan-pool", "start": "192.168.10.100", "end": "192.168.10.200"}],
        "dhcp_servers": [
            {
                "name": "lan",
                "interface": "eth1",
                "pool": "lan-pool",
                "network": "192.168.10.0/24",
                "gateway": "192.168.10.1",
                "dns_servers": ["1.1.1.1"],
            }
        ],
        "dhcp_reservations": [
            {
                "server": "lan",
                "mac": "02:11:22:33:44:55",
                "address": "192.168.10.50",
                "hostname": "printer",
            }
        ],
        "dns": {
            "enabled": True,
            "listen_interfaces": ["eth1"],
            "servers": ["9.9.9.9"],
            "local_domain": "home.arpa",
        },
        "forwarding": True,
    }


def router() -> NetworkConfiguration:
    return NetworkConfiguration.model_validate(router_data())


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("addresses", "interface", "eth1;reboot"),
        ("addresses", "interface", "interface-too-long"),
        ("addresses", "address", "192.168.10.0/24"),
        ("addresses", "address", "192.168.10.255/24"),
        ("addresses", "address", "::1/64"),
        ("addresses", "address", "1.2.3.4\nCOMMIT"),
        ("routes", "gateway", "203.0.113.1;reboot"),
        ("routes", "metric", -1),
        ("pools", "start", "192.168.10.201"),
        ("pools", "end", "192.168.11.1"),
        ("pools", "start", "192.168.10.1"),
        ("dhcp_servers", "pool", "missing"),
        ("dhcp_servers", "gateway", "192.168.10.2"),
        ("dhcp_servers", "lease_minutes", 0),
        ("dhcp_reservations", "server", "missing"),
        ("dhcp_reservations", "mac", "ff:ff:ff:ff:ff:ff"),
        ("dhcp_reservations", "mac", "00:00:00:00:00:00"),
        ("dhcp_reservations", "address", "192.168.10.1"),
        ("dhcp_reservations", "hostname", "printer\ndhcp-script=/bin/sh"),
    ],
)
def test_rejects_invalid_router_settings(section: str, field: str, value: Any) -> None:
    data = router_data()
    data[section][0][field] = value
    with pytest.raises(ValidationError):
        NetworkConfiguration.model_validate(data)


def test_dhcp_requires_managed_gateway_and_explicit_dns() -> None:
    data = router_data()
    data["addresses"] = []
    with pytest.raises(ValidationError, match="Assign gateway"):
        NetworkConfiguration.model_validate(data)
    data = router_data()
    data["dhcp_servers"][0]["dns_servers"] = []
    assert NetworkConfiguration.model_validate(data).dhcp_servers[0].dns_servers == []
    data["dns"]["enabled"] = False
    with pytest.raises(ValidationError, match="DHCP DNS servers"):
        NetworkConfiguration.model_validate(data)


def test_dns_requires_explicit_managed_listener_and_avoids_self_loop() -> None:
    data = router_data()
    data["dns"]["listen_interfaces"] = ["eth0"]
    with pytest.raises(ValidationError, match="managed IPv4 address"):
        NetworkConfiguration.model_validate(data)
    data = router_data()
    data["dns"]["servers"] = ["192.168.10.1"]
    with pytest.raises(ValidationError, match="back to the router"):
        NetworkConfiguration.model_validate(data)
    data = router_data()
    data["dns"]["listen_interfaces"] = []
    with pytest.raises(ValidationError, match="explicit listening"):
        NetworkConfiguration.model_validate(data)


def test_cross_reference_and_topology_validation() -> None:
    data = router_data()
    data["bridges"] = [{"name": "br0", "members": ["eth1"]}]
    with pytest.raises(ValidationError, match="not its member"):
        NetworkConfiguration.model_validate(data)
    data = router_data()
    data["dhcp_reservations"].append(copy.deepcopy(data["dhcp_reservations"][0]))
    with pytest.raises(ValidationError, match="unique MAC and IP"):
        NetworkConfiguration.model_validate(data)
    data = router_data()
    data["routes"].append(copy.deepcopy(data["routes"][0]))
    with pytest.raises(ValidationError, match="different metrics"):
        NetworkConfiguration.model_validate(data)


def test_service_configs_never_expose_dns_on_dhcp_listener_implicitly(tmp_path: Path) -> None:
    data = router_data()
    config = NetworkConfiguration.model_validate(data)
    configs = dnsmasq_configs(config, tmp_path)
    assert configs["dhcp"] is not None and configs["dns"] is not None
    assert "port=0\n" in configs["dhcp"]
    assert "except-interface=lo" in configs["dhcp"]
    assert "interface=eth1\n" in configs["dhcp"]
    assert "interface=eth1:o\n" in configs["dhcp"]
    assert "listen-address=192.168.10.1\n" in configs["dns"]
    assert "interface=" not in configs["dns"]
    assert "listen-address=0.0.0.0" not in configs["dns"]
    assert "no-resolv\n" in configs["dns"]
    assert "host-record=printer.home.arpa,192.168.10.50" in configs["dns"]
    data["dns"]["enabled"] = False
    assert dnsmasq_configs(NetworkConfiguration.model_validate(data), tmp_path)["dns"] is None


class Kernel:
    """Small kernel fixture that records argv and owns no real host resources."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.addresses: list[dict[str, Any]] = [
            {"interface": "eth0", "address": "203.0.113.10/24", "managed": False}
        ]
        self.routes: list[dict[str, Any]] = [
            {
                "destination": "198.51.100.0/24",
                "gateway": "203.0.113.1",
                "interface": "eth0",
                "metric": 5,
                "managed": False,
            }
        ]
        self.services = {"dhcp": False, "dns": False}
        self.links = {"eth0": True, "eth1": False, "eth2": False}
        self.commands: list[list[str]] = []
        self.fail_route = False
        self.fail_dns_once = False

    def command(self, args: list[str]) -> str:
        self.commands.append(args)
        if args[0] == "dnsmasq":
            if "--test" in args:
                return "syntax check OK"
            kind = Path(args[1].split("=", 1)[1]).stem
            if kind == "dns" and self.fail_dns_once:
                self.fail_dns_once = False
                raise NetworkError("Address already in use")
            self.services[kind] = True
            return ""
        if "link" in args:
            if "show" in args:
                return json.dumps(
                    [
                        {"ifname": name, "flags": ["UP"] if up else []}
                        for name, up in self.links.items()
                    ]
                )
            name = args[args.index("dev") + 1]
            self.links[name] = args[-1] == "up"
            return ""
        if "address" in args and "show" in args:
            result = []
            for row in self.addresses:
                address, prefix = row["address"].split("/")
                result.append(
                    {
                        "ifname": row["interface"],
                        "addr_info": [
                            {
                                "family": "inet",
                                "local": address,
                                "prefixlen": int(prefix),
                                "label": row["interface"] + (":o" if row["managed"] else ""),
                                "secondary": row.get("secondary", False),
                            }
                        ],
                    }
                )
            return json.dumps(result)
        if "route" in args and "show" in args:
            return json.dumps(
                [
                    {
                        "dst": row["destination"],
                        "gateway": row["gateway"],
                        "dev": row["interface"],
                        "metric": row["metric"],
                        "protocol": 196 if row["managed"] else "static",
                    }
                    for row in self.routes
                ]
            )
        if "address" in args:
            operation = args[3]
            address = args[4]
            interface = args[args.index("dev") + 1]
            if operation == "add":
                assert "label" in args and args[args.index("label") + 1] == interface + ":o"
                self.addresses.append({"interface": interface, "address": address, "managed": True})
            else:
                self.addresses = [
                    row
                    for row in self.addresses
                    if (row["interface"], row["address"]) != (interface, address)
                ]
            return ""
        if "route" in args:
            if self.fail_route:
                self.fail_route = False
                raise NetworkError("Route not reachable")
            operation = args[3]
            destination = args[4]
            assert args[args.index("proto") + 1] == "196"
            gateway = args[args.index("via") + 1] if "via" in args else ""
            interface = args[args.index("dev") + 1] if "dev" in args else ""
            metric = int(args[args.index("metric") + 1])
            if operation == "add":
                self.routes.append(
                    {
                        "destination": destination,
                        "gateway": gateway,
                        "interface": interface,
                        "metric": metric,
                        "managed": True,
                    }
                )
            else:
                self.routes = [
                    row
                    for row in self.routes
                    if (row["destination"], row["gateway"], row["interface"], row["metric"])
                    != (destination, gateway, interface, metric)
                ]
            return ""
        raise AssertionError(f"Unexpected command: {args}")


@pytest.fixture
def kernel_driver(tmp_path: Path) -> Iterator[tuple[Kernel, LinuxNetworkDriver]]:
    driver = LinuxNetworkDriver(tmp_path)
    driver.ip_binary = "ip"
    driver.dnsmasq_binary = "dnsmasq"
    driver.forwarding_file = tmp_path / "forwarding"
    driver.forwarding_file.write_text("0\n")
    kernel = Kernel(driver.directory)
    with (
        patch("app.networking.run_command", side_effect=kernel.command),
        patch.object(
            driver, "_owned_pid", side_effect=lambda kind: 123 if kernel.services[kind] else None
        ),
        patch.object(
            driver,
            "_stop_service",
            side_effect=lambda kind: kernel.services.__setitem__(kind, False),
        ),
    ):
        yield kernel, driver


def test_check_is_read_only_and_refuses_to_take_over_addresses_or_routes(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    driver.check(NetworkConfiguration(), router())
    assert not any("add" in args or "del" in args for args in kernel.commands)
    assert not (driver.directory / "dhcp.conf").exists()
    assert not any(kernel.services.values())
    data = router_data()
    data["addresses"].append({"interface": "eth0", "address": "203.0.113.10/24"})
    with pytest.raises(NetworkError, match="another network manager"):
        driver.check(NetworkConfiguration(), NetworkConfiguration.model_validate(data))
    data = router_data()
    data["routes"] = [
        {
            "destination": "198.51.100.0/24",
            "gateway": "203.0.113.1",
            "interface": "eth0",
            "metric": 5,
        }
    ]
    with pytest.raises(NetworkError, match="non-managed route"):
        driver.check(NetworkConfiguration(), NetworkConfiguration.model_validate(data))


def test_accepts_planned_bridge_before_it_is_created(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    _, driver = kernel_driver
    data = router_data()
    data["bridges"] = [{"name": "br0", "members": ["eth1"]}]
    data["addresses"][0]["interface"] = "br0"
    data["dhcp_servers"][0]["interface"] = "br0"
    data["dns"]["listen_interfaces"] = ["br0"]
    driver.check(NetworkConfiguration(), NetworkConfiguration.model_validate(data))


def test_apply_and_rollback_preserve_foreign_resources_and_issued_leases(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    before = driver.snapshot(NetworkConfiguration())
    driver.apply(NetworkConfiguration(), router())
    assert len(kernel.addresses) == 2
    assert len(kernel.routes) == 2
    assert all(kernel.services.values())
    assert driver.forwarding_file.read_text() == "1\n"
    kernel.addresses.append({"interface": "eth0", "address": "203.0.113.20/24", "managed": False})
    kernel.routes.append(
        {
            "destination": "192.0.2.0/24",
            "gateway": "203.0.113.1",
            "interface": "eth0",
            "metric": 7,
            "managed": False,
        }
    )
    lease_file = driver.directory / "dhcp.leases"
    lease = "2000000000 02:11:22:33:44:55 192.168.10.100 laptop *\n"
    lease_file.write_text(lease)
    driver.rollback(before)
    assert all(not item["managed"] for item in kernel.addresses + kernel.routes)
    assert len(kernel.addresses) == 2 and len(kernel.routes) == 2
    assert not any(kernel.services.values())
    assert driver.forwarding_file.read_text() == "0\n"
    assert lease_file.read_text() == lease


def test_partial_route_failure_can_be_rolled_back(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    before = driver.snapshot(NetworkConfiguration())
    kernel.fail_route = True
    with pytest.raises(NetworkError, match="not reachable"):
        driver.apply(NetworkConfiguration(), router())
    assert any(row["managed"] for row in kernel.addresses)
    driver.rollback(before)
    assert all(not row["managed"] for row in kernel.addresses)


def test_dns_port_conflict_keeps_foreign_service_and_recovers_previous_configs(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    previous_data = router_data()
    previous_data["dns"]["enabled"] = False
    previous = NetworkConfiguration.model_validate(previous_data)
    driver.apply(NetworkConfiguration(), previous)
    before = driver.snapshot(previous)
    kernel.fail_dns_once = True
    with pytest.raises(NetworkError, match="Address already in use"):
        driver.apply(previous, router())
    driver.rollback(before)
    assert kernel.services == {"dhcp": True, "dns": False}
    assert driver._read_config("dns") is None
    assert driver._read_config("dhcp") == before["dnsmasq"]["dhcp"]


def test_reconcile_restarts_missing_services_without_duplicating_resources(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    target = router()
    driver.apply(NetworkConfiguration(), target)
    kernel.services = {"dhcp": False, "dns": False}
    kernel.commands.clear()
    driver.apply(target, target)
    assert all(kernel.services.values())
    assert not any("add" in args or "del" in args for args in kernel.commands)


def test_physical_interface_up_is_recovered_without_touching_unrelated_links(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    before = driver.snapshot(NetworkConfiguration())
    driver.apply(NetworkConfiguration(), router())
    assert kernel.links["eth1"]
    # An administrator changes an unrelated interface while application is pending.
    kernel.links["eth2"] = True
    driver.rollback(before)
    assert not kernel.links["eth1"]
    assert kernel.links["eth0"]
    assert kernel.links["eth2"]
    assert driver._admin_registry() == {}


def test_up_intent_is_durable_before_link_change_and_recovers_after_partial_failure(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    before = driver.snapshot(NetworkConfiguration())
    original_command = kernel.command

    def inspected(args: list[str]) -> str:
        if args == ["ip", "link", "set", "dev", "eth1", "up"]:
            assert driver._admin_registry() == {"eth1": False}
        return original_command(args)

    kernel.fail_route = True
    with (
        patch("app.networking.run_command", side_effect=inspected),
        pytest.raises(NetworkError, match="Route not reachable"),
    ):
        driver.apply(NetworkConfiguration(), router())
    assert kernel.links["eth1"]
    driver.rollback(before)
    assert not kernel.links["eth1"]


def test_disabled_managed_link_can_stage_address_but_not_active_service(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    kernel.links["br0"] = False
    target = NetworkConfiguration.model_validate(
        {
            "bridges": [{"name": "br0", "enabled": False}],
            "addresses": [{"interface": "br0", "address": "192.168.20.1/24"}],
        }
    )
    driver.apply(NetworkConfiguration(), target)
    assert not kernel.links["br0"]
    data = router_data()
    data["bridges"] = [{"name": "br0", "enabled": False}]
    data["addresses"][0]["interface"] = "br0"
    data["dhcp_servers"][0]["interface"] = "br0"
    data["dns"]["listen_interfaces"] = ["br0"]
    with pytest.raises(ValidationError, match="Enable the managed interface"):
        NetworkConfiguration.model_validate(data)


def test_primary_address_removal_refuses_to_remove_foreign_secondaries(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    kernel, driver = kernel_driver
    before = driver.snapshot(NetworkConfiguration())
    driver.apply(NetworkConfiguration(), router())
    kernel.addresses.append(
        {"interface": "eth1", "address": "192.168.10.2/24", "managed": False, "secondary": True}
    )
    with pytest.raises(NetworkError, match="foreign addresses share"):
        driver.rollback(before)
    assert any(item["address"] == "192.168.10.2/24" for item in kernel.addresses)
    assert any(item["address"] == "192.168.10.1/24" for item in kernel.addresses)


@pytest.mark.parametrize("resource", ["address", "route"])
def test_corrupt_reserved_state_is_a_recoverable_domain_error(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver], resource: str
) -> None:
    kernel, driver = kernel_driver
    if resource == "address":
        kernel.addresses.append(
            {"interface": "eth1", "address": "192.168.10.0/24", "managed": True}
        )
    else:
        kernel.routes.append(
            {
                "destination": "not-a-network",
                "gateway": "203.0.113.1",
                "interface": "eth0",
                "metric": 100,
                "managed": True,
            }
        )
    with pytest.raises(NetworkError, match="Cannot snapshot managed networking"):
        driver.snapshot(NetworkConfiguration())


def test_corrupt_recovery_snapshot_is_a_domain_error(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    _, driver = kernel_driver
    before = driver.snapshot(NetworkConfiguration())
    before["addresses"] = [{"interface": "eth1", "address": "192.168.10.0/24"}]
    with pytest.raises(NetworkError, match="Cannot rollback managed networking"):
        driver.rollback(before)


def test_malformed_leases_do_not_break_valid_status(
    kernel_driver: tuple[Kernel, LinuxNetworkDriver],
) -> None:
    _, driver = kernel_driver
    (driver.directory / "dhcp.leases").write_text(
        "2000000000 02:11:22:33:44:55 192.168.10.100 laptop *\ninvalid\n"
    )
    assert driver.status()["leases"] == [
        {
            "expires": 2000000000,
            "mac": "02:11:22:33:44:55",
            "address": "192.168.10.100",
            "hostname": "laptop",
            "client_id": "",
        }
    ]


def test_does_not_signal_a_pid_without_exact_process_ownership(tmp_path: Path) -> None:
    driver = LinuxNetworkDriver(tmp_path)
    (driver.directory / "dns.pid").write_text("999\n")
    with (
        patch("pathlib.Path.read_bytes", return_value=b"dnsmasq\0--conf-file=/etc/dnsmasq.conf\0"),
        patch("pathlib.Path.resolve", return_value=Path("/usr/sbin/dnsmasq")),
        patch("app.networking.os.kill") as kill,
    ):
        driver._stop_service("dns")
        kill.assert_not_called()


def test_demo_lifecycle_never_calls_subprocess(tmp_path: Path) -> None:
    driver = DemoNetworkDriver()
    before = driver.snapshot(NetworkConfiguration())
    with patch("subprocess.run", side_effect=AssertionError("Demo must never call Linux commands")):
        driver.check(NetworkConfiguration(), router())
        assert "dhcp-range" in driver.preview(NetworkConfiguration(), router())["script"]
        driver.apply(NetworkConfiguration(), router())
        assert driver.status()["dnsmasq"]["dhcp"]["running"]
        driver.rollback(before)
        assert driver.status()["addresses"] == []


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Opt-in Linux network namespace test; never mutates host networking",
)
def test_real_networking_in_isolated_namespace() -> None:
    unshare = shutil.which("unshare")
    assert unshare, "Install util-linux"
    code = """
from pathlib import Path
from tempfile import TemporaryDirectory
from app.networking import LinuxNetworkDriver, run_command
from app.network_models import NetworkConfiguration
run_command(['ip','link','add','eth1','type','dummy'])
run_command(['ip','link','set','eth1','up'])
run_command(['ip','address','add','192.0.2.1/24','dev','eth1'])
with TemporaryDirectory() as path:
    driver = LinuxNetworkDriver(Path(path))
    old = NetworkConfiguration()
    target = NetworkConfiguration.model_validate({
        'addresses':[{'interface':'eth1','address':'192.168.10.1/24'}]
    })
    before = driver.snapshot(old)
    driver.check(old,target)
    try:
        driver.apply(old,target)
        assert any(row['managed'] for row in driver.status()['addresses'])
    finally:
        driver.rollback(before)
    assert not any(row['managed'] for row in driver.status()['addresses'])
    assert any(row['address']=='192.0.2.1/24' for row in driver.status()['addresses'])
"""
    result = subprocess.run(
        [unshare, "--net", sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        timeout=40,
    )
    assert result.returncode == 0, result.stderr
