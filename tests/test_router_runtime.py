import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from app.compiler import FirewallError, compiled_rules
from app.demo import demo_config
from app.filtering import DemoFilterDriver, compiled_filters, filter_patch, filter_rollback
from app.firewall import Conflict, DemoDriver, FirewallService
from app.links import DemoLinkDriver
from app.models import Configuration, FilterRule, NatRule
from app.network_models import NetworkConfiguration
from app.networking import DemoNetworkDriver
from app.runtime import RouterRuntime
from app.storage import Store


def service_at(directory: Path) -> FirewallService:
    initial = Configuration()
    runtime = RouterRuntime(
        DemoNetworkDriver(initial.network),
        DemoLinkDriver(initial.network),
        DemoFilterDriver(initial),
    )
    return FirewallService(
        Store(directory / "router.sqlite3", initial), DemoDriver(initial), runtime=runtime
    )


def test_filter_compilation_expands_interface_lists_and_preserves_foreign_chains() -> None:
    config = demo_config()
    lines = compiled_filters(config)
    assert any("-j DROP" in line for line in lines)
    dhcp = [line for line in lines if "--dports 67 " in line]
    assert len(dhcp) == 2
    assert any("-i br-lan" in line for line in dhcp)
    assert any("-i vlan20" in line for line in dhcp)
    driver = DemoFilterDriver(Configuration())
    driver._table.table = driver.snapshot().replace(
        "COMMIT", "-A INPUT -s 10.0.0.0/8 -j ACCEPT\nCOMMIT"
    )
    before = driver.snapshot()
    driver.restore(filter_patch(before, config))
    assert "-A INPUT -s 10.0.0.0/8 -j ACCEPT" in driver.snapshot()
    assert driver.snapshot().count("openmikrorout:filter-anchor") == 3
    driver.restore(filter_rollback(driver.snapshot(), before))
    assert driver.snapshot() == before


def test_nat_interface_lists_expand_and_share_reference_validation() -> None:
    config = demo_config()
    config.rules = [
        NatRule(
            name="Internet",
            chain="srcnat",
            action="masquerade",
            protocol="any",
            out_interface_list="LOCAL",
        )
    ]
    lines = compiled_rules(config)
    assert len(lines) == 2
    assert any("-o br-lan" in line for line in lines)
    assert any("-o vlan20" in line for line in lines)
    with pytest.raises(ValueError, match="Unknown interface list"):
        Configuration(
            rules=[
                NatRule(
                    name="Bad",
                    chain="srcnat",
                    action="masquerade",
                    protocol="any",
                    out_interface_list="missing",
                )
            ]
        )
    with pytest.raises(ValueError, match="outgoing interface"):
        FilterRule(name="Bad", chain="input", out_interface="eth0")


def test_unified_apply_and_manual_rollback_restores_network_links_and_filter(
    tmp_path: Path,
) -> None:
    service = service_at(tmp_path)
    assert service.runtime is not None
    before_nat = service.driver.snapshot()
    before_filter = service.runtime.filters.snapshot()
    target = demo_config()
    service.save(target, 0)
    pending = service.apply(1)["pending"]
    assert pending
    status = service.network_status()
    assert {row["name"] for row in status["links"]} == {"br-lan", "vlan20", "lo-mgmt"}
    assert len(status["addresses"]) == 3
    assert status["dnsmasq"]["dhcp"]["running"]
    assert "-j DROP" in service.runtime.filters.snapshot()
    stored = service.store.read("pending")
    assert stored["router_snapshot"]["network"]
    assert stored["router_snapshot"]["links"]
    service.rollback()
    assert service.driver.snapshot() == before_nat
    assert service.runtime.filters.snapshot() == before_filter
    assert service.network_status()["addresses"] == []
    assert service.network_status()["links"] == []
    assert service.state()["dirty"]


def test_partial_network_failure_undoes_already_created_links(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    assert service.runtime is not None
    service.save(demo_config(), 0)
    network = service.runtime.network
    actual_apply = network.apply

    def fail_after_address_assignment(
        previous: NetworkConfiguration, target: NetworkConfiguration
    ) -> None:
        actual_apply(previous, target)
        raise FirewallError("DHCP bind conflict")

    with (
        patch.object(network, "apply", side_effect=fail_after_address_assignment),
        pytest.raises(FirewallError, match="DHCP bind conflict"),
    ):
        service.apply(1)
    assert service.state()["pending"] is None
    assert service.network_status()["links"] == []
    assert service.network_status()["addresses"] == []
    assert "DHCP bind conflict" in service.state()["runtime_error"]


def test_nat_rollback_failure_does_not_skip_other_subsystems(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    service.save(demo_config(), 0)
    service.apply(1)
    with (
        patch.object(service.driver, "restore", side_effect=FirewallError("NAT unavailable")),
        pytest.raises(FirewallError, match="NAT unavailable"),
    ):
        service.rollback()
    assert service.state()["pending"] is not None
    assert service.network_status()["links"] == []
    assert service.network_status()["addresses"] == []
    service.rollback()
    assert service.state()["pending"] is None


def test_restart_reconciles_confirmed_state_without_applying_new_draft(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    target = demo_config()
    service.save(target, 0)
    token = service.apply(1)["pending"]["token"]
    service.confirm(token)
    draft = target.model_copy(deep=True)
    draft.rules[0].name = "Unsaved-to-network change"
    service.save(draft, 1)
    service.restore_confirmed()
    assert service.store.read("applied")["rules"][0]["name"] == target.rules[0].name
    assert service.config().rules[0].name == draft.rules[0].name
    assert service.state()["dirty"]
    assert service.network_status()["dnsmasq"]["dns"]["running"]


def test_legacy_json_migration_preserves_rules_order_and_draft(tmp_path: Path) -> None:
    path = tmp_path / "old.sqlite3"
    initial = demo_config()
    old_applied = initial.model_dump(mode="json")
    old_applied.pop("network")
    old_applied.pop("filter_rules")
    for rule in old_applied["rules"]:
        rule.pop("in_interface_list")
        rule.pop("out_interface_list")
    old_draft = json.loads(json.dumps(old_applied))
    old_draft["rules"][0], old_draft["rules"][1] = old_draft["rules"][1], old_draft["rules"][0]
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE state (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO state VALUES (?,?)",
            [
                ("config", json.dumps(old_draft)),
                ("applied", json.dumps(old_applied)),
                ("revision", "5"),
                ("pending", "null"),
            ],
        )
    store = Store(path, initial)
    assert store.read("revision") == 5
    assert [item["id"] for item in store.read("config")["rules"]] == [
        item["id"] for item in old_draft["rules"]
    ]
    assert [item["id"] for item in store.read("applied")["rules"]] == [
        item["id"] for item in old_applied["rules"]
    ]
    assert len(store.read("config")["network"]["dhcp_servers"]) == 2
    assert store.read("config")["network"] == store.read("applied")["network"]


def test_deleting_referenced_managed_interface_is_rejected_before_save(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    target = demo_config()
    service.save(target, 0)
    orphaned = target.model_copy(deep=True)
    orphaned.network.virtual_interfaces = []
    with pytest.raises(Conflict, match="still referenced by IP address"):
        service.save(orphaned, 1)
    assert service.store.read("revision") == 1
    assert len(service.config().network.virtual_interfaces) == 1
    clean = target.model_copy(deep=True)
    clean.network.addresses = [
        item for item in clean.network.addresses if item.interface != "lo-mgmt"
    ]
    clean.network.virtual_interfaces = []
    assert service.save(clean, 1)["revision"] == 2


def test_dhcp_on_vlan_requires_its_managed_parent_to_be_enabled() -> None:
    target = demo_config().network.model_dump(mode="json")
    target["bridges"][0]["enabled"] = False
    target["dhcp_servers"][0]["enabled"] = False
    target["dns"]["listen_interfaces"] = ["vlan20"]
    with pytest.raises(ValueError, match="Enable the managed interface"):
        NetworkConfiguration.model_validate(target)
