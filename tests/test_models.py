from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models import AddressList, Configuration, NatRule


def rule(**changes: object) -> NatRule:
    return NatRule.model_validate({"name": "Test", "to_address": "192.168.1.10", **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"dst_ports": "0"},
        {"dst_ports": "65536"},
        {"dst_ports": "90-80"},
        {"dst_ports": "80;reboot"},
        {"dst_ports": "80,,443"},
        {"protocol": "icmp", "dst_ports": "80"},
        {"src_address": "::1"},
        {"src_address": "example.com"},
        {"src_address": "1.2.3.4\nCOMMIT"},
        {"in_interface": "eth0 -j ACCEPT"},
        {"in_interface": "$(reboot)"},
        {"in_interface": "eth0\nCOMMIT"},
        {"to_address": "1.2.3.0/24"},
        {"to_address": ""},
        {"chain": "srcnat"},
        {"out_interface": "eth0"},
        {"chain": "output", "in_interface": "eth0"},
        {"action": "redirect"},
        {"to_ports": "80,443"},
        {"src_address": "192.168.0.0/16", "src_list": "lan"},
        {"dst_ports": ",".join(str(i) for i in range(1, 17))},
        {"command": "reboot"},
        {"action": "DROP"},
    ],
)
def test_rejects_unsafe_or_incompatible_rules(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        rule(**changes)


def test_normalizes_networks_and_port_ranges() -> None:
    item = rule(src_address="192.168.1.50/24", dst_ports="80, 443,8000:8010")
    assert item.src_address == "192.168.1.0/24"
    assert item.dst_ports == "80,443,8000-8010"


def test_address_list_normalizes_and_deduplicates() -> None:
    item = AddressList(name="lan", addresses=["192.168.1.5/24", "192.168.1.0/24", "10.0.0.1"])
    assert item.addresses == ["192.168.1.0/24", "10.0.0.1/32"]


def test_rejects_unknown_list_even_on_disabled_rule() -> None:
    with pytest.raises(ValidationError, match="Unknown address list"):
        Configuration(rules=[rule(enabled=False, src_list="missing")])


def test_rejects_duplicate_names_and_identifiers() -> None:
    item = AddressList(name="lan", addresses=["10.0.0.0/8"])
    with pytest.raises(ValidationError, match="names must be unique"):
        Configuration(address_lists=[item, item.model_copy(update={"id": uuid4()})])
    item_rule = rule()
    with pytest.raises(ValidationError, match="identifiers must be unique"):
        Configuration(rules=[item_rule, item_rule])


def test_bounds_cartesian_list_expansion() -> None:
    addresses = [f"10.0.0.{i}" for i in range(1, 18)]
    with pytest.raises(ValidationError, match="256 address combinations"):
        Configuration(
            address_lists=[AddressList(name="many", addresses=addresses)],
            rules=[rule(src_list="many", dst_list="many")],
        )


@pytest.mark.parametrize("protocol", ["any", "tcp", "udp", "icmp", "gre", "esp", "ah"])
def test_all_supported_protocols(protocol: str) -> None:
    assert rule(protocol=protocol).protocol == protocol
