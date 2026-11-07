"""Negation is an explicit bounded predicate, including whole-list complements."""

import ipaddress
import shlex
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.backup_archive import BackupPayload, decrypt_backup, encrypt_backup
from app.compiler import compiled_rules, expanded_matches, match_tokens
from app.fail2ban_models import RuleProtection
from app.fail2ban_rules import reply_match_tokens, service_match_tokens
from app.filtering import EMPTY_FILTER, filter_patch
from app.main import Settings, create_app
from app.match_expansion import address_list_matches
from app.models import AddressList, Configuration, FilterRule, NatRule
from app.rsc import export_rsc, import_rsc
from app.rule_protection import managed_profiles
from app.version import VERSION


def test_old_configuration_keeps_positive_predicates_and_rsc_roundtrips() -> None:
    old = Configuration.model_validate(
        {"filter_rules": [{"name": "Old", "src_address": "10.0.0.1"}]}
    )
    assert old.filter_rules[0].negate == []
    before = filter_patch(EMPTY_FILTER, old)
    old.filter_rules[0].negate = ["src_address"]
    inverted = filter_patch(EMPTY_FILTER, old)
    assert "-s 10.0.0.1/32" in before and "! -s 10.0.0.1/32" not in before
    assert "! -s 10.0.0.1/32" in inverted
    assert import_rsc(export_rsc(old)) == old
    assert Configuration.model_validate_json(old.model_dump_json()) == old


def test_encrypted_backup_keeps_negation_on_restore() -> None:
    rule = FilterRule(name="Except trusted", src_address="192.0.2.0/24", negate=["src_address"])
    payload = BackupPayload(
        version=VERSION,
        created_at=0,
        hostname="test-router",
        config=Configuration(filter_rules=[rule]),
        accounts=[],
        keys=[],
    )
    password = "test-only-backup-passphrase"
    restored = decrypt_backup(encrypt_backup(payload, password), password)
    assert restored.config == payload.config
    assert "! -s 192.0.2.0/24" in filter_patch(EMPTY_FILTER, restored.config)


@pytest.mark.parametrize(
    "values",
    [
        {"negate": ["src_address"]},
        {"protocol": "any", "negate": ["protocol"]},
        {"protocol": "tcp", "dst_ports": "80", "negate": ["protocol"]},
        {"negate": ["to_address"]},
        {"negate": ["in_interface_list"]},
        {"src_address": "!192.0.2.1"},
        {"negate": ["src_address; COMMIT"]},
    ],
)
def test_rejects_empty_unknown_or_incompatible_negation(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        FilterRule.model_validate({"name": "Unsafe", **values})


def test_negated_protocol_cannot_supply_nat_translation_port() -> None:
    with pytest.raises(ValidationError, match="positive TCP"):
        NatRule(name="Bad translation", to_address="10.0.0.1", to_ports="80", negate=["protocol"])


def test_native_selector_tokens_and_unique_flags() -> None:
    rule = FilterRule(
        name="All except",
        protocol="udp",
        src_address="10.0.0.1",
        dst_address="192.0.2.0/24",
        src_ports="80,443",
        dst_ports="1000-2000",
        in_interface="eth0",
        out_interface="br0",
        connection_states=["ESTABLISHED", "RELATED"],
        negate=[
            "src_address",
            "src_address",
            "dst_address",
            "src_ports",
            "dst_ports",
            "in_interface",
            "out_interface",
            "connection_states",
        ],
    )
    assert rule.negate.count("src_address") == 1
    tokens = match_tokens(rule, rule.src_address, rule.dst_address, "eth0", "br0")
    text = " ".join(tokens)
    for expected in (
        "! -s 10.0.0.1/32",
        "! -d 192.0.2.0/24",
        "! -i eth0",
        "! -o br0",
        "-m multiport ! --sports 80,443",
        "-m multiport ! --dports 1000:2000",
        "-m conntrack ! --ctstate ESTABLISHED,RELATED",
    ):
        assert expected in text
    assert "! -p icmp" in " ".join(
        match_tokens(
            FilterRule(name="Not ICMP", protocol="icmp", negate=["protocol"]), "", "", "", ""
        )
    )


def test_system_list_and_country_negation_are_native_set_predicates() -> None:
    rule = FilterRule(
        name="Excluded countries",
        src_list="f2b_web",
        src_country="US",
        dst_country="AU",
        negate=["src_list", "src_country", "dst_country"],
    )
    text = filter_patch(EMPTY_FILTER, Configuration(filter_rules=[rule]))
    assert "-m set ! --match-set omr_f2b_web src" in text
    assert "-m set ! --match-set omr_geo_US src" in text
    assert "-m set ! --match-set omr_geo_AU dst" in text


def test_list_complement_excludes_the_union_including_overlap_and_cidr() -> None:
    excluded = ["10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/16", "10.0.0.0/8"]
    values = address_list_matches(excluded, negate=True)
    networks = [ipaddress.IPv4Network(value) for value in values]
    for address in ("10.0.0.0", "10.255.255.255", "192.168.0.1", "192.168.255.255"):
        assert not any(ipaddress.IPv4Address(address) in net for net in networks)
    for address in ("0.0.0.0", "9.255.255.255", "11.0.0.0", "192.169.0.0", "255.255.255.255"):
        assert sum(ipaddress.IPv4Address(address) in net for net in networks) == 1
    assert sum(net.num_addresses for net in networks) == (1 << 32) - (1 << 24) - (1 << 16)
    assert address_list_matches(["0.0.0.0/0"], negate=True) == []
    assert address_list_matches([], negate=True) == ["0.0.0.0/0"]


def test_nat_and_filter_expand_complement_once_without_double_negation() -> None:
    rule = NatRule(
        name="Except internal",
        chain="output",
        to_address="127.0.0.1",
        src_list="internal",
        negate=["src_list"],
    )
    config = Configuration(
        address_lists=[AddressList(name="internal", addresses=["0.0.0.0/1"])], rules=[rule]
    )
    assert list(expanded_matches(config, rule)) == [("128.0.0.0/1", "", "", "")]
    text = "\n".join(compiled_rules(config))
    assert "-s 128.0.0.0/1" in text and "! -s" not in text
    config.address_lists[0].addresses = ["0.0.0.0/0"]
    assert compiled_rules(config) == []


def test_expansion_limits_use_complement_size_and_total_real_emitted_rules() -> None:
    excluded = AddressList(name="one", addresses=["10.0.0.1"])
    many = AddressList(name="nine", addresses=[f"192.0.2.{i}" for i in range(1, 10)])
    with pytest.raises(ValidationError, match="256 address combinations"):
        Configuration(
            address_lists=[excluded, many],
            filter_rules=[
                FilterRule(name="Too many", src_list="one", dst_list="nine", negate=["src_list"])
            ],
        )
    with pytest.raises(ValueError, match="256 IPv4 networks"):
        address_list_matches([f"10.{i}.0.1/32" for i in range(129)], negate=True)
    with pytest.raises(ValidationError, match="4096 iptables rules"):
        Configuration(
            address_lists=[excluded],
            filter_rules=[
                FilterRule(name=f"Rule {i}", src_list="one", negate=["src_list"])
                for i in range(129)
            ],
        )


def test_inline_protection_observation_and_existing_bans_exclude_source_networks() -> None:
    rule = FilterRule(
        name="Protected except trusted",
        chain="input",
        dst_ports="22",
        src_list="trusted",
        negate=["src_list"],
        protection=RuleProtection(enabled=True),
    )
    config = Configuration(
        address_lists=[AddressList(name="trusted", addresses=["0.0.0.0/1"])], filter_rules=[rule]
    )
    profile = managed_profiles(config)[0]
    assert profile.scope is not None and profile.scope.sources == ["128.0.0.0/1"]
    assert profile.ignore_addresses == ["0.0.0.0/1"]
    matches = list(service_match_tokens(profile))
    assert len(matches) == 1 and matches[0][:4] == ["-p", "tcp", "-s", "128.0.0.0/1"]
    assert "-d 128.0.0.0/1" in " ".join(reply_match_tokens(matches[0]))
    payload = filter_patch(EMPTY_FILTER, config)
    relevant = [line for line in payload.splitlines() if "f2b:" in line or "--nflog-prefix" in line]
    assert relevant and all("128.0.0.0/1" in line for line in relevant)


def test_dynamic_source_exclusion_uses_set_for_connections_and_rejects_log_sources() -> None:
    rule = FilterRule(
        name="Dynamic",
        chain="input",
        dst_ports="22",
        src_list="f2b_web",
        negate=["src_list"],
        protection=RuleProtection(enabled=True),
    )
    profile = managed_profiles(Configuration(filter_rules=[rule]))[0]
    assert "-m set ! --match-set omr_f2b_web src" in " ".join(next(service_match_tokens(profile)))
    for source in ("web", "ssh"):
        with pytest.raises(ValidationError, match="connection-based"):
            Configuration(
                filter_rules=[
                    rule.model_copy(
                        update={
                            "protection": rule.protection.model_copy(
                                update={"event_source": source}
                            )
                        }
                    )
                ]
            )


def test_unrepresentable_automatic_protection_is_rejected_not_silently_broadened() -> None:
    with pytest.raises(ValidationError, match="negation only for source"):
        Configuration(
            filter_rules=[
                FilterRule(
                    name="Bad auto",
                    chain="input",
                    dst_ports="22",
                    dst_address="192.0.2.1",
                    negate=["dst_address"],
                    protection=RuleProtection(enabled=True),
                )
            ]
        )
    rule = FilterRule(
        name="Nothing",
        src_address="0.0.0.0/0",
        negate=["src_address"],
        dst_ports="22",
        protection=RuleProtection(enabled=True),
    )
    assert not managed_profiles(Configuration(filter_rules=[rule]))[0].enabled


def test_api_saves_typed_negation_and_preview_uses_it(tmp_path: Path) -> None:
    with TestClient(
        create_app(Settings(mode="demo", data_dir=tmp_path, auth_enabled=False))
    ) as client:
        state = client.get("/api/state").json()
        rule = FilterRule(
            name="All except admin",
            chain="input",
            action="drop",
            src_address="192.0.2.1",
            negate=["src_address"],
        )
        state["config"]["filter_rules"].append(rule.model_dump(mode="json"))
        response = client.put(
            "/api/config",
            headers={"X-NAT-Request": "1"},
            json={"revision": state["revision"], "config": state["config"]},
        )
        assert response.status_code == 200, response.text
        saved = response.json()["config"]["filter_rules"][-1]
        assert saved["negate"] == ["src_address"]
        preview = client.post("/api/preview", headers={"X-NAT-Request": "1"})
        assert preview.status_code == 200, preview.text
        assert any(
            tokens[index - 1 : index + 2] == ["!", "-s", "192.0.2.1/32"]
            for line in preview.json()["router"]["filter_script"].splitlines()
            if str(rule.id) in line
            for tokens in [shlex.split(line)]
            for index in [tokens.index("-s")]
        )
