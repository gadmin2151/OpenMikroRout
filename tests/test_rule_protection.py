"""Rule-owned protection derives bounded service scopes and keeps one source of truth."""

from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.compiler import FirewallError
from app.fail2ban_models import F2BConfiguration
from app.fail2ban_rules import observation_limit_name, reply_match_tokens
from app.fail2ban_runtime import Fail2banService
from app.filtering import EMPTY_FILTER, DemoFilterDriver, filter_patch, filter_rollback, inspect
from app.ipsets import DemoIPSetDriver
from app.main import Settings, create_app
from app.models import Configuration
from app.rsc import export_rsc, import_rsc
from app.rule_protection import (
    concrete_ports,
    effective_fail2ban,
    managed_profiles,
    rule_profile_id,
)
from app.system_lists import required_system_lists, resolved_system_lists


def nat_rule(**values: object) -> dict[str, object]:
    return {
        "id": str(uuid4()),
        "name": "RDP",
        "chain": "dstnat",
        "action": "dst-nat",
        "protocol": "tcp",
        "dst_ports": "13389",
        "to_address": "192.168.1.20",
        "to_ports": "3389",
        "in_interface": "eth0",
        "protection": {"enabled": True},
        **values,
    }


def config(**rule_values: object) -> Configuration:
    return Configuration.model_validate({"rules": [nat_rule(**rule_values)]})


def test_inline_derived_from_nat_target_without_mutating_manual_profiles() -> None:
    source = config()
    before = source.model_dump(mode="json")
    effective = effective_fail2ban(source)
    assert effective.enabled and not source.fail2ban.enabled
    profile = effective.profiles[-1]
    assert profile.enabled and profile.service == "connections"
    assert profile.chain == "forward"
    assert profile.ports == [3389] and profile.destination == "192.168.1.20/32"
    assert profile.in_interface == "eth0"
    assert profile.rule_table == "nat" and profile.rule_id == source.rules[0].id
    assert profile.id == rule_profile_id(source.rules[0].id)
    assert all(not p.enabled for p in effective.profiles[:-1])
    assert source.model_dump(mode="json") == before
    assert source.fail2ban.profiles[0].enabled  # The manual toggle is still independent.
    assert set(required_system_lists(source)) == {f"f2b_{profile.id}"}
    assert f"f2b_{profile.id}" in resolved_system_lists(source)
    assert import_rsc(export_rsc(source)) == source


def test_rename_port_change_disable_and_removal_follow_parent_identity() -> None:
    source = config()
    original = managed_profiles(source)[0]
    source.rules[0].name = "Renamed"
    source.rules[0].to_ports = "3390"
    updated = managed_profiles(source)[0]
    assert updated.id == original.id and updated.name == "Renamed" and updated.ports == [3390]
    source.rules[0].enabled = False
    assert not effective_fail2ban(source).enabled
    assert not managed_profiles(source)[0].enabled
    assert required_system_lists(source) == {}
    source.rules.clear()
    assert managed_profiles(source) == []
    assert effective_fail2ban(source) == source.fail2ban


def test_manual_engine_toggle_never_disables_inline_policy_or_enables_default_web() -> None:
    source = config()
    assert [p.id for p in effective_fail2ban(source).profiles if p.enabled] == [
        rule_profile_id(source.rules[0].id)
    ]
    source.fail2ban.enabled = True
    assert {p.id for p in effective_fail2ban(source).profiles if p.enabled} == {
        "web",
        rule_profile_id(source.rules[0].id),
    }
    source.rules[0].protection.enabled = False
    assert effective_fail2ban(source) == source.fail2ban


@pytest.mark.parametrize(
    "changes",
    [
        {"protocol": "udp"},
        {"chain": "output", "in_interface": ""},
        {
            "chain": "srcnat",
            "action": "masquerade",
            "to_address": "",
            "in_interface": "",
            "to_ports": "",
        },
        {"action": "accept", "to_address": "", "to_ports": ""},
        {"dst_ports": "", "to_ports": ""},
        {"to_ports": "3000-3015"},
        {"protection": {"enabled": True, "event_source": "ssh"}},
        {"protection": {"enabled": True, "event_source": "web"}},
    ],
)
def test_unsupported_or_unbounded_inline_nat_is_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        config(**changes)


def test_default_rules_keep_previous_behavior_and_unsupported_disabled_policy_is_allowed() -> None:
    source = config(protocol="udp", protection={"enabled": False})
    assert not source.rules[0].protection.enabled
    assert managed_profiles(source) == []
    assert effective_fail2ban(source) == F2BConfiguration()
    assert required_system_lists(source) == {}
    old = Configuration.model_validate({"filter_rules": [{"name": "Old"}]})
    assert not old.filter_rules[0].protection.enabled


def test_redirect_can_use_router_login_events_with_port_inferred() -> None:
    source = config(
        action="redirect",
        to_address="",
        to_ports="8088",
        protection={
            "enabled": True,
            "event_source": "web",
            "max_retry": 7,
            "find_time": 60,
            "ban_time": 1200,
        },
    )
    profile = managed_profiles(source)[0]
    assert profile.chain == "input" and profile.ports == [8088]
    assert profile.destination == ""
    assert (profile.max_retry, profile.find_time, profile.ban_time) == (7, 60, 1200)


def test_filter_endpoint_lists_remain_bounded_and_country_is_a_destination_set() -> None:
    source = Configuration.model_validate(
        {
            "address_lists": [{"name": "servers", "addresses": ["10.0.0.1", "10.0.0.2"]}],
            "network": {
                "interface_lists": [
                    {"name": "WAN", "members": ["eth0", "eth1"]},
                    {"name": "LAN", "members": ["br0"]},
                ]
            },
            "filter_rules": [
                {
                    "name": "Servers",
                    "chain": "forward",
                    "dst_list": "servers",
                    "dst_country": "US",
                    "dst_ports": "80,443",
                    "in_interface_list": "WAN",
                    "out_interface_list": "LAN",
                    "protection": {"enabled": True},
                }
            ],
        }
    )
    profile = managed_profiles(source)[0]
    assert profile.scope is not None
    assert profile.scope.destinations == ["10.0.0.1/32", "10.0.0.2/32"]
    assert profile.scope.in_interfaces == ["eth0", "eth1"]
    assert profile.scope.out_interfaces == ["br0"]
    assert profile.scope.destination_sets == ["geo_US"]
    script = filter_patch(EMPTY_FILTER, source)
    assert script.count("--nflog-prefix") == 12
    limit_names = {
        line.split("--hashlimit-name ")[-1].split()[0]
        for line in script.splitlines()
        if "--hashlimit-name " in line
    }
    assert len(limit_names) == 1  # Every expanded selector shares the same profile budget.
    for phase in ("start", "reply", "attempt"):
        name = observation_limit_name(profile, phase)
        assert len(name) == 15 and name not in limit_names
        assert script.count(f"--hashlimit-name {name}") == 4
    assert script.count(f"--match-set omr_f2b_{profile.id} src") == 4
    assert "-o br0" in script and "--match-set omr_geo_US dst" in script
    assert "-i br0" in script and "--match-set omr_geo_US src" in script


def test_reply_scope_preserves_literal_interface_and_set_names() -> None:
    original = [
        "-p",
        "tcp",
        "-i",
        "src",
        "-o",
        "dst",
        "-d",
        "10.0.0.1/32",
        "-m",
        "multiport",
        "--dports",
        "443",
        "-m",
        "set",
        "--match-set",
        "src",
        "dst",
    ]
    assert reply_match_tokens(original) == [
        "-p",
        "tcp",
        "-o",
        "src",
        "-i",
        "dst",
        "-s",
        "10.0.0.1/32",
        "-m",
        "multiport",
        "--sports",
        "443",
        "-m",
        "set",
        "--match-set",
        "src",
        "src",
    ]


def test_managed_ownership_cannot_be_forged_in_editable_manual_configuration() -> None:
    generated = managed_profiles(config())[0]
    with pytest.raises(ValidationError, match="parent rule"):
        Configuration(fail2ban=F2BConfiguration(profiles=[generated]))
    source = config()
    source.fail2ban.profiles[0].id = rule_profile_id(source.rules[0].id)
    with pytest.raises(ValueError, match="conflicts"):
        managed_profiles(source)


def test_disabled_web_proxy_settings_do_not_block_tcp_rule_protection() -> None:
    for mode in ("external_proxy", "local_proxy"):
        source = Configuration.model_validate(
            {"rules": [nat_rule()], "fail2ban": {"access_mode": mode}}
        )
        effective = effective_fail2ban(source)
        assert effective.enabled and effective.access_mode == "direct"
        assert source.fail2ban.access_mode == mode and not source.fail2ban.enabled
        assert all(p.service != "web" for p in effective.profiles if p.enabled)


def test_proxy_requirements_are_not_bypassed_for_inline_web_authentication() -> None:
    for mode in ("external_proxy", "local_proxy"):
        with pytest.raises(ValidationError):
            Configuration.model_validate(
                {
                    "rules": [
                        nat_rule(
                            action="redirect",
                            to_address="",
                            to_ports="8088",
                            protection={"enabled": True, "event_source": "web"},
                        )
                    ],
                    "fail2ban": {"access_mode": mode},
                }
            )


@pytest.mark.parametrize("value", ["1-65535", "0", "65536", "9-8", "", "1-2-3"])
def test_port_expansion_never_creates_an_unbounded_profile(value: str) -> None:
    with pytest.raises(ValueError):
        concrete_ports(value)


def test_port_expansion_deduplicates_small_valid_ranges() -> None:
    assert concrete_ports("20-22,22,443") == [20, 21, 22, 443]


def test_ban_guard_precedes_attempt_log_and_foreign_accept_with_rollback() -> None:
    source = config()
    profile = managed_profiles(source)[0]
    driver = DemoFilterDriver(Configuration())
    driver._table.table = EMPTY_FILTER.replace("COMMIT", "-A FORWARD -j ACCEPT\nCOMMIT")
    before = driver.snapshot()
    payload = filter_patch(before, source)
    assert payload.index(f"openmikrorout:f2b:{profile.id}") < payload.index("--nflog-prefix")
    assert "--nflog-group 5088" in payload
    assert "--ctstate NEW --ctdir ORIGINAL -m tcp --syn" in payload
    assert "--ctstate ESTABLISHED --ctdir ORIGINAL --ctstatus ASSURED" in payload
    assert "--hashlimit-upto 128/second" in payload
    assert "--nflog-size 0" in payload
    assert "CONNMARK" not in payload
    assert "--dports 3389" in payload
    assert "--dports 13389" not in payload
    driver.restore(payload)
    forwards = [line for line in driver.snapshot().splitlines() if line.startswith("-A FORWARD ")]
    assert "f2b-anchor" in forwards[0]
    driver.restore(filter_rollback(driver.snapshot(), before))
    assert "-A FORWARD -j ACCEPT" in driver.snapshot()
    assert "f2b-anchor" not in driver.snapshot()


def test_private_connection_filter_uses_only_generated_id_and_local_log(tmp_path: Path) -> None:
    service = Fail2banService(tmp_path, True, DemoIPSetDriver())
    try:
        source = config()
        profile = managed_profiles(source)[0]
        service.initialize_files(effective_fail2ban(source))
        log = service.directory / "attempts.log"
        log.write_text("preserve previous events\n")
        service.initialize_files(effective_fail2ban(source))
        assert log.read_text() == "preserve previous events\n"
        assert log.stat().st_mode & 0o777 == 0o600
        jail = (service.config_dir / "jail.conf").read_text()
        assert f"filter = omr-connections-{profile.id}" in jail
        assert "backend = systemd" not in jail
        regex = (service.config_dir / "filter.d" / f"omr-connections-{profile.id}.conf").read_text()
        assert f"connection_attempt profile={profile.id} src=<ADDR>" in regex
    finally:
        service.journal.close()


def test_api_exposes_generated_draft_profiles_and_marks_protection_changes(tmp_path: Path) -> None:
    app = create_app(Settings(mode="demo", data_dir=tmp_path, auth_enabled=False))
    with TestClient(app) as client:
        state = client.get("/api/state").json()
        state["config"]["rules"].append(nat_rule())
        response = client.put(
            "/api/config",
            headers={"X-NAT-Request": "1"},
            json={"revision": state["revision"], "config": state["config"]},
        )
        assert response.status_code == 200, response.text
        assert client.get("/api/state").json()["security_dirty"]
        result = client.get("/api/security/fail2ban").json()
        assert not result["manual_enabled"] and result["inline_enabled_count"] == 1
        generated = [p for p in result["draft_profiles"] if p["rule_id"]]
        assert len(generated) == 1 and generated[0]["ports"] == [3389]
        assert generated[0]["enabled"]


def test_dnat_local_endpoint_is_protected_on_input_as_well_as_forward() -> None:
    source = config(to_address="127.0.0.1", to_ports="8088")
    profile = managed_profiles(source)[0]
    assert profile.scope is not None and profile.scope.chains == ["input", "forward"]
    payload = filter_patch(EMPTY_FILTER, source)
    for chain in ("OMR_F2B", "OMR_F2B_FORWARD"):
        rows = [line for line in payload.splitlines() if line.startswith(f"-A {chain} ")]
        guarded = [line for line in rows if f"openmikrorout:f2b:{profile.id}" in line]
        attempts = [
            line for line in rows if "--nflog-prefix" in line and "--ctdir ORIGINAL" in line
        ]
        assert len(guarded) == 1 and len(attempts) == 2
        for line in [*guarded, *attempts]:
            assert "-d 127.0.0.1/32" in line and "--dports 8088" in line
    assert "-I INPUT 1" in payload and "-I FORWARD 1" in payload
    assert "-I OUTPUT 1" in payload
    replies = [line for line in payload.splitlines() if "--ctdir REPLY" in line]
    assert len(replies) == 2
    for line in replies:
        assert "-s 127.0.0.1/32" in line and "--sports 8088" in line
        assert "--tcp-flags SYN,RST,ACK SYN,ACK" in line


def test_runtime_verifies_both_endpoint_hooks_and_collector_rules(tmp_path: Path) -> None:
    source = config(to_address="127.0.0.1", to_ports="8088")
    service = Fail2banService(tmp_path, True, DemoIPSetDriver())
    service.settings = effective_fail2ban(source)
    snapshot = DemoFilterDriver(source).snapshot()
    try:
        with patch("app.filtering.LinuxFilterDriver") as driver:
            driver.return_value.snapshot.return_value = snapshot
            assert service._enforced()
        for chain, missing_marker in (
            ("OMR_F2B", "f2b-start:"),
            ("OMR_F2B", "f2b-attempt:"),
            ("OMR_F2B", "f2b:"),
            ("OMR_F2B_FORWARD", "f2b-reply:"),
            ("OMR_F2B_OUTPUT", "f2b-reply:"),
        ):
            missing = (
                "\n".join(
                    row
                    for row in snapshot.splitlines()
                    if not (row.startswith(f"-A {chain} ") and missing_marker in row)
                )
                + "\n"
            )
            with patch("app.filtering.LinuxFilterDriver") as driver:
                driver.return_value.snapshot.return_value = missing
                assert not service._enforced()
    finally:
        service.journal.close()


def test_inline_apply_requires_proof_and_rollback_restores_collector_and_rules(
    tmp_path: Path,
) -> None:
    password = "integration-protection-password"
    headers = {"X-NAT-Request": "1"}
    app = create_app(Settings(mode="demo", data_dir=tmp_path, password=password, auth_enabled=True))
    with TestClient(app) as client:
        assert (
            client.post(
                "/api/login", headers=headers, json={"username": "admin", "password": password}
            ).status_code
            == 200
        )
        state = client.get("/api/state").json()
        state["config"]["rules"].append(nat_rule())
        identifier = state["config"]["rules"][-1]["id"]
        saved = client.put(
            "/api/config", headers=headers, json={"revision": 0, "config": state["config"]}
        )
        assert saved.status_code == 200, saved.text
        assert client.post("/api/apply", headers=headers, json={"revision": 1}).status_code == 409
        assert not client.get("/api/security/fail2ban").json()["connection_collector"]["enabled"]
        before = app.state.service.runtime.filters.snapshot()
        response = client.post(
            "/api/apply", headers=headers, json={"revision": 1, "proof": {"password": password}}
        )
        assert response.status_code == 200, response.text
        status = client.get("/api/security/fail2ban").json()
        assert status["connection_collector"]["enabled"]
        assert status["connection_collector"]["healthy"]
        assert any(profile["rule_id"] == identifier for profile in status["profiles"])
        assert "--nflog-group 5088" in app.state.service.runtime.filters.snapshot()
        assert client.post("/api/rollback", headers=headers).status_code == 200
        assert inspect(app.state.service.runtime.filters.snapshot()) == inspect(before)
        status = client.get("/api/security/fail2ban").json()
        assert not status["connection_collector"]["enabled"]
        assert all(profile["rule_id"] is None for profile in status["profiles"])


def test_collector_readiness_and_failed_apply_preserve_previous_runtime(tmp_path: Path) -> None:
    app = create_app(Settings(mode="demo", data_dir=tmp_path, auth_enabled=False))
    with TestClient(app):
        service = app.state.service
        attempts = app.state.security_services.attempts
        before = service.runtime.filters.snapshot()
        service.save(config(), 0)
        with (
            patch.object(attempts, "check", side_effect=FirewallError("Private group in use")),
            pytest.raises(FirewallError, match="Private group in use"),
        ):
            service.apply(1)
        assert service.state()["pending"] is None
        assert inspect(service.runtime.filters.snapshot()) == inspect(before)
        assert not attempts.status()["enabled"]
        # Binding succeeds, but a later subsystem fails: the durable snapshot releases it again.
        with (
            patch.object(
                service.runtime.network, "apply", side_effect=FirewallError("Address busy")
            ),
            pytest.raises(FirewallError, match="Address busy"),
        ):
            service.apply(1)
        assert not attempts.status()["enabled"]
        assert service.state()["pending"] is None
        assert inspect(service.runtime.filters.snapshot()) == inspect(before)


@pytest.mark.parametrize("change", ["port", "destination", "disable", "delete"])
def test_endpoint_changes_and_parent_removal_require_security_proof(
    tmp_path: Path, change: str
) -> None:
    app = create_app(Settings(mode="demo", data_dir=tmp_path, auth_enabled=False))
    with TestClient(app):
        service = app.state.service
        source = config()
        service.save(source, 0)
        service.confirm(service.apply(1)["pending"]["token"])
        assert not service.state()["security_dirty"]
        if change == "port":
            source.rules[0].to_ports = "3390"
        elif change == "destination":
            source.rules[0].to_address = "192.168.1.21"
        elif change == "disable":
            source.rules[0].enabled = False
        else:
            source.rules.clear()
        service.save(source, 1)
        assert service.state()["security_dirty"]
