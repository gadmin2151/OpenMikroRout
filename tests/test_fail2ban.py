"""Fail2ban contracts: safe event sources, durable timeouts and scoped owned rules."""

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.compiler import FirewallError
from app.fail2ban_action import process_event
from app.fail2ban_events import AuthenticationJournal, BanStore
from app.fail2ban_models import F2BConfiguration, F2BProfile, client_ipv4
from app.fail2ban_rules import f2b_rules
from app.fail2ban_runtime import Fail2banService, _safe_path
from app.filtering import EMPTY_FILTER, DemoFilterDriver, filter_patch, filter_rollback
from app.ipsets import DemoIPSetDriver
from app.models import Configuration


def settings() -> F2BConfiguration:
    return F2BConfiguration(enabled=True)


def test_model_defaults_no_network_protection_and_strict_fields() -> None:
    assert not F2BConfiguration().enabled
    assert F2BConfiguration().profiles[0].max_retry == 5
    assert F2BConfiguration().profiles[0].ban_time == 900
    for raw in (
        {"id": "web;id", "name": "Unsafe"},
        {"id": "web", "name": "Unsafe", "ports": [0]},
        {"id": "web", "name": "Unsafe", "ban_time": -1},
        {"id": "web", "name": "Unsafe", "include_countries": ["ZZ"]},
        {"id": "web", "name": "Unsafe", "include_countries": ["MD"], "exclude_countries": ["MD"]},
    ):
        with pytest.raises(ValidationError):
            F2BProfile.model_validate(raw)
    with pytest.raises(ValidationError):
        F2BConfiguration(enabled=True, access_mode="external_proxy")
    with pytest.raises(ValidationError):
        F2BConfiguration(enabled=True, access_mode="local_proxy")
    with pytest.raises(ValidationError):
        F2BConfiguration(trusted_proxies=["0.0.0.0/0"])


def test_socket_peer_is_authoritative_and_forwarded_is_not_trusted_by_default() -> None:
    assert client_ipv4(settings(), "198.51.100.7", "8.8.8.8") == "198.51.100.7"
    assert client_ipv4(settings(), "127.0.0.1", "8.8.8.8") is None
    assert client_ipv4(settings(), "::1") is None
    assert client_ipv4(settings(), "198.51.100.1\nspoof") is None
    proxy = F2BConfiguration(enabled=True, access_mode="local_proxy", trusted_proxies=["127.0.0.1"])
    assert client_ipv4(proxy, "127.0.0.1", "8.8.8.8") == "8.8.8.8"
    assert client_ipv4(proxy, "198.51.100.1", "8.8.8.8") is None
    assert client_ipv4(proxy, "127.0.0.1", "8.8.8.8, 9.9.9.9") is None


def test_journal_contains_only_confirmed_failure_address_and_rotates_privately(
    tmp_path: Path,
) -> None:
    journal = AuthenticationJournal(tmp_path)
    try:
        assert not journal.failure(F2BConfiguration(), "8.8.8.8")
        assert not journal.failure(settings(), "127.0.0.1")
        assert not journal.failure(settings(), "8.8.8.8\nreason=credentials")
        assert journal.failure(settings(), "8.8.8.8", "spoofed")
        lines = journal.path.read_text().splitlines()
        assert len(lines) == 1
        assert lines[0].endswith("openmikrorout auth_failure src=8.8.8.8 reason=credentials")
        assert "spoofed" not in lines[0]
        journal.handler.maxBytes = 1
        journal.failure(settings(), "9.9.9.9")
        assert journal.path.with_name("auth.log.1").exists()
        assert journal.path.stat().st_mode & 0o777 == 0o600
    finally:
        journal.close()


def test_duplicate_recovery_and_expiration_do_not_extend_bans(tmp_path: Path) -> None:
    driver = DemoIPSetDriver()
    store = BanStore(tmp_path, driver)
    profile = settings().profiles[0]
    started = time.time()
    with patch("app.fail2ban_events.time.time", return_value=started):
        assert store.ban(profile, "8.8.8.8", started, 100)
    with patch("app.fail2ban_events.time.time", return_value=started + 40):
        assert store.ban(profile, "8.8.8.8", started, 100)
        page = store.page()
        assert page["items"][0]["remaining_seconds"] == 60
        assert page["items"][0]["expires_at"] == started + 100
        restored = BanStore(tmp_path, driver)
        restored.restore(settings(), lambda _: "US")
        assert restored.page()["items"][0]["remaining_seconds"] == 60
    with patch("app.fail2ban_events.time.time", return_value=started + 101):
        assert not store.ban(profile, "8.8.8.8", started, 100)
        assert store.page()["total"] == 0


def test_unban_tombstone_and_profiles_are_independent(tmp_path: Path) -> None:
    driver = DemoIPSetDriver()
    store = BanStore(tmp_path, driver)
    web = settings().profiles[0]
    ssh = F2BProfile(id="ssh", name="SSH", enabled=True, service="ssh", ports=[22])
    started = time.time()
    store.ban(web, "8.8.8.8", started, 300)
    store.ban(ssh, "8.8.8.8", started, 300)
    assert store.unban("web", "8.8.8.8", started)
    assert not store.ban(web, "8.8.8.8", started, 300)
    assert store.page()["total"] == 1
    assert store.page()["items"][0]["profile"] == "ssh"
    assert store.ban(web, "8.8.8.8", started + 1, 300)
    assert not store.unban("web", "8.8.8.8", started)
    assert store.page()["total"] == 2


def test_exceptions_country_scope_and_paging(tmp_path: Path) -> None:
    driver = DemoIPSetDriver()
    store = BanStore(tmp_path, driver)
    profile = F2BProfile(
        id="web",
        name="Web",
        enabled=True,
        ignore_addresses=["10.0.0.0/8"],
        include_countries=["MD"],
        exclude_countries=["US"],
    )
    started = time.time()
    assert not store.ban(profile, "127.0.0.1", started, 50, "MD")
    assert not store.ban(profile, "10.0.0.2", started, 50, "MD")
    assert not store.ban(profile, "8.8.8.8", started, 50, "US")
    assert not store.ban(profile, "1.1.1.1", started, 50, "")
    assert store.ban(profile, "8.8.8.8", started, 50, "MD")
    assert store.ban(profile, "9.9.9.9", started, 50, "MD")
    assert store.page(query="8.8", limit=1)["total"] == 1
    assert store.page(limit=1, offset=1)["items"][0]["address"] == "9.9.9.9"
    driver.delete_temporary("f2b_web", "8.8.8.8")
    assert not store.page(query="8.8")["items"][0]["kernel_present"]


def test_scoped_f2b_hooks_precede_foreign_accept_and_rollback_preserves_foreign() -> None:
    config = Configuration(fail2ban=settings())
    config.fail2ban.profiles[0].ports = [8088, 443]
    config.fail2ban.profiles[0].in_interface = "eth0"
    config.fail2ban.profiles[0].destination = "10.0.0.1/32"
    driver = DemoFilterDriver(Configuration())
    driver._table.table = EMPTY_FILTER.replace("COMMIT", "-A INPUT -j ACCEPT\nCOMMIT")
    before = driver.snapshot()
    payload = filter_patch(before, config)
    assert "-I INPUT 1" in payload
    assert "-I FORWARD 1" not in payload
    rule = f2b_rules(config.fail2ban)[0]
    assert "-i eth0 -d 10.0.0.1/32" in rule
    assert "--dports 8088,443" in rule and "--match-set omr_f2b_web src" in rule
    driver.restore(payload)
    input_rules = [line for line in driver.snapshot().splitlines() if line.startswith("-A INPUT ")]
    assert "f2b-anchor" in input_rules[0]
    assert input_rules[1] == "-A INPUT -j ACCEPT"
    driver.restore(filter_patch(driver.snapshot(), config))
    assert driver.snapshot().count("f2b-anchor") == 1
    driver.restore(filter_rollback(driver.snapshot(), before))
    assert "f2b-anchor" not in driver.snapshot()
    assert "-A INPUT -j ACCEPT" in driver.snapshot()


def test_refuse_foreign_references_to_f2b_chain() -> None:
    for line in ("-A OMR_F2B -j ACCEPT", "-A INPUT -j OMR_F2B"):
        with pytest.raises(FirewallError, match="unmanaged"):
            filter_patch(EMPTY_FILTER.replace("COMMIT", f"{line}\nCOMMIT"), Configuration())


def test_private_config_has_no_user_commands_and_profile_limits(tmp_path: Path) -> None:
    service = Fail2banService(tmp_path, True, DemoIPSetDriver())
    try:
        service.initialize_files(settings())
        jail = (service.config_dir / "jail.conf").read_text()
        assert "maxretry = 5" in jail and "bantime = 900" in jail
        assert "omr.py[python=" in jail and "backend = polling" in jail
        assert "[sshd]" not in jail and "[omr-ssh]" not in jail
        assert (service.config_dir / "jail.conf").stat().st_mode & 0o777 == 0o600
        service.apply(F2BConfiguration(), settings())
        assert service.status()["demo"] and not service.status()["effective"]
        assert json.loads((service.directory / "settings.json").read_text())["enabled"]
    finally:
        service.journal.close()


def test_action_bridge_rejects_untyped_or_injected_payloads_before_execution(
    tmp_path: Path,
) -> None:
    for event in ("[]", '{"operation":"shell"}', "x" * 4097):
        with pytest.raises(ValueError):
            process_event(tmp_path, "web", event)
    with pytest.raises(ValueError):
        process_event(tmp_path, "web;whoami", "{}")


def test_restart_rollback_reconciles_persisted_pending_engine_settings(tmp_path: Path) -> None:
    service = Fail2banService(tmp_path, False, DemoIPSetDriver())
    try:
        # Startup first restores the confirmed model in memory; disk may still contain a
        # pending enabled target. Equality of Python models cannot skip native reload.
        service.initialize_files(settings())
        service.restore(F2BConfiguration())
        with patch.object(service, "_client", return_value="Jail list:") as client:
            service.rollback({"settings": F2BConfiguration().model_dump(mode="json")})
        assert any(call.args[0] == ["reload"] for call in client.call_args_list)
        assert not json.loads((service.directory / "settings.json").read_text())["enabled"]
    finally:
        service.journal.close()


def test_generated_action_preserves_venv_interpreter_symlink(tmp_path: Path) -> None:
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to("/usr/bin/python3")
    assert _safe_path(interpreter) == str(interpreter)
    service = Fail2banService(tmp_path / "data", True, DemoIPSetDriver())
    try:
        with patch("app.fail2ban_runtime.sys.executable", str(interpreter)):
            service.initialize_files(settings())
        assert f'python="{interpreter}"' in (service.config_dir / "jail.conf").read_text()
    finally:
        service.journal.close()


def test_unban_disabled_profile_retains_no_resurrection_tombstone(tmp_path: Path) -> None:
    driver = DemoIPSetDriver()
    service = Fail2banService(tmp_path, False, driver)
    try:
        profile = settings().profiles[0]
        started = time.time()
        service.bans.ban(profile, "8.8.8.8", started, 300)
        with patch.object(service, "_client", return_value="Jail list:") as client:
            service.unban("web", "8.8.8.8")
        assert client.call_count == 1 and client.call_args.args[0] == ["status"]
        assert service.bans.page()["total"] == 0
        assert not service.bans.ban(profile, "8.8.8.8", started, 300)
    finally:
        service.journal.close()
