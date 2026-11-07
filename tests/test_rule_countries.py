"""Independent country matches share GeoIP sets across NAT, Filter and config transfer."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.backup_archive import BackupPayload, decrypt_backup, encrypt_backup
from app.compiler import FirewallError, compiled_rules
from app.filtering import compiled_filters
from app.geoip import GeoIPService
from app.ipsets import DemoIPSetDriver
from app.models import Configuration
from app.rsc import HEADER, export_rsc, import_rsc
from app.system_list_runtime import SystemListRuntime
from app.system_lists import required_system_lists, resolved_system_lists
from app.version import VERSION


def country_config() -> Configuration:
    return Configuration.model_validate(
        {
            "address_lists": [{"name": "clients", "addresses": ["8.8.8.0/24", "9.9.9.0/24"]}],
            "rules": [
                {
                    "name": "US clients to AU service",
                    "src_list": "clients",
                    "src_country": "us",
                    "dst_country": "AU",
                    "dst_address": "1.1.1.1",
                    "dst_ports": "443",
                    "to_address": "192.168.1.20",
                    "f2b_profile": "web",
                    "f2b_match": "not_banned",
                }
            ],
            "filter_rules": [
                {
                    "name": "US to AU",
                    "src_address": "8.8.8.8",
                    "src_country": "US",
                    "dst_country": "au",
                    "action": "drop",
                    "f2b_profile": "ssh",
                    "f2b_match": "banned",
                }
            ],
        }
    )


def test_country_matches_are_intersections_without_expanding_country_ranges() -> None:
    configuration = country_config()
    assert configuration.rules[0].src_country == "US"
    assert configuration.filter_rules[0].dst_country == "AU"
    assert configuration.system_lists == []
    assert set(required_system_lists(configuration)) == {"geo_US", "geo_AU", "f2b_web", "f2b_ssh"}
    nat = compiled_rules(configuration)
    assert len(nat) == 2  # Only the explicit static source list expands.
    assert "-s 8.8.8.0/24" in nat[0] and "-s 9.9.9.0/24" in nat[1]
    for rule in nat:
        assert "-d 1.1.1.1/32" in rule
        assert "--match-set omr_geo_US src" in rule
        assert "--match-set omr_geo_AU dst" in rule
        assert "-j DNAT --to-destination 192.168.1.20" in rule
    filters = compiled_filters(configuration)
    assert len(filters) == 1
    assert "-s 8.8.8.8/32" in filters[0]
    assert "--match-set omr_geo_US src" in filters[0]
    assert "--match-set omr_geo_AU dst" in filters[0]


def test_same_country_as_address_list_matches_once_per_direction() -> None:
    configuration = Configuration.model_validate(
        {
            "filter_rules": [
                {
                    "name": "Country set alias",
                    "src_country": "US",
                    "dst_country": "US",
                    "src_list": "geo_US",
                    "dst_list": "geo_US",
                }
            ]
        }
    )
    line = compiled_filters(configuration)[0]
    assert line.count("--match-set omr_geo_US src") == 1
    assert line.count("--match-set omr_geo_US dst") == 1
    assert set(required_system_lists(configuration)) == {"geo_US"}


@pytest.mark.parametrize("code", ["ZZ", "QQ", "USA", "US;", "--", "1", "::", None])
@pytest.mark.parametrize("side", ["src_country", "dst_country"])
def test_country_codes_reject_unknown_or_unsafe_values(code: object, side: str) -> None:
    with pytest.raises(ValidationError):
        Configuration.model_validate({"filter_rules": [{"name": "Invalid", side: code}]})


def test_disabled_country_rules_do_not_require_database_or_kernel_sets(tmp_path: Path) -> None:
    configuration = country_config()
    for rule in [*configuration.rules, *configuration.filter_rules]:
        rule.enabled = False
    assert {"geo_US", "geo_AU"} <= set(resolved_system_lists(configuration))
    assert required_system_lists(configuration) == {}
    driver = DemoIPSetDriver()
    runtime = SystemListRuntime(GeoIPService(tmp_path), driver)
    runtime.prepare(configuration)
    assert driver.countries == {}
    configuration.rules[0].enabled = True
    with pytest.raises(FirewallError, match="Download"):
        runtime.prepare(configuration)


def test_country_fields_round_trip_rsc_and_encrypted_backup() -> None:
    configuration = country_config()
    script = export_rsc(configuration)
    assert 'src-country="US"' in script
    assert 'dst-country="AU"' in script
    assert 'f2b-profile="web"' in script
    assert 'f2b-match="banned"' in script
    assert import_rsc(script) == configuration
    payload = BackupPayload(
        version=VERSION,
        created_at=0,
        hostname="test-router",
        config=configuration,
        accounts=[],
        keys=[],
    )
    password = "test-only-country-backup-passphrase"
    assert decrypt_backup(encrypt_backup(payload, password), password).config == configuration


def test_legacy_configs_default_to_any_country_and_preserve_list_migration() -> None:
    legacy: dict[str, Any] = {
        "address_lists": [{"name": "geo_US", "addresses": ["192.168.1.1"]}],
        "filter_rules": [{"name": "Old static list", "src_list": "geo_US"}],
    }
    configuration = Configuration.model_validate(legacy)
    rule = configuration.filter_rules[0]
    assert rule.src_country == rule.dst_country == ""
    assert rule.src_list == "legacy_geo_US"
    assert "--match-set" not in compiled_filters(configuration)[0]
    assert legacy["filter_rules"][0]["src_list"] == "geo_US"
    script = HEADER + '\n/ip firewall filter add name="Legacy" action="drop"'
    imported = import_rsc(script)
    assert imported.filter_rules[0].src_country == imported.filter_rules[0].dst_country == ""


@pytest.mark.parametrize("collection", ["rules", "filter_rules"])
@pytest.mark.parametrize("match", ["banned", "not_banned"])
def test_fail2ban_condition_matches_source_set_without_changing_rule_action(
    collection: str, match: str, tmp_path: Path
) -> None:
    item = {"name": "Profile source condition", "f2b_profile": "web", "f2b_match": match}
    if collection == "rules":
        item["to_address"] = "192.168.1.20"
    else:
        item["action"] = "reject"
    configuration = Configuration.model_validate({collection: [item]})
    assert not configuration.fail2ban.enabled
    assert set(required_system_lists(configuration)) == {"f2b_web"}
    driver = DemoIPSetDriver()
    SystemListRuntime(GeoIPService(tmp_path), driver).prepare(configuration)
    assert "f2b_web" in driver.temporary
    line = (
        compiled_rules(configuration)[0]
        if collection == "rules"
        else compiled_filters(configuration)[0]
    )
    inversion = "! " if match == "not_banned" else ""
    assert f"-m set {inversion}--match-set omr_f2b_web src" in line
    assert "-j DNAT" in line if collection == "rules" else "-j REJECT" in line
    assert "DROP" not in line  # The condition must never silently change the selected action.


@pytest.mark.parametrize("profile", ["ghost", "Web", "web;shutdown", "../web", "web " * 6])
def test_fail2ban_profile_reference_is_validated(profile: str) -> None:
    with pytest.raises(ValidationError):
        Configuration.model_validate(
            {"filter_rules": [{"name": "Invalid", "f2b_profile": profile}]}
        )


def test_fail2ban_match_enum_and_deleted_profile_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Configuration.model_validate(
            {"filter_rules": [{"name": "Invalid", "f2b_profile": "web", "f2b_match": "ignore"}]}
        )
    configuration = country_config().model_dump(mode="json")
    configuration["fail2ban"]["profiles"] = []
    with pytest.raises(ValidationError, match="Unknown Fail2ban profile"):
        Configuration.model_validate(configuration)


def test_fail2ban_condition_and_source_list_deduplicate_identical_positive_match() -> None:
    configuration = Configuration.model_validate(
        {
            "filter_rules": [
                {
                    "name": "Banned",
                    "src_list": "f2b_web",
                    "f2b_profile": "web",
                    "f2b_match": "banned",
                    "action": "drop",
                }
            ]
        }
    )
    assert compiled_filters(configuration)[0].count("--match-set omr_f2b_web src") == 1
