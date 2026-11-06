"""Old static list names retain firewall semantics across upgrade and restore."""

import copy
import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.backup_archive import BackupPayload
from app.bootstrap import read_confirmed
from app.compiler import compiled_rules
from app.config_migrations import migrate_legacy_address_lists
from app.filtering import compiled_filters
from app.models import Configuration
from app.rsc import HEADER, ScriptError, export_rsc, import_rsc
from app.storage import Store
from app.system_lists import required_system_lists


def legacy() -> dict[str, Any]:
    return {
        "address_lists": [
            {
                "id": str(UUID(int=1)),
                "name": "geo_US",
                "addresses": ["8.8.8.8", "9.9.9.9"],
                "comment": "User-managed static allowlist",
            },
            {"id": str(UUID(int=2)), "name": "f2b_web", "addresses": ["10.0.0.0/8"]},
        ],
        "rules": [
            {
                "id": str(UUID(int=3)),
                "name": "Static NAT",
                "src_list": "geo_US",
                "dst_list": "f2b_web",
                "to_address": "10.0.0.10",
                "dst_ports": "443",
            }
        ],
        "filter_rules": [
            {
                "id": str(UUID(int=4)),
                "name": "Static input",
                "chain": "input",
                "src_list": "f2b_web",
                "action": "accept",
            },
            {
                "id": str(UUID(int=5)),
                "name": "Static forward",
                "src_list": "geo_US",
                "action": "drop",
            },
        ],
    }


def assert_semantics(config: Configuration) -> None:
    assert [item.name for item in config.address_lists] == ["legacy_geo_US", "legacy_f2b_web"]
    assert [item.id for item in config.address_lists] == [UUID(int=1), UUID(int=2)]
    assert [item.id for item in config.filter_rules] == [UUID(int=4), UUID(int=5)]
    nat = compiled_rules(config)
    filters = compiled_filters(config)
    assert len(nat) == 2 and len(filters) == 3
    assert "-s 8.8.8.8/32 -d 10.0.0.0/8" in nat[0]
    assert "-s 9.9.9.9/32 -d 10.0.0.0/8" in nat[1]
    assert f"nat-panel:{UUID(int=3)}" in nat[0]
    assert "-A OMR_INPUT -p tcp -s 10.0.0.0/8" in filters[0]
    assert f"openmikrorout:{UUID(int=4)}" in filters[0]
    assert all("--match-set" not in line for line in [*nat, *filters])
    assert required_system_lists(config) == {}


def test_legacy_names_migrate_once_without_mutating_input_or_rule_ids() -> None:
    raw = legacy()
    before = copy.deepcopy(raw)
    config = Configuration.model_validate(raw)
    assert raw == before
    assert_semantics(config)
    assert config.address_lists[0].comment == raw["address_lists"][0]["comment"]
    assert Configuration.model_validate(config.model_dump(mode="json")) == config
    assert import_rsc(export_rsc(config)) == config


def test_collision_suffixes_and_long_names_are_deterministic_and_bounded() -> None:
    long_name = "geo_" + "a" * 36
    collision = ("legacy_" + long_name)[:40]
    names = ["geo_US", "legacy_geo_US", "legacy_geo_US_2", long_name, collision]
    raw = {"address_lists": [{"name": name, "addresses": ["192.0.2.1"]} for name in names]}
    result = Configuration.model_validate(raw)
    result_names = [item.name for item in result.address_lists]
    assert result_names[0] == "legacy_geo_US_3"
    assert result_names[1:3] == names[1:3]
    assert result_names[3] == collision[:38] + "_2"
    assert len(set(result_names)) == len(names)
    assert all(len(name) <= 40 for name in result_names)
    assert migrate_legacy_address_lists(raw) == migrate_legacy_address_lists(copy.deepcopy(raw))


def test_duplicate_and_invalid_legacy_entries_are_not_repaired_or_deduplicated() -> None:
    duplicate = legacy()
    duplicate["address_lists"].append({"name": "geo_US", "addresses": ["1.1.1.1"]})
    migrated = migrate_legacy_address_lists(duplicate)
    assert isinstance(migrated, dict) and len(migrated["address_lists"]) == 3
    with pytest.raises(ValidationError, match="unique"):
        Configuration.model_validate(duplicate)
    for row in (
        {"name": "geo_" + "a" * 37, "addresses": ["1.1.1.1"]},
        {"name": "geo_x;command", "addresses": ["1.1.1.1"]},
        {"name": "geo_US", "addresses": ["not-an-ip"]},
        {"name": "f2b_web"},
        None,
    ):
        with pytest.raises(ValidationError):
            Configuration.model_validate({"address_lists": [row]})


@pytest.mark.parametrize("new_field", ["system_lists", "fail2ban"])
def test_new_schema_keeps_reserved_names_strict(new_field: str) -> None:
    raw = legacy()
    raw[new_field] = [] if new_field == "system_lists" else {"enabled": False}
    with pytest.raises(ValidationError, match="reserved"):
        Configuration.model_validate(raw)


def test_old_rsc_uses_same_migration_but_new_rsc_rejects_static_system_names() -> None:
    text = (
        HEADER + '\n/ip firewall address-list add name="geo_US" addresses=["8.8.8.8"]'
        '\n/ip firewall nat add name="Legacy NAT" src-list="geo_US" to-address="10.0.0.1"\n'
    )
    parsed = import_rsc(text)
    assert parsed.address_lists[0].name == "legacy_geo_US"
    assert parsed.rules[0].src_list == "legacy_geo_US"
    assert "-s 8.8.8.8/32" in compiled_rules(parsed)[0]
    assert "--match-set" not in compiled_rules(parsed)[0]
    with pytest.raises(ScriptError):
        import_rsc(text + "/security fail2ban set enabled=false\n")
    with pytest.raises(ScriptError):
        import_rsc(
            text + '/ip firewall system-list add name="geo_US" kind="country" country="US"\n'
        )


def test_old_backup_payload_uses_same_migration() -> None:
    payload = BackupPayload.model_validate(
        {
            "version": "0.5.1",
            "created_at": 1,
            "hostname": "old-router",
            "config": legacy(),
            "accounts": [],
            "keys": [],
        }
    )
    assert_semantics(payload.config)


def test_sqlite_startup_and_early_boot_preserve_legacy_firewall_semantics(tmp_path: Path) -> None:
    path = tmp_path / "linux.sqlite3"
    raw = legacy()
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        for key in ("config", "applied"):
            database.execute("INSERT INTO state VALUES (?, ?)", (key, json.dumps(raw)))
    original_bytes = path.read_bytes()
    assert_semantics(read_confirmed(tmp_path))
    assert path.read_bytes() == original_bytes, "Early bootstrap must not modify stored state"
    store = Store(path, Configuration())
    assert_semantics(Configuration.model_validate(store.read("config")))
    assert store.read("config") == store.read("applied")
    persisted = store.read("config")
    assert persisted["rules"][0]["id"] == raw["rules"][0]["id"]
    assert persisted["rules"][0]["src_list"] == "legacy_geo_US"
    restarted = Store(path, Configuration())
    assert restarted.read("applied") == persisted


def test_legacy_migration_respects_existing_whitespace_normalization() -> None:
    raw = legacy()
    raw["address_lists"][0]["name"] = " geo_US "
    raw["rules"][0]["src_list"] = " geo_US "
    assert_semantics(Configuration.model_validate(raw))
