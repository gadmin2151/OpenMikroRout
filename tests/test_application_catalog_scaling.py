"""Large catalogs retain pinned mappings, licensed observation, isolation and bounds."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.application_catalog import ApplicationCatalog, CatalogBundle
from app.application_models import ApplicationRule
from app.application_policy import resolve_policy
from app.models import Configuration


def capabilities(profile: str = "not-for-profit") -> dict[str, Any]:
    return {
        "available": True,
        "observe": True,
        "enforce": True,
        "allow_over_port_deny": True,
        "license_profile": profile,
        "engine": {
            "name": "ndpi",
            "version": "6.0.0",
            "profile": profile,
            "restricted_components_enabled": profile != "lgpl-only",
        },
        "protocols": [
            {"id": 1, "name": "HTTP"},
            {"id": 2, "name": "TLS"},
            {"id": 3, "name": "POP3"},
        ],
    }


def entry(identifier: str = "app.service", **values: Any) -> dict[str, Any]:
    return {
        "id": identifier,
        "kind": "application",
        "name": {"en": "Service", "ru": "Сервис"},
        "domains": ["service.example"],
        **values,
    }


def install(store: ApplicationCatalog, entries: list[dict[str, Any]], serial: int = 1) -> str:
    version = f"scaling-{serial}"
    raw = (
        CatalogBundle.model_validate({"serial": serial, "version": version, "entries": entries})
        .model_dump_json()
        .encode()
    )
    key = Ed25519PrivateKey.generate()
    store.import_signed(raw, key.sign(raw), key.public_key().verify)
    return version


def config(version: str) -> Configuration:
    return Configuration.model_validate(
        {
            "applications": {
                "enabled": True,
                "mode": "observe",
                "interfaces": ["lan0"],
                "source_networks": ["192.0.2.0/24"],
                "catalog_version": version,
            }
        }
    )


def test_domain_only_services_are_licensed_observable_and_never_automatically_enforced(
    tmp_path: Path,
) -> None:
    store = ApplicationCatalog(tmp_path)
    version = install(store, [entry(allow_over_port_deny=True)])
    full = store.entries(version, capabilities())[0]
    assert full["observable"] and full["hostname_observable"]
    assert not full["block_validated"] and not full["allow_over_port_deny"]
    core = store.entries(version, capabilities("lgpl-only"))[0]
    assert not core["observable"] and not core["hostname_observable"]
    full_policy = resolve_policy(
        config(version), [full], 1, engine_license_profile="not-for-profit"
    )
    core_policy = resolve_policy(config(version), [core], 2, engine_license_profile="lgpl-only")
    assert full_policy["catalog"]["entries"][0]["domains"] == ["service.example"]
    assert core_policy["catalog"]["entries"][0]["domains"] == []
    unavailable = capabilities()
    unavailable["available"] = False
    assert not store.entries(version, unavailable)[0]["observable"]


def test_domain_only_enforcement_still_requires_fixture_promoted_block(tmp_path: Path) -> None:
    store = ApplicationCatalog(tmp_path)
    version = install(store, [entry()])
    cfg = config(version)
    cfg.applications.mode = "enforce"
    cfg.applications.rules = [
        ApplicationRule(name="Block service", application_ids=["app.service"])
    ]
    with pytest.raises(ValueError, match="validated block"):
        resolve_policy(cfg, store.entries(version, capabilities()), 1)


def test_exact_protocol_name_mapping_preserves_engine_and_version_pins(tmp_path: Path) -> None:
    store = ApplicationCatalog(tmp_path)
    mapping = {
        "engine": "ndpi",
        "version": "6.0",
        "symbol": "NDPI_PROTOCOL_MAIL_POP",
        "native_id": 2,
        "protocol_name": "POP3",
    }
    version = install(store, [entry(domains=[], engine_mapping=mapping)])
    assert store.entries(version, capabilities())[0]["protocol_names"] == ["POP3"]
    other = capabilities()
    other["engine"]["version"] = "7.0.0"
    assert not store.entries(version, other)[0]["observable"]
    other = capabilities()
    other["engine"]["name"] = "other"
    assert not store.entries(version, other)[0]["observable"]
    missing = capabilities()
    missing["protocols"] = [{"name": "pop3"}]
    assert not store.entries(version, missing)[0]["observable"]
    legacy = install(
        store,
        [
            entry(
                domains=[],
                engine_mapping={
                    "engine": "ndpi",
                    "version": "6.0",
                    "symbol": "NDPI_PROTOCOL_HTTP",
                    "native_id": 7,
                },
            )
        ],
        2,
    )
    assert store.entries(legacy, capabilities())[0]["protocol_names"] == ["HTTP"]


def test_generic_protocols_are_attributed_but_not_independent_rule_targets(tmp_path: Path) -> None:
    store = ApplicationCatalog(tmp_path)
    version = install(
        store,
        [
            entry(
                "app.ndpi.http",
                kind="protocol",
                domains=[],
                engine_mapping={
                    "engine": "ndpi",
                    "version": "6.0",
                    "symbol": "NDPI_PROTOCOL_HTTP",
                    "native_id": 7,
                },
            )
        ],
    )
    rows = store.entries(version, capabilities())
    assert rows[0]["observable"] and rows[0]["concrete_ids"] == []
    assert not rows[0]["allow_over_port_deny"] and not rows[0]["block_validated"]
    cfg = config(version)
    policy = resolve_policy(cfg, rows, 1)
    assert policy["catalog"]["entries"][0]["kind"] == "protocol"
    cfg.applications.rules = [ApplicationRule(name="Generic", application_ids=["app.ndpi.http"])]
    with pytest.raises(ValueError, match="concrete"):
        resolve_policy(cfg, rows, 2)


def test_cached_pages_do_not_reparse_or_expose_mutable_catalog_graph(tmp_path: Path) -> None:
    store = ApplicationCatalog(tmp_path)
    version = install(store, [entry()])
    with (
        patch.object(
            CatalogBundle, "model_validate_json", wraps=CatalogBundle.model_validate_json
        ) as parse,
        patch.object(store, "_normalize_entries", wraps=store._normalize_entries) as normalize,
    ):
        first = store.page(version, capabilities())
        first["items"][0]["domains"].append("mutated.example")
        first["items"][0]["capabilities"]["observable"] = False
        private_model = store.bundle(version)
        private_model.entries[0].name.en = "Mutated"
        public = store.entries(version, capabilities())
        public[0]["name_en"] = "Other"
        second = store.page(version, capabilities())
        store.status(version)
    parse.assert_called_once()
    normalize.assert_called_once()
    assert second["items"][0]["domains"] == ["service.example"]
    assert second["items"][0]["name_en"] == "Service"
    assert second["items"][0]["capabilities"]["observable"]


def test_counts_by_kind_describe_full_catalog_even_when_page_is_filtered(tmp_path: Path) -> None:
    store = ApplicationCatalog(tmp_path)
    version = install(
        store,
        [
            entry(),
            entry("app.family", kind="family", children=["app.service"]),
            entry("app.provider", kind="provider"),
            entry("app.category", kind="category"),
            entry("app.protocol", kind="protocol"),
        ],
    )
    query = json.dumps({"kind": "condition", "field": "id", "op": "eq", "value": "app.service"})
    page = store.page(version, capabilities(), query)
    assert page["total"] == 1
    assert page["counts_by_kind"] == {
        "application": 1,
        "family": 1,
        "provider": 1,
        "category": 1,
        "protocol": 1,
    }


def test_cache_is_bounded_across_pins_profiles_and_languages(tmp_path: Path) -> None:
    import app.application_catalog as module

    store = ApplicationCatalog(tmp_path)
    with patch.object(module, "MAX_CACHED_BUNDLES", 1), patch.object(module, "MAX_CACHED_ROWS", 1):
        for serial in range(1, 5):
            version = install(
                store, [entry(name={"en": f"Service {serial}", "ru": f"Сервис {serial}"})], serial
            )
            for language in ("en", "ru"):
                page = store.page(version, capabilities(), language=language)
                assert page["items"][0]["name"].endswith(str(serial))
                assert len(store._bundles) <= 1 and len(store._rows) <= 1
                assert store._cache_bytes <= module.MAX_CACHE_BYTES


def test_policy_accepts_4096_protocols_and_rejects_the_next_entry() -> None:
    rows = [
        {"id": f"app.protocol.{index}", "kind": "protocol", "protocol_names": [], "domains": []}
        for index in range(4096)
    ]
    assert len(resolve_policy(config("scaling"), rows, 1)["catalog"]["entries"]) == 4096
    with pytest.raises(ValueError, match="4096"):
        resolve_policy(config("scaling"), rows + [dict(rows[0], id="app.extra")], 1)


def test_policy_byte_limit_is_four_mib_including_generation_field() -> None:
    row = {
        "kind": "application",
        "protocol_names": [],
        "domains": ["a" * 253] * 32,
        "hostname_extraction_supported": True,
    }
    rows = [dict(row, id=f"app.service.{index}") for index in range(200)]
    policy = resolve_policy(config("scaling"), rows, 1, engine_license_profile="not-for-profit")
    assert 1024 * 1024 < len(json.dumps(policy, separators=(",", ":")).encode()) < 4 * 1024 * 1024
    with pytest.raises(ValueError, match="4 MiB"):
        resolve_policy(
            config("scaling"),
            [dict(row, id=f"app.service.{index}") for index in range(600)],
            1,
            engine_license_profile="not-for-profit",
        )


def test_shared_suffixes_do_not_promise_observation_or_lose_ambiguity_sentinels(
    tmp_path: Path,
) -> None:
    store = ApplicationCatalog(tmp_path)
    version = install(
        store,
        [
            entry("app.owner.a", domains=["shared.example", "unique.example"]),
            entry("app.owner.b", domains=["shared.example"], observable=False),
        ],
    )
    rows = store.entries(version, capabilities())
    by_id = {row["id"]: row for row in rows}
    assert by_id["app.owner.a"]["hostname_observable"]
    assert not by_id["app.owner.b"]["hostname_observable"]
    assert not by_id["app.owner.b"]["observable"]
    assert by_id["app.owner.b"]["hostname_extraction_supported"]
    policy = resolve_policy(config(version), rows, 1, engine_license_profile="not-for-profit")
    catalog = {row["id"]: row for row in policy["catalog"]["entries"]}
    assert "shared.example" in catalog["app.owner.a"]["domains"]
    assert "shared.example" in catalog["app.owner.b"]["domains"], (
        "The native longest-suffix conflict sentinel must retain BOTH owners"
    )
