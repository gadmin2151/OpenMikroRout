"""Composable SQL display filters agree with the typed engine and retain scopes."""

import io
import ipaddress
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.discovery import DiscoveryService
from app.discovery_models import DiscoverySettings
from app.fail2ban_events import BanStore
from app.fail2ban_models import F2BProfile
from app.geoip import GeoIPService
from app.ipsets import DemoIPSetDriver
from app.list_filter_sql import SQLField, compile_list_expression, register_list_filter_functions
from app.list_filters import FieldSpec, compile_expression, parse_expression
from app.main import Settings, create_app
from app.system_lists import SystemAddressList


def condition(field: str, op: str, value: str = "") -> dict[str, Any]:
    return {"kind": "condition", "field": field, "op": op, "value": value}


def group(join: str, *children: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "group", "join": join, "children": list(children)}


def encoded(value: dict[str, Any]) -> str:
    return json.dumps(value)


@pytest.mark.parametrize(
    "expression",
    [
        condition("label", "eq", "STRASSE"),
        condition("label", "contains", "ß"),
        condition("label", "not_contains", "%_"),
        condition("label", "empty"),
        condition("label", "not_empty"),
        condition("protocol", "in", "TCP,udp"),
        condition("protocol", "not_in", "tcp"),
        condition("address", "eq", "8.8.8.8"),
        condition("address", "neq", "8.8.8.8"),
        condition("address", "in", "8.8.0.0/16,1.1.1.1"),
        condition("address", "not_in", "8.8.0.0/16,1.1.1.1"),
        condition("address", "empty"),
        condition("value", "eq", "9007199254740993"),
        condition("value", "gt", "9007199254740992.5"),
        condition("value", "lte", "0.5"),
        condition("value", "neq", "0"),
        condition("value", "empty"),
        condition("addresses", "in", "8.8.8.0/24"),
        condition("addresses", "not_in", "8.8.8.0/24"),
        condition("addresses", "empty"),
        condition("addresses", "not_empty"),
        group(
            "and",
            group("or", condition("label", "eq", "STRASSE"), condition("value", "gt", "0")),
            condition("address", "not_in", "1.1.0.0/16"),
        ),
    ],
)
def test_sql_matches_typed_engine_for_unicode_missing_numbers_ranges_and_groups(
    expression: dict[str, Any],
) -> None:
    rows: list[dict[str, Any]] = [
        {
            "label": "Straße",
            "protocol": "tcp",
            "address": "8.8.8.0-8.8.8.255",
            "value": "9007199254740993",
            "addresses": ["8.8.8.8", "9.9.9.9"],
        },
        {
            "label": "literal %_",
            "protocol": "UDP",
            "address": "1.1.1.1",
            "value": 0,
            "addresses": ["1.1.1.1"],
        },
        {"label": None, "protocol": "", "address": None, "value": None, "addresses": []},
        {
            "label": "",
            "protocol": None,
            "address": "0.0.0.0",
            "value": "0.25",
            "addresses": [None, ""],
        },
    ]
    fields = {
        "label": SQLField(FieldSpec("text"), "label"),
        "protocol": SQLField(FieldSpec("enum", options=("tcp", "udp")), "protocol"),
        "address": SQLField(FieldSpec("ipv4"), "low", ipv4_range=("low", "high")),
        "value": SQLField(FieldSpec("number"), "number_value"),
        "addresses": SQLField(
            FieldSpec("ipv4"), "ips.value", values_from="json_each(records.addresses) AS ips"
        ),
    }
    schema = {key: field.spec for key, field in fields.items()}
    predicate = compile_expression(parse_expression(expression, schema), schema)
    with sqlite3.connect(":memory:") as db:
        register_list_filter_functions(db)
        db.execute("CREATE TABLE records(id, label, protocol, low, high, number_value, addresses)")
        for index, row in enumerate(rows):
            if row["address"]:
                parts = row["address"].split("-")
                low, high = (
                    int(ipaddress.IPv4Address(parts[0])),
                    int(ipaddress.IPv4Address(parts[-1])),
                )
            else:
                low, high = None, None
            db.execute(
                "INSERT INTO records VALUES(?,?,?,?,?,?,?)",
                (
                    index,
                    row["label"],
                    row["protocol"],
                    low,
                    high,
                    row["value"],
                    json.dumps(row["addresses"]),
                ),
            )
        sql, parameters = compile_list_expression(expression, fields)
        selected = [row[0] for row in db.execute(f"SELECT id FROM records WHERE {sql}", parameters)]
    assert selected == [index for index, row in enumerate(rows) if predicate(row)]


def test_sql_values_are_bound_and_unknown_fields_never_become_sql() -> None:
    fields = {"label": SQLField(FieldSpec("text"), "label")}
    payload = "' OR 1=1 --"
    sql, values = compile_list_expression(condition("label", "contains", payload), fields)
    assert payload not in sql and payload.casefold() in values
    for node in (condition("label;DROP", "eq", "x"), condition("label", "gt", "1")):
        with pytest.raises(ValueError):
            compile_list_expression(node, fields)


def test_discovery_expression_uses_visible_latest_text_and_whole_any_ip_source(
    tmp_path: Path,
) -> None:
    service = DiscoveryService(tmp_path, True, DiscoverySettings)
    now = time.time()
    common = {"interface": "eth0", "mac": "00:0c:42:00:01:02"}
    service.ingest(
        {
            **common,
            "source": "arp",
            "addresses": ["10.0.0.1"],
            "hostname": "old-name",
            "model": "retained-model",
        },
        now - 1,
    )
    service.ingest(
        {
            **common,
            "source": "mndp",
            "addresses": ["10.0.0.2"],
            "hostname": "new-name",
            "vendor": "Straße",
        },
        now,
    )
    assert service.hosts(expression=encoded(condition("hostname", "eq", "old-name")))["total"] == 0
    expr = group(
        "and",
        condition("hostname", "contains", "new"),
        condition("vendor", "eq", "STRASSE"),
        condition("model", "eq", "retained-model"),
    )
    assert service.hosts(expression=encoded(expr))["total"] == 1
    assert service.hosts(expression=encoded(condition("address", "neq", "10.0.0.1")))["total"] == 0
    assert service.hosts(expression=encoded(condition("source", "not_in", "arp")))["total"] == 0
    expr = group("or", condition("source", "in", "arp"), condition("vendor", "empty"))
    assert service.hosts(interface="eth1", expression=encoded(expr))["total"] == 0
    assert service.hosts(query="new", negate="query", expression=encoded(expr))["total"] == 0
    assert service.hosts(expression=encoded(expr), limit=1, offset=1)["total"] == 1
    service.ingest(
        {**common, "source": "lldp", "addresses": ["10.0.0.2"], "hostname": "tied-name"},
        now,
    )
    assert service.hosts(expression=encoded(condition("hostname", "eq", "new-name")))["total"] == 0
    assert service.hosts(expression=encoded(condition("hostname", "eq", "tied-name")))["total"] == 1


def test_ban_expression_or_cannot_escape_profile_expiry_or_legacy_search(tmp_path: Path) -> None:
    store = BanStore(tmp_path, DemoIPSetDriver())
    for identifier, address in (("web", "8.8.8.8"), ("web", "9.9.9.9"), ("ssh", "1.1.1.1")):
        assert store.ban(F2BProfile(id=identifier, name=identifier), address, time.time(), 600)
    with store.connection() as db:
        db.execute(
            "INSERT INTO bans(profile,address,added_at,expires_at) VALUES(?,?,?,?)",
            ("web", "4.4.4.4", time.time() - 100, time.time() - 1),
        )
    expr = encoded(
        group("or", condition("profile", "eq", "ssh"), condition("remaining_seconds", "gt", "100"))
    )
    first = store.page(profile="web", expression=expr, limit=1)
    second = store.page(profile="web", expression=expr, limit=1, offset=1)
    assert first["total"] == second["total"] == 2
    assert first["items"][0]["address"] != second["items"][0]["address"]
    assert all(row["profile"] == "web" for row in first["items"] + second["items"])
    assert store.page(profile="web", query="8.8", negate="query", expression=expr)["total"] == 1
    assert (
        store.page(profile="web", expression=encoded(condition("remaining_seconds", "lt", "0")))[
            "total"
        ]
        == 0
    )


def test_geoip_expression_or_stays_inside_active_version_and_country(tmp_path: Path) -> None:
    service = GeoIPService(tmp_path)
    service.import_csv(io.BytesIO(b"4.4.4.0,4.4.4.255,US\n"), "2026-09", compressed=False)
    service.activate("2026-09")
    service.import_csv(
        io.BytesIO(b"1.1.1.0,1.1.1.255,AU\n8.8.8.0,8.8.8.255,US\n9.9.9.0,9.9.9.255,US\n"),
        "2026-10",
        compressed=False,
    )
    service.activate("2026-10")
    expr = group("or", condition("country", "eq", "US"), condition("networks", "gt", "999"))
    assert service.countries(expression=encoded(expr))["items"][0]["country"] == "US"
    assert service.countries(search="US", negate="query", expression=encoded(expr))["total"] == 0
    expr = group("or", condition("address", "in", "1.1.1.0/24"), condition("first", "not_empty"))
    page = service.entries("US", expression=encoded(expr), offset=1, limit=1)
    assert page["total"] == 2 and page["items"] == [{"first": "9.9.9.0", "last": "9.9.9.255"}]
    expr = condition("address", "in", "8.8.8.128/25")
    assert service.entries("US", expression=encoded(expr))["total"] == 1
    assert (
        service.entries("US", expression=encoded(condition("address", "in", "4.4.4.0/24")))["total"]
        == 0
    )


def test_expression_api_keeps_reader_acl_and_bad_input_is_422(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            data_dir=tmp_path,
            password="advanced-filter-admin-password",
            read_password="advanced-filter-reader-password",
            auth_enabled=True,
        )
    )
    with TestClient(app) as client:
        configuration = app.state.service.config()
        configuration.system_lists.append(
            SystemAddressList(name="geo_US", kind="country", country="US")
        )
        app.state.service.save(configuration, app.state.service.state()["revision"])
        valid = encoded(condition("query", "not_contains", "missing"))
        paths = (
            "discovery/hosts",
            "security/fail2ban/bans",
            "security/geoip/countries",
            "security/lists/f2b_web",
        )
        for path in paths:
            assert client.get("/api/" + path, params={"expression": valid}).status_code == 401
        response = client.post(
            "/api/login",
            headers={"X-NAT-Request": "1"},
            json={"username": "viewer", "password": "advanced-filter-reader-password"},
        )
        assert response.status_code == 200
        before = app.state.service.store.read("config")
        for path in paths:
            response = client.get("/api/" + path, params={"expression": valid})
            assert response.status_code == 200, response.text
            for bad in (
                "{",
                encoded(condition("sqlite_master", "eq", "x")),
                encoded(group("or")),
                encoded(condition("query", "gt", "1")),
                encoded({**condition("query", "eq", "x"), "sql": "1=1"}),
            ):
                response = client.get("/api/" + path, params={"expression": bad})
                assert response.status_code == 422, response.text
        assert app.state.service.store.read("config") == before
        response = client.get(
            "/api/security/lists/geo_US",
            params={"expression": encoded(condition("address", "in", "0.0.0.0/0"))},
        )
        assert response.status_code == 200
        assert response.json()["total"] > 0
        assert response.json()["total"] == client.get("/api/security/lists/geo_US").json()["total"]
        response = client.get(
            "/api/security/lists/geo_US",
            params={"expression": encoded(condition("profile", "eq", "ssh"))},
        )
        assert response.status_code == 422
        assert (
            client.post(
                "/api/security/fail2ban/unban",
                headers={"X-NAT-Request": "1"},
                json={"profile": "web", "address": "8.8.8.8"},
            ).status_code
            == 403
        )
