"""Display exclusions keep resource scope, totals, pagination and read-only ACLs."""

import io
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.discovery import DiscoveryService
from app.discovery_models import DiscoverySettings
from app.display_filters import parse_display_negation, validate_display_negation
from app.fail2ban_events import BanStore
from app.fail2ban_models import F2BProfile
from app.geoip import GeoIPService
from app.ipsets import DemoIPSetDriver
from app.main import Settings, create_app


@pytest.mark.parametrize("value", ["query,interface", ["query,interface"], ["query", "interface"]])
def test_negation_csv_and_repeated_chunks_are_bounded_and_allowlisted(value: object) -> None:
    assert parse_display_negation(value, allowed={"query", "interface"}) == ["query", "interface"]
    assert parse_display_negation(["query", "query"], allowed={"query"}) == ["query"]


@pytest.mark.parametrize(
    "value",
    [None, {}, [1], ["query"] * 8, "query," * 8, "x" * 101, "QUERY", "query,", "query;DROP"],
)
def test_negation_rejects_unknown_empty_or_oversized_tokens(value: object) -> None:
    with pytest.raises(ValueError):
        parse_display_negation(value, allowed={"query", "interface"})


def test_empty_negated_criterion_is_rejected() -> None:
    assert validate_display_negation("", {"query": ""}) == []
    for value in ("", "   "):
        with pytest.raises(ValueError, match="non-empty"):
            validate_display_negation("query", {"query": value})


def discovery_fixture(path: Path) -> DiscoveryService:
    service = DiscoveryService(path, True, DiscoverySettings)
    for number, (interface, name) in enumerate(
        (("eth0", "alpha"), ("eth0", "beta"), ("eth1", "alpha"), ("eth1", "beta")), start=1
    ):
        service.ingest(
            {
                "interface": interface,
                "source": "arp",
                "addresses": [f"10.0.0.{number}"],
                "hostname": name,
            },
            time.time() - number,
        )
    return service


def test_hosts_negate_each_whole_criterion_before_count_and_page(tmp_path: Path) -> None:
    service = discovery_fixture(tmp_path)
    page = service.hosts(query="alpha", interface="eth0", negate="query")
    assert page["total"] == 1 and page["items"][0]["hostname"] == "beta"
    page = service.hosts(query="alpha", interface="eth0", negate="interface")
    assert page["total"] == 1 and page["items"][0]["interface"] == "eth1"
    page = service.hosts(query="alpha", interface="eth0", negate="query,interface")
    assert page["total"] == 1 and page["items"][0]["addresses"] == ["10.0.0.4"]
    first = service.hosts(query="alpha", negate="query", limit=1)
    second = service.hosts(query="alpha", negate="query", limit=1, offset=1)
    assert first["total"] == second["total"] == 2
    assert first["items"][0]["id"] != second["items"][0]["id"]
    for literal in ("%", "10_0", "' OR 1=1 --"):
        assert service.hosts(query=literal)["total"] == 0
        assert service.hosts(query=literal, negate="query")["total"] == 4


def test_ban_search_negates_address_or_profile_without_escaping_profile_scope(
    tmp_path: Path,
) -> None:
    driver = DemoIPSetDriver()
    store = BanStore(tmp_path, driver)
    for profile, address in (("web", "8.8.8.8"), ("web", "9.9.9.9"), ("ssh", "8.8.4.4")):
        assert store.ban(F2BProfile(id=profile, name=profile), address, time.time(), 600)
    first = store.page(query="8.8", negate="query", limit=1)
    assert first["total"] == 1 and first["items"][0]["address"] == "9.9.9.9"
    assert store.page(query="WEB")["total"] == 2
    assert store.page(query="WEB", negate="query")["items"][0]["profile"] == "ssh"
    page = store.page(profile="web", query="8.8", negate="query")
    assert page["total"] == 1 and page["items"][0]["profile"] == "web"
    assert store.page(profile="web", negate="profile")["total"] == 1
    page = store.page(profile="web", query="8.8", negate="profile,query")
    assert page["total"] == 0
    assert store.page(query="' OR 1=1 --", negate="query")["total"] == 3
    assert len(driver.temporary_entries("f2b_web")) == 2


def geo_fixture(path: Path) -> GeoIPService:
    service = GeoIPService(path)
    service.import_csv(
        io.BytesIO(b"1.1.1.0,1.1.1.255,AU\n8.8.8.0,8.8.8.255,US\n9.9.9.0,9.9.9.255,US\n"),
        "2026-10",
        compressed=False,
    )
    service.activate("2026-10")
    return service


def test_country_and_range_exclusion_is_scoped_and_applied_before_pagination(
    tmp_path: Path,
) -> None:
    service = geo_fixture(tmp_path)
    page = service.countries(search="US", negate="query", limit=1)
    assert page["total"] == 1 and page["items"][0]["country"] == "AU"
    for network in ("8.8.8.0", "8.8.8.255", "8.8.8.128/25", "8.8.0.0/16"):
        page = service.entries("US", query=network, negate="query", limit=1)
        assert page["total"] == 1
        assert page["items"] == [{"first": "9.9.9.0", "last": "9.9.9.255"}]
    page = service.entries("US", query="1.1.1.0/24", negate="query", offset=1, limit=1)
    assert page["total"] == 2 and len(page["items"]) == 1
    assert service.entries("US", query="0.0.0.0/0", negate="query")["total"] == 0
    assert service.entries("US", query="8.8.0.0/16", negate="query", offset=1)["items"] == []
    with pytest.raises(ValueError):
        service.entries("US", query="8.8.8.8;DROP", negate="query")
    with pytest.raises(ValueError, match="non-empty"):
        service.countries(search="%", negate="query")


def test_api_read_user_can_filter_but_negation_cannot_escape_resource_or_mutate(
    tmp_path: Path,
) -> None:
    password = "display-filter-reader-password"
    app = create_app(
        Settings(
            data_dir=tmp_path,
            password="display-filter-admin-password",
            read_password=password,
            auth_enabled=True,
        )
    )
    with TestClient(app) as client:
        service = app.state.security_services
        original = app.state.service.store.read("config")
        driver = service.fail2ban.bans.driver
        assert service.fail2ban.bans.ban(
            F2BProfile(id="web", name="web"), "8.8.8.8", time.time(), 600
        )
        assert service.fail2ban.bans.ban(
            F2BProfile(id="ssh", name="ssh"), "9.9.9.9", time.time(), 600
        )
        client.post(
            "/api/login",
            headers={"X-NAT-Request": "1"},
            json={"username": "viewer", "password": password},
        )
        for path in (
            "/api/discovery/hosts?query=missing&negate=query",
            "/api/security/fail2ban/bans?query=8.8&negate=query",
            "/api/security/geoip/countries?query=US&negate=query",
            "/api/security/lists/f2b_web?query=8.8&negate=query",
        ):
            response = client.get(path)
            assert response.status_code == 200, response.text
        assert client.get("/api/security/lists/f2b_web?query=8.8&negate=query").json()["total"] == 0
        path = "/api/security/fail2ban/bans?profile=web&query=8.8&negate=profile&negate=query"
        response = client.get(path)
        assert response.status_code == 200 and response.json()["total"] == 1
        assert response.json()["items"][0]["profile"] == "ssh"
        for endpoint in (
            "discovery/hosts",
            "security/fail2ban/bans",
            "security/geoip/countries",
            "security/lists/f2b_web",
        ):
            for query in (
                "negate=query",
                "query=8.8&negate=unknown",
                "query=8.8&negate=query,",
                "query=8.8&negate=" + ",".join(["query"] * 8),
            ):
                response = client.get(f"/api/{endpoint}?{query}")
                assert response.status_code == 422, response.text
        assert (
            client.get("/api/security/lists/f2b_web?profile=web&negate=profile").status_code == 422
        )
        assert (
            client.post(
                "/api/security/fail2ban/unban",
                headers={"X-NAT-Request": "1"},
                json={"profile": "web", "address": "8.8.8.8"},
            ).status_code
            == 403
        )
        assert app.state.service.store.read("config") == original
        assert len(driver.temporary_entries("f2b_web")) == 1
