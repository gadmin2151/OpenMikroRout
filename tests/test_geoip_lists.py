"""Country-list references, bounded ingestion and atomic kernel-set recovery."""

import gzip
import io
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.compiler import FirewallError, compiled_rules
from app.filtering import compiled_filters
from app.geoip import GeoIPService, download_url
from app.ipsets import DemoIPSetDriver, LinuxIPSetDriver
from app.models import AddressList, Configuration
from app.system_list_runtime import SystemListRuntime
from app.system_lists import kernel_set_name, required_system_lists

CSV = b"1.1.1.0,1.1.1.255,AU\n8.8.8.0,8.8.8.255,US\n2001:4860::,2001:4860::ffff,US\n"


def database(tmp_path: Path) -> GeoIPService:
    service = GeoIPService(tmp_path)
    service.import_csv(io.BytesIO(gzip.compress(CSV)), "2026-10")
    service.activate("2026-10")
    return service


def config(*countries: str) -> Configuration:
    return Configuration.model_validate(
        {
            "system_lists": [
                {"kind": "country", "name": f"geo_{code}", "country": code} for code in countries
            ],
            "filter_rules": [
                {"name": code, "src_list": f"geo_{code}", "action": "drop"} for code in countries
            ],
        }
    )


def test_reserved_names_and_explicit_reference_contract() -> None:
    for name in ["geo_US", "f2b_web"]:
        with pytest.raises(ValidationError, match="reserved"):
            AddressList(name=name, addresses=["1.2.3.4"])
    with pytest.raises(ValidationError, match="Unknown address list"):
        Configuration.model_validate({"filter_rules": [{"name": "Unknown", "src_list": "geo_US"}]})
    for value in ["geo_ZZ", "geo_us", "f2b_a;shutdown", "anything", "f2b_" + "x" * 30]:
        with pytest.raises(ValueError):
            kernel_set_name(value)
    assert kernel_set_name("geo_MD") == "omr_geo_MD"


def test_system_lists_compile_one_match_in_filter_and_nat() -> None:
    value = config("AU", "US")
    value = Configuration.model_validate(
        {
            **value.model_dump(),
            "rules": [
                {
                    "name": "Geo NAT",
                    "src_list": "geo_US",
                    "dst_list": "geo_AU",
                    "dst_ports": "443",
                    "to_address": "192.168.1.10",
                    "to_ports": "443",
                }
            ],
        }
    )
    lines = compiled_rules(value)
    assert len(lines) == 1
    assert "-m set --match-set omr_geo_US src" in lines[0]
    assert "-m set --match-set omr_geo_AU dst" in lines[0]
    assert "-s geo_" not in lines[0]
    assert any("--match-set omr_geo_US src" in rule for rule in compiled_filters(value))


def test_offline_boundaries_unknown_special_and_pagination(tmp_path: Path) -> None:
    service = database(tmp_path)
    assert service.lookup("1.1.1.0")["country"] == "AU"
    assert service.lookup("1.1.1.255")["country"] == "AU"
    assert service.lookup("1.1.2.0")["status"] == "unknown"
    assert service.lookup("8.8.8.8")["country"] == "US"
    assert service.lookup("192.168.1.1")["status"] == "special"
    assert service.lookup("127.0.0.1")["country"] is None
    assert service.lookup("224.0.0.1")["status"] == "special"
    assert list(service.networks("US")) == ["8.8.8.0/24"]
    page = service.countries(limit=1)
    assert page["total"] == 2 and len(page["items"]) == 1
    assert service.countries(search="US")["items"][0]["country"] == "US"
    assert service.entries("US")["items"] == [{"first": "8.8.8.0", "last": "8.8.8.255"}]
    for kwargs in [{"offset": -1}, {"limit": 201}, {"limit": 0}]:
        with pytest.raises(ValueError):
            service.countries(offset=kwargs.get("offset", 0), limit=kwargs.get("limit", 50))


@pytest.mark.parametrize(
    "content",
    [
        b"8.8.8.1,8.8.8.0,US\n",
        b"8.8.8.0,8.8.8.255,ZZ\n",
        b"8.8.8.0,8.8.8.255,US\n8.8.8.128,8.8.9.255,US\n",
        b"8.8.8.0,::1,US\n",
        b"8.8.8.0,8.8.8.255,US,extra\n",
        b"x" * 1024,
        b"",
        b"2001:4860::,2001:4860::ffff,US\n",
    ],
)
def test_bad_import_preserves_old_database(tmp_path: Path, content: bytes) -> None:
    service = database(tmp_path)
    with pytest.raises(FirewallError):
        service.import_csv(io.BytesIO(gzip.compress(content)), "2026-11")
    assert service.active_version == "2026-10"
    assert service.lookup("8.8.8.8")["country"] == "US"
    with service.connect() as db:
        assert db.execute("SELECT count(*) FROM versions").fetchone()[0] == 1


def test_bad_gzip_and_version_are_bounded(tmp_path: Path) -> None:
    service = database(tmp_path)
    with pytest.raises(FirewallError):
        service.import_csv(io.BytesIO(b"not gzip"), "2026-11")
    for value in ["../../passwd", "2026-99", "http://evil", "2026-1"]:
        with pytest.raises(ValueError):
            download_url(value)


def test_disabled_features_require_no_database_or_ipset(tmp_path: Path) -> None:
    service = GeoIPService(tmp_path)
    driver = DemoIPSetDriver()
    runtime = SystemListRuntime(service, driver)
    value = Configuration()
    assert not required_system_lists(value)
    runtime.prepare(value)
    assert not driver.temporary and not driver.countries
    with pytest.raises(FirewallError, match="Download"):
        runtime.prepare(config("US"))
    unused = Configuration.model_validate(
        {"system_lists": [{"name": "geo_US", "kind": "country", "country": "US"}]}
    )
    runtime.prepare(unused)
    assert not driver.countries


def test_preview_does_not_replace_active_set(tmp_path: Path) -> None:
    service = database(tmp_path)
    driver = DemoIPSetDriver()
    runtime = SystemListRuntime(service, driver)
    driver.countries["geo_US"] = ["9.9.9.0/24"]
    runtime.prepare(config("US"))
    assert driver.countries["geo_US"] == ["9.9.9.0/24"]
    runtime.apply(config("US"))
    assert driver.countries["geo_US"] == ["8.8.8.0/24"]


def test_partial_activation_restores_previous_sets(tmp_path: Path) -> None:
    class FailingDriver(DemoIPSetDriver):
        failed = False

        def replace_country(self, name: str, networks: Any) -> None:
            values = list(networks)
            if name == "geo_US" and values == ["8.8.4.0/24"] and not self.failed:
                self.failed = True
                raise FirewallError("Injected second-set failure")
            super().replace_country(name, values)

    service = database(tmp_path)
    driver = FailingDriver()
    runtime = SystemListRuntime(service, driver)
    configuration = config("AU", "US")
    runtime.prepare(configuration)
    before = dict(driver.countries)
    service.import_csv(
        io.BytesIO(b"1.0.0.0,1.0.0.255,AU\n8.8.4.0,8.8.4.255,US\n"), "2026-11", compressed=False
    )
    with pytest.raises(FirewallError, match="Injected"):
        service.activate(
            "2026-11", lambda version: runtime.activate_version(configuration, version)
        )
    assert driver.countries == before
    assert service.active_version == "2026-10"
    assert service.lookup("8.8.8.8")["country"] == "US"


def test_restart_recovers_pending_geoip_activation(tmp_path: Path) -> None:
    service = database(tmp_path)
    driver = DemoIPSetDriver()
    runtime = SystemListRuntime(service, driver)
    configuration = config("US")
    runtime.prepare(configuration)
    saved = runtime.snapshot(configuration)
    runtime.journal.write_text(json.dumps(saved))
    driver.countries["geo_US"] = ["8.8.4.0/24"]
    service._set_meta({"activation_pending": "2026-11", "activation_previous": "2026-10"})
    SystemListRuntime(GeoIPService(tmp_path), driver).recover(configuration)
    assert driver.countries["geo_US"] == ["8.8.8.0/24"]
    assert not runtime.journal.exists()


def test_temporary_timeout_is_positive_and_country_rollback_keeps_bans(tmp_path: Path) -> None:
    driver = DemoIPSetDriver()
    driver.add_temporary("f2b_web", "1.1.1.1", 90)
    runtime = SystemListRuntime(database(tmp_path), driver)
    for timeout in [0, -1, 2_147_484]:
        with pytest.raises(ValueError):
            driver.add_temporary("f2b_web", "1.1.1.1", timeout)
    before = dict(driver.temporary["f2b_web"])
    runtime.apply(config("US"))
    assert driver.temporary["f2b_web"] == before
    driver.delete_temporary("f2b_web", "1.1.1.1")
    assert driver.temporary_entries("f2b_web") == []


def test_linux_rejects_foreign_reserved_set(tmp_path: Path) -> None:
    class ForeignDriver(LinuxIPSetDriver):
        def _run(self, args: list[str], payload: str | None = None) -> str:
            assert args[0] == "list"
            return "omr_f2b_web\n"

    driver = ForeignDriver(tmp_path)
    with pytest.raises(FirewallError, match="not owned"):
        driver.ensure_temporary("f2b_web")


def test_unknown_feed_sentinel_and_special_ranges_never_match(tmp_path: Path) -> None:
    service = GeoIPService(tmp_path)
    service.import_csv(
        io.BytesIO(
            b"8.8.8.0,8.8.8.255,US\n10.0.0.0,10.255.255.255,US\n"
            b"11.0.0.0,11.0.0.255,ZZ\n127.0.0.0,127.255.255.255,US\n"
            b"224.0.0.0,239.255.255.255,US\n"
        ),
        "2026-11",
        compressed=False,
    )
    service.activate("2026-11")
    assert list(service.networks("US")) == ["8.8.8.0/24"]
    assert service.lookup("11.0.0.1")["status"] == "unknown"


def test_callback_owns_activation_commit_and_invalid_version_releases_lock(tmp_path: Path) -> None:
    service = database(tmp_path)
    service.import_csv(io.BytesIO(CSV), "2026-11", compressed=False)
    seen = []

    def activate(version: str) -> None:
        seen.append(service.active_version)
        service.activate(version)

    state = service.update(activate, "2026-11")
    assert seen == ["2026-10"] and not state["updating"]
    assert service.active_version == "2026-11"
    with pytest.raises(ValueError):
        service.update(version="bad")
    assert not service.update_lock.locked()


def test_retention_keeps_active_version_and_bounds_history(tmp_path: Path) -> None:
    service = database(tmp_path)
    for month in range(1, 8):
        service.import_csv(io.BytesIO(CSV), f"2025-{month:02d}", compressed=False)
    with service.connect() as db:
        assert db.execute("SELECT count(*) FROM versions").fetchone()[0] == 4
    assert service.lookup("8.8.8.8")["country"] == "US"


def test_temporary_lists_require_an_owned_profile() -> None:
    with pytest.raises(ValidationError, match="configured Fail2ban profile"):
        Configuration.model_validate(
            {"system_lists": [{"name": "f2b_ghost", "kind": "temporary", "profile": "ghost"}]}
        )


def test_read_preview_never_creates_or_changes_sets(tmp_path: Path) -> None:
    service = database(tmp_path)
    driver = DemoIPSetDriver()
    runtime = SystemListRuntime(service, driver)
    configuration = config("US")
    with pytest.raises(FirewallError, match="Full access"):
        runtime.prepare(configuration, create=False)
    assert driver.countries == {}
    driver.countries["geo_US"] = ["9.9.9.0/24"]
    runtime.prepare(configuration, create=False)
    assert driver.countries["geo_US"] == ["9.9.9.0/24"]


def test_country_entry_search_matches_range_boundaries(tmp_path: Path) -> None:
    service = database(tmp_path)
    for address in ["8.8.8.0", "8.8.8.255", "8.8.8.128/25", "8.8.0.0/16"]:
        assert service.entries("US", query=address)["total"] == 1
    assert service.entries("US", query="8.8.9.0")["total"] == 0
    assert service.entries("US", query="1.1.1.1")["total"] == 0
    for invalid in ["8.8", "host.example", "8.8.8.8;drop", "::1"]:
        with pytest.raises(ValueError, match="IPv4"):
            service.entries("US", query=invalid)
