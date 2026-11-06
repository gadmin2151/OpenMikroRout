"""Authorization, persistence and failure accounting for the security integration."""

import time
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.auth import AuthError
from app.main import Settings, create_app
from app.models import Configuration
from app.rsc import export_rsc, import_rsc

HEADERS = {"X-NAT-Request": "1"}
PASSWORD = "test-security-admin-password"
READER = "test-security-reader-password"


def login(client: TestClient, reader: bool = False) -> None:
    response = client.post(
        "/api/login",
        headers=HEADERS,
        json={
            "username": "viewer" if reader else "admin",
            "password": READER if reader else PASSWORD,
        },
    )
    assert response.status_code == 200


def test_new_views_require_auth_read_cannot_mutate(tmp_path: Path) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, password=PASSWORD, read_password=READER, auth_enabled=True)
    )
    with TestClient(app) as client:
        paths = [
            "security/fail2ban",
            "security/fail2ban/bans",
            "security/geoip",
            "security/geoip/countries",
            "security/lists",
            "discovery/status",
            "discovery/hosts",
            "scans/status",
            "scans/jobs",
        ]
        for path in paths:
            assert client.get("/api/" + path).status_code == 401
        login(client, reader=True)
        for path in paths:
            result = client.get("/api/" + path)
            assert result.status_code == 200, (path, result.text)
        for path in ["security/geoip/update", "security/fail2ban/unban", "scans/jobs"]:
            assert client.post("/api/" + path, headers=HEADERS, json={}).status_code == 403
        assert not app.state.security_services.scans.jobs()["items"]


def test_protection_draft_requires_fresh_proof_at_apply_and_rolls_back(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path, password=PASSWORD, auth_enabled=True))
    with TestClient(app) as client:
        login(client)
        state = client.get("/api/state").json()
        old = state["config"]["fail2ban"]
        state["config"]["fail2ban"]["enabled"] = True
        assert (
            client.put(
                "/api/config", headers=HEADERS, json={"revision": 0, "config": state["config"]}
            ).status_code
            == 200
        )
        assert client.get("/api/state").json()["security_dirty"]
        denied = client.post("/api/apply", headers=HEADERS, json={"revision": 1})
        assert denied.status_code == 409
        assert not client.get("/api/state").json()["pending"]
        applied = client.post(
            "/api/apply", headers=HEADERS, json={"revision": 1, "proof": {"password": PASSWORD}}
        )
        assert applied.status_code == 200, applied.text
        assert client.get("/api/security/fail2ban").json()["enabled"]
        assert client.post("/api/rollback", headers=HEADERS).status_code == 200
        assert not client.get("/api/security/fail2ban").json()["enabled"]
        assert app.state.service.store.read("applied")["fail2ban"]["profiles"] == old["profiles"]


def test_only_invalid_credentials_generate_fail2ban_event(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path, password=PASSWORD, auth_enabled=True))
    journal = app.state.security_services.fail2ban.journal
    with (
        TestClient(app, client=("91.121.219.84", 41111)) as client,
        patch.object(journal, "failure") as record,
    ):
        bad = {"username": "admin", "password": "wrong-password"}
        assert (
            client.post(
                "/api/login", headers={**HEADERS, "X-Forwarded-For": "8.8.8.8"}, json=bad
            ).status_code
            == 401
        )
        assert record.call_count == 1
        assert record.call_args.args[1] == "91.121.219.84"
        record.reset_mock()
        assert client.post("/api/login", json=bad).status_code == 403
        with patch("app.auth.AuthService.login", side_effect=AuthError(429, "Too many attempts")):
            assert client.post("/api/login", headers=HEADERS, json=bad).status_code == 429
        with patch("app.auth.AuthService.login", side_effect=AuthError(503, "Storage error")):
            assert client.post("/api/login", headers=HEADERS, json=bad).status_code == 503
        with patch(
            "app.auth.AuthService.login",
            side_effect=AuthError(401, "Account changed; sign in again"),
        ):
            assert client.post("/api/login", headers=HEADERS, json=bad).status_code == 401
        record.assert_not_called()


def test_old_configs_and_rsc_keep_new_settings(tmp_path: Path) -> None:
    config = Configuration.model_validate({"rules": [], "address_lists": []})
    assert (
        not config.fail2ban.enabled and not config.discovery.enabled and not config.scanning.enabled
    )
    config.fail2ban.profiles[0].ignore_addresses = ["10.0.0.0/8"]
    config.discovery.interfaces = ["eth0"]
    config.scanning.interfaces = ["eth0"]
    assert import_rsc(export_rsc(config)) == config
    app = create_app(Settings(data_dir=tmp_path))
    assert not (tmp_path / "geoip.sqlite3").exists()  # synthetic demo data cannot become live data
    with TestClient(app) as client:
        assert (
            client.get("/api/security/lists").json()["total"] == 2
        )  # empty default F2B sets visible
        assert client.get("/api/security/lists/f2b_web").json()["total"] == 0
        assert client.get("/api/security/geoip/lookup?address=127.0.0.1").json()["country"] is None


def test_scanning_is_explicit_and_retains_jobs_across_restart(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))
    with TestClient(app) as client:
        assert client.get("/api/discovery/hosts").status_code == 200
        assert client.get("/api/scans/jobs").json()["total"] == 0
        request = {"kind": "ports", "interface": "eth0", "target": "203.0.113.12"}
        assert client.post("/api/scans/jobs", headers=HEADERS, json=request).status_code == 503
        state = client.get("/api/state").json()
        state["config"]["scanning"].update(enabled=True, interfaces=["eth0"])
        assert (
            client.put(
                "/api/config", headers=HEADERS, json={"revision": 0, "config": state["config"]}
            ).status_code
            == 200
        )
        pending = client.post("/api/apply", headers=HEADERS, json={"revision": 1}).json()["pending"]
        assert client.post("/api/scans/jobs", headers=HEADERS, json=request).status_code == 409
        assert (
            client.post(
                "/api/confirm", headers=HEADERS, json={"token": pending["token"]}
            ).status_code
            == 200
        )
        response = client.post("/api/scans/jobs", headers=HEADERS, json=request)
        assert response.status_code == 202, response.text
        identifier = response.json()["id"]
        for _ in range(100):
            result = client.get(f"/api/scans/jobs/{identifier}").json()
            if result["state"] == "completed":
                break
            time.sleep(0.01)
        assert result["state"] == "completed" and result["result"]["demo"]
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        assert client.get(f"/api/scans/jobs/{identifier}").json()["state"] == "completed"


def test_security_query_bounds_fail_validation_without_server_errors(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))
    with TestClient(app) as client:
        for path in [
            "/api/scans/jobs?limit=101",
            "/api/scans/jobs?offset=101",
            "/api/discovery/hosts?limit=101",
            "/api/discovery/hosts?offset=4097",
            "/api/discovery/hosts?interface=eth0;evil",
            "/api/discovery/hosts?interface=eth0%2B",
            "/api/discovery/hosts?interface=eth0:1",
            "/api/discovery/hosts?interface=lo",
        ]:
            assert client.get(path).status_code == 422, path
        assert client.get("/api/scans/jobs?limit=100&offset=100").status_code == 200
        assert client.get("/api/discovery/hosts?limit=100&offset=4096").status_code == 200


def test_country_entries_query_validation_and_read_access(tmp_path: Path) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, password=PASSWORD, read_password=READER, auth_enabled=True)
    )
    with TestClient(app) as client:
        login(client)
        state = client.get("/api/state").json()
        state["config"]["system_lists"] = [{"name": "geo_US", "kind": "country", "country": "US"}]
        assert (
            client.put(
                "/api/config", headers=HEADERS, json={"revision": 0, "config": state["config"]}
            ).status_code
            == 200
        )
        login(client, reader=True)
        path = "/api/security/lists/geo_US"
        assert client.get(path + "?query=8.8.8.255").json()["total"] == 1
        assert client.get(path + "?query=8.8.8.128/25").json()["total"] == 1
        assert client.get(path + "?query=8.8.9.0").json()["total"] == 0
        assert client.get(path + "?query=invalid").status_code == 409
        assert client.get(path + "?query=" + "x" * 65).status_code == 422
        assert client.get("/api/security/lists/f2b_web?query=8.8").status_code == 200


def test_reader_preview_does_not_prepare_country_sets(tmp_path: Path) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, password=PASSWORD, read_password=READER, auth_enabled=True)
    )
    with TestClient(app) as client:
        login(client)
        state = client.get("/api/state").json()
        state["config"]["system_lists"] = [{"name": "geo_US", "kind": "country", "country": "US"}]
        state["config"]["filter_rules"].append(
            {"name": "Country restriction", "src_list": "geo_US", "action": "drop"}
        )
        assert (
            client.put(
                "/api/config", headers=HEADERS, json={"revision": 0, "config": state["config"]}
            ).status_code
            == 200
        )
        driver = app.state.security_services.lists.driver
        login(client, reader=True)
        assert client.post("/api/preview", headers=HEADERS).status_code == 503
        assert not driver.exists("geo_US")
        login(client)
        assert client.post("/api/preview", headers=HEADERS).status_code == 200
        assert driver.exists("geo_US")
        login(client, reader=True)
        assert client.post("/api/preview", headers=HEADERS).status_code == 200
