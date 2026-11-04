import json
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.firewall import DemoDriver
from app.main import Settings, create_app
from app.models import Configuration

HEADERS = {"X-NAT-Request": "1"}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as test_client:
        yield test_client


def test_demo_loads_and_does_not_require_linux(client: TestClient) -> None:
    response = client.get("/api/state")
    assert response.status_code == 200
    assert response.json()["mode"] == "demo"
    assert len(response.json()["config"]["rules"]) == 7
    assert client.get("/").status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_api_apply_confirm_flow(client: TestClient) -> None:
    state = client.get("/api/state").json()
    state["config"]["rules"][0]["name"] = "Updated"
    saved = client.put(
        "/api/config",
        headers=HEADERS,
        json={"config": state["config"], "revision": state["revision"]},
    )
    assert saved.status_code == 200
    preview = client.post("/api/preview", headers=HEADERS)
    assert preview.json()["valid"]
    applied = client.post("/api/apply", headers=HEADERS, json={"revision": 1})
    assert applied.status_code == 200
    confirmed = client.post(
        "/api/confirm", headers=HEADERS, json={"token": applied.json()["pending"]["token"]}
    )
    assert confirmed.status_code == 200
    assert not confirmed.json()["dirty"]
    assert client.get("/api/audit").json()[0]["event"] == "confirmed"


def test_csrf_and_host_protection(client: TestClient) -> None:
    assert client.post("/api/rollback").status_code == 403
    assert (
        client.post("/api/rollback", headers={**HEADERS, "Origin": "https://evil.test"}).status_code
        == 403
    )
    assert client.get("/api/state", headers={"Host": "evil.test"}).status_code == 400


def test_rule_order_is_persisted_and_compiled_in_the_same_order(client: TestClient) -> None:
    state = client.get("/api/state").json()
    config = state["config"]
    config["rules"][1], config["rules"][2] = config["rules"][2], config["rules"][1]
    response = client.put(
        "/api/config", headers=HEADERS, json={"revision": state["revision"], "config": config}
    )
    assert response.status_code == 200
    saved = client.get("/api/state").json()
    assert [rule["id"] for rule in saved["config"]["rules"]] == [
        rule["id"] for rule in config["rules"]
    ]
    script = client.post("/api/preview", headers=HEADERS).json()["script"]
    assert script.index(config["rules"][1]["id"]) < script.index(config["rules"][2]["id"])


def test_rejects_large_body(client: TestClient) -> None:
    assert client.put("/api/config", content=b"x" * 1_048_577, headers=HEADERS).status_code == 413


def test_rejects_stale_revision_and_invalid_input(client: TestClient) -> None:
    state = client.get("/api/state").json()
    body = {"config": state["config"], "revision": 0}
    assert client.put("/api/config", headers=HEADERS, json=body).status_code == 200
    assert client.put("/api/config", headers=HEADERS, json=body).status_code == 409
    body["config"]["rules"][0]["src_address"] = "invalid"
    assert client.put("/api/config", headers=HEADERS, json=body).status_code == 422


def test_linux_requires_auth_cookie_and_logout(tmp_path: Path) -> None:
    settings = Settings(mode="linux", data_dir=tmp_path, password="test-only-strong-password")
    app = create_app(settings, DemoDriver(Configuration()))
    with TestClient(app) as client:
        assert client.get("/api/state").status_code == 401
        assert (
            client.post("/api/login", headers=HEADERS, json={"password": "wrong"}).status_code
            == 401
        )
        response = client.post("/api/login", headers=HEADERS, json={"password": settings.password})
        assert response.status_code == 200
        assert "HttpOnly" in response.headers["set-cookie"]
        assert "SameSite=strict" in response.headers["set-cookie"]
        assert client.get("/api/state").status_code == 200
        assert client.get("/api/state").json()["config"]["rules"] == []
        assert client.post("/api/logout", headers=HEADERS).status_code == 200
        assert client.get("/api/state").status_code == 401


def test_login_rate_limit_and_no_password_echo(tmp_path: Path) -> None:
    app = create_app(
        Settings(mode="linux", data_dir=tmp_path, password="test-only-strong-password"),
        DemoDriver(Configuration()),
    )
    with TestClient(app) as client:
        for _ in range(5):
            assert (
                client.post("/api/login", headers=HEADERS, json={"password": "wrong"}).status_code
                == 401
            )
        assert (
            client.post("/api/login", headers=HEADERS, json={"password": "wrong"}).status_code
            == 429
        )
        secret = "x" * 513
        response = client.post("/api/login", headers=HEADERS, json={"password": secret})
        assert response.status_code == 422
        assert secret not in response.text


def test_linux_mode_refuses_empty_password(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="12 characters"):
        Settings(mode="linux", data_dir=tmp_path, password="")


def test_linux_interface_discovery_includes_physical_and_virtual_links(tmp_path: Path) -> None:
    settings = Settings(mode="linux", data_dir=tmp_path, password="test-only-strong-password")
    rows = [
        {
            "ifname": "eth3",
            "operstate": "UP",
            "addr_info": [
                {"family": "inet", "local": "192.168.5.1", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
            ],
        },
        {
            "ifname": "wg0",
            "operstate": "UNKNOWN",
            "addr_info": [
                {"family": "inet", "local": "10.8.0.1", "prefixlen": 24},
            ],
        },
        {"ifname": "br0", "operstate": "DOWN", "addr_info": []},
    ]
    with TestClient(create_app(settings, DemoDriver(Configuration()))) as client:
        client.post("/api/login", headers=HEADERS, json={"password": settings.password})
        with (
            patch("app.main.shutil.which", return_value="/usr/sbin/ip"),
            patch("app.main.LinuxDriver.run", return_value=json.dumps(rows)),
            patch("pathlib.Path.read_text", return_value="1"),
        ):
            response = client.get("/api/interfaces")
        assert response.status_code == 200
        data = response.json()
        assert not data["demo"]
        assert data["forwarding"]
        assert [item["name"] for item in data["interfaces"]] == ["eth3", "wg0", "br0"]
        assert data["interfaces"][0]["address"] == "192.168.5.1/24"
        assert data["interfaces"][2]["address"] == ""
