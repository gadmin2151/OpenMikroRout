from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import Settings, create_app
from app.models import Configuration

HEADERS = {"X-NAT-Request": "1"}
DOMAIN = "router.example.test"


@pytest.mark.parametrize(
    "value",
    [
        "https://router.example.com",
        "router.example.com:8291",
        "*.example.com",
        "a/b",
        "a@b.com",
        "127.0.0.1",
        "::1",
        "x\nexample.com",
        "<script>",
        "a..com",
    ],
)
def test_domain_rejects_urls_ips_wildcards_and_markup(value: str) -> None:
    with pytest.raises(ValidationError):
        Configuration(web_domain=value)


def test_domain_is_optional_and_uses_existing_dns_normalization() -> None:
    assert Configuration.model_validate({}).web_domain == ""
    assert Configuration(web_domain=" Router.Example.COM. ").web_domain == "router.example.com"
    assert Configuration(web_domain="router.lan").web_domain == "router.lan"


def stage(client: TestClient, domain: str) -> int:
    state = client.get("/api/state").json()
    state["config"]["web_domain"] = domain
    saved = client.put(
        "/api/config",
        headers=HEADERS,
        json={
            "revision": state["revision"],
            "config": state["config"],
        },
    )
    assert saved.status_code == 200
    return int(saved.json()["revision"])


def test_domain_draft_apply_confirm_persistence_and_removal(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    with TestClient(create_app(settings)) as client:
        revision = stage(client, DOMAIN)
        host = {"Host": DOMAIN + ":8291"}
        assert client.get("/api/health", headers=host).status_code == 400
        applied = client.post("/api/apply", headers=HEADERS, json={"revision": revision})
        assert applied.status_code == 200
        assert client.get("/api/health", headers=host).status_code == 200
        assert client.get("/api/health").status_code == 200
        confirmed = client.post(
            "/api/confirm",
            headers={
                **HEADERS,
                **host,
                "Origin": "http://" + DOMAIN + ":8291",
            },
            json={"token": applied.json()["pending"]["token"]},
        )
        assert confirmed.status_code == 200

    with TestClient(create_app(settings)) as client:
        assert client.get("/api/health", headers={"Host": DOMAIN}).status_code == 200
        assert client.get("/api/health", headers={"Host": "other.test"}).status_code == 400
        revision = stage(client, "")
        applied = client.post("/api/apply", headers=HEADERS, json={"revision": revision})
        assert applied.status_code == 200
        assert client.get("/api/health", headers={"Host": DOMAIN}).status_code == 200
        assert (
            client.post(
                "/api/confirm",
                headers=HEADERS,
                json={
                    "token": applied.json()["pending"]["token"],
                },
            ).status_code
            == 200
        )
        assert client.get("/api/health", headers={"Host": DOMAIN}).status_code == 400
        assert client.get("/api/state").status_code == 200


def test_rollback_revokes_pending_hostname_without_loosening_csrf(tmp_path: Path) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        revision = stage(client, DOMAIN)
        assert (
            client.post("/api/apply", headers=HEADERS, json={"revision": revision}).status_code
            == 200
        )
        assert (
            client.post(
                "/api/preview",
                headers={
                    **HEADERS,
                    "Host": DOMAIN,
                    "Origin": "http://evil.test",
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/preview",
                headers={
                    **HEADERS,
                    "Host": DOMAIN,
                    "Origin": "https://" + DOMAIN,
                    "X-Forwarded-Proto": "https",
                },
            ).status_code
            == 403
        )
        assert (
            client.get("/api/health", headers={"Host": DOMAIN + ":" + "9" * 5000}).status_code
            == 400
        )
        assert client.post("/api/rollback", headers=HEADERS).status_code == 200
        assert client.get("/api/health", headers={"Host": DOMAIN}).status_code == 400
        assert client.get("/api/state").json()["dirty"] is True


def test_read_account_cannot_change_domain(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        auth_enabled=True,
        password="test-only-administrator-password",
        read_password="test-only-reader-password",
    )
    with TestClient(create_app(settings)) as client:
        assert (
            client.post(
                "/api/login",
                headers=HEADERS,
                json={
                    "username": "viewer",
                    "password": "test-only-reader-password",
                },
            ).status_code
            == 200
        )
        state = client.get("/api/state").json()
        state["config"]["web_domain"] = DOMAIN
        assert (
            client.put(
                "/api/config",
                headers=HEADERS,
                json={
                    "revision": state["revision"],
                    "config": state["config"],
                },
            ).status_code
            == 403
        )
