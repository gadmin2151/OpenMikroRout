import hashlib
import json
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.auth import (
    HASH_ITERATIONS,
    MAX_SESSIONS,
    SESSION_SECONDS,
    AuthError,
    AuthService,
    AuthStore,
    LoginSession,
    UserCreate,
    UserUpdate,
    password_hash,
    password_matches,
)
from app.main import Settings, create_app

ADMIN_PASSWORD = "test-only-administrator-password"
READ_PASSWORD = "test-only-reader-password"
NEW_PASSWORD = "test-only-replacement-password"
HEADERS = {"X-NAT-Request": "1"}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        data_dir=tmp_path, auth_enabled=True, password=ADMIN_PASSWORD, read_password=READ_PASSWORD
    )
    with TestClient(create_app(settings)) as connection:
        yield connection


def login(client: TestClient, username: str = "admin", password: str = ADMIN_PASSWORD) -> None:
    result = client.post(
        "/api/login", headers=HEADERS, json={"username": username, "password": password}
    )
    assert result.status_code == 200
    assert result.json()["user"]["username"] == username


def test_accounts_are_hashed_private_and_never_exposed(client: TestClient, tmp_path: Path) -> None:
    assert client.get("/api/session").json() == {"auth_enabled": True, "user": None}
    assert client.get("/api/state").status_code == 401
    login(client)
    state = client.get("/api/state").json()
    assert state["auth_enabled"]
    assert state["current_user"]["role"] == "full"
    response = client.get("/api/users")
    assert response.status_code == 200
    assert len(response.json()["users"]) == 2
    assert "password" not in response.text
    assert "hash" not in response.text
    assert "version" not in response.text
    path = tmp_path / "auth.sqlite3"
    assert path.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(path) as db:
        digests = [row[0] for row in db.execute("SELECT password_hash FROM users")]
    assert all(digest.startswith(f"pbkdf2_sha256${HASH_ITERATIONS}$") for digest in digests)
    assert all(
        secret.encode() not in path.read_bytes() for secret in (ADMIN_PASSWORD, READ_PASSWORD)
    )
    assert password_matches(ADMIN_PASSWORD, digests[0]) or password_matches(
        ADMIN_PASSWORD, digests[1]
    )


def test_read_account_has_view_access_and_all_write_operations_are_blocked(
    client: TestClient,
) -> None:
    login(client, "viewer", READ_PASSWORD)
    before = client.get("/api/state").json()
    assert before["current_user"]["role"] == "read"
    for route in ("state", "statistics", "audit", "interfaces", "network/status", "telemetry"):
        assert client.get("/api/" + route).status_code == 200, route
    assert client.post("/api/preview", headers=HEADERS).status_code == 200
    assert client.get("/api/users").status_code == 403
    for method, path in (
        ("PUT", "/api/config"),
        ("POST", "/api/discard"),
        ("POST", "/api/apply"),
        ("POST", "/api/confirm"),
        ("POST", "/api/rollback"),
        ("POST", "/api/users"),
        ("PUT", "/api/users/nonexistent"),
        ("DELETE", "/api/users/nonexistent"),
        ("POST", "/api/future-mutation"),
    ):
        result = client.request(method, path, headers=HEADERS, json={})
        assert result.status_code == 403, (method, path)
        assert result.headers["cache-control"] == "no-store"
    after = client.get("/api/state").json()
    assert after["revision"] == before["revision"]
    assert after["config"] == before["config"]
    assert client.post("/api/logout", headers=HEADERS).status_code == 200
    assert client.get("/api/state").status_code == 401


def test_full_account_can_manage_users_and_last_full_is_protected(client: TestClient) -> None:
    login(client)
    admin_id = client.get("/api/session").json()["user"]["id"]
    for body in ({"role": "read"}, {"enabled": False}):
        assert client.put(f"/api/users/{admin_id}", headers=HEADERS, json=body).status_code == 409
    assert client.delete(f"/api/users/{admin_id}", headers=HEADERS).status_code == 409
    result = client.post(
        "/api/users",
        headers=HEADERS,
        json={"username": "Operator", "password": NEW_PASSWORD, "role": "full"},
    )
    assert result.status_code == 201
    user = result.json()
    assert user["username"] == "operator" and user["enabled"]
    assert isinstance(user["created_at"], float)
    updated = client.put(
        f"/api/users/{user['id']}", headers=HEADERS, json={"username": "auditor", "role": "read"}
    )
    assert updated.status_code == 200
    assert updated.json()["username"] == "auditor"
    assert client.delete(f"/api/users/{user['id']}", headers=HEADERS).status_code == 200
    assert client.delete(f"/api/users/{user['id']}", headers=HEADERS).status_code == 404
    assert (
        client.post(
            "/api/users",
            headers=HEADERS,
            json={"username": "ADMIN", "password": NEW_PASSWORD, "role": "read"},
        ).status_code
        == 409
    )


@pytest.mark.parametrize(
    "change",
    [
        {"password": NEW_PASSWORD},
        {"role": "full"},
        {"enabled": False},
        {"username": "renamed"},
    ],
)
def test_account_changes_revoke_existing_sessions(
    tmp_path: Path, change: dict[str, object]
) -> None:
    service = AuthService(tmp_path, True, "admin", ADMIN_PASSWORD, "viewer", READ_PASSWORD)
    token, user = service.login("viewer", READ_PASSWORD, "test-client")
    assert token and user and service.resolve(token)
    service.update(user.id, UserUpdate.model_validate(change))
    assert not service.sessions
    assert service.resolve(token) is None
    if change == {"enabled": False}:
        with pytest.raises(AuthError, match="Incorrect username or password"):
            service.login("viewer", READ_PASSWORD, "test-client")


def test_sessions_store_only_token_hash_and_expire(tmp_path: Path) -> None:
    time_value = [1000.0]
    service = AuthService(tmp_path, True, "admin", ADMIN_PASSWORD, clock=lambda: time_value[0])
    token, _user = service.login("admin", ADMIN_PASSWORD, "test-client")
    assert token is not None
    assert token not in service.sessions
    assert hashlib.sha256(token.encode()).hexdigest() in service.sessions
    time_value[0] += SESSION_SECONDS + 1
    assert service.resolve(token) is None
    token, _user = service.login("admin", ADMIN_PASSWORD, "test-client")
    assert token
    service.logout(token)
    assert service.resolve(token) is None


def test_last_full_guard_is_transactional_under_concurrent_demotions(tmp_path: Path) -> None:
    service = AuthService(tmp_path, True, "admin", ADMIN_PASSWORD)
    second = service.create(
        UserCreate(username="second", password=SecretStr(NEW_PASSWORD), role="full")
    )
    store = service.require_store()
    admin = store.by_name("admin")
    assert admin

    def demote(user_id: str) -> int:
        try:
            store.update(user_id, UserUpdate(role="read"), None)
            return 200
        except AuthError as error:
            return error.status

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(demote, (admin.id, second.id)))
    assert sorted(outcomes) == [200, 409]
    assert len([user for user in store.list_users() if user.enabled and user.role == "full"]) == 1


def test_existing_accounts_restart_without_bootstrap_env_and_cannot_open_anonymous(
    tmp_path: Path,
) -> None:
    initial = Settings(
        data_dir=tmp_path, auth_enabled=True, password=ADMIN_PASSWORD, read_password=READ_PASSWORD
    )
    with TestClient(create_app(initial)) as first:
        login(first)
        users = first.get("/api/users").json()["users"]
        admin = next(user for user in users if user["role"] == "full")
        viewer = next(user for user in users if user["role"] == "read")
        assert first.delete(f"/api/users/{viewer['id']}", headers=HEADERS).status_code == 200
        assert (
            first.put(
                f"/api/users/{admin['id']}", headers=HEADERS, json={"password": NEW_PASSWORD}
            ).status_code
            == 200
        )
        assert first.get("/api/state").status_code == 401
    restarted = Settings(data_dir=tmp_path, password="", auth_enabled=False)
    assert restarted.auth_enabled
    with TestClient(create_app(restarted)) as second:
        assert second.get("/api/state").status_code == 401
        login(second, password=NEW_PASSWORD)
        assert len(second.get("/api/users").json()["users"]) == 1
    # Stale bootstrap credentials may be supplied; persisted accounts are authoritative.
    with TestClient(create_app(initial)) as third:
        assert (
            third.post("/api/login", headers=HEADERS, json={"password": ADMIN_PASSWORD}).status_code
            == 401
        )
        login(third, password=NEW_PASSWORD)
        assert len(third.get("/api/users").json()["users"]) == 1


def test_corrupt_account_database_fails_closed_and_empty_demo_stays_compatible(
    tmp_path: Path,
) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        assert client.get("/api/session").json() == {"auth_enabled": False, "user": None}
        assert client.get("/api/state").status_code == 200
        assert client.get("/api/users").status_code == 409
    empty_store = AuthStore(tmp_path / "auth.sqlite3")
    assert not empty_store.has_users(empty_store.path)
    assert not Settings(data_dir=tmp_path).auth_enabled
    empty_store.path.write_bytes(b"not a sqlite database")
    with pytest.raises(RuntimeError, match="Cannot read the account database"):
        Settings(data_dir=tmp_path)


def test_login_rate_limits_user_and_client_and_errors_do_not_enumerate(client: TestClient) -> None:
    unknown = client.post(
        "/api/login", headers=HEADERS, json={"username": "missing", "password": "incorrect"}
    )
    known = client.post(
        "/api/login", headers=HEADERS, json={"username": "admin", "password": "incorrect"}
    )
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()
    for _index in range(3):
        assert (
            client.post(
                "/api/login", headers=HEADERS, json={"username": "viewer", "password": "incorrect"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/login", headers=HEADERS, json={"username": "other", "password": "incorrect"}
        ).status_code
        == 429
    )


def test_invalid_user_input_and_passwords_are_rejected_without_echo(client: TestClient) -> None:
    login(client)
    for username in ("' OR 1=1--", "../admin", "a/b", "üser", ""):
        assert (
            client.post(
                "/api/users",
                headers=HEADERS,
                json={"username": username, "password": NEW_PASSWORD, "role": "read"},
            ).status_code
            == 422
        )
    for password in ("a" * 11, "a" * 513, "\ud800" * 12):
        result = client.post(
            "/api/users",
            headers={**HEADERS, "Content-Type": "application/json"},
            content=json.dumps(
                {"username": "valid", "password": password, "role": "read"}
            ).encode(),
        )
        assert result.status_code == 422
        assert password not in result.text
    admin_id = client.get("/api/session").json()["user"]["id"]
    for update in ({}, {"enabled": None}, {"role": "root"}, {"password": None}):
        assert client.put(f"/api/users/{admin_id}", headers=HEADERS, json=update).status_code == 422
    assert not password_matches("\ud800", password_hash(NEW_PASSWORD))
    assert not password_matches(NEW_PASSWORD, "malformed")


def test_hash_work_is_bounded_and_csrf_cannot_be_bypassed(
    tmp_path: Path, client: TestClient
) -> None:
    service = AuthService(tmp_path / "other", True, "admin", ADMIN_PASSWORD)
    assert service.hash_slots.acquire(blocking=False)
    assert service.hash_slots.acquire(blocking=False)
    with pytest.raises(AuthError, match="Authentication is busy"):
        service.login("admin", ADMIN_PASSWORD, "test-client")
    service.hash_slots.release()
    service.hash_slots.release()
    assert service.login("admin", ADMIN_PASSWORD, "test-client")[0]
    login(client)
    assert client.post("/api/users", json={}).status_code == 403
    assert (
        client.post(
            "/api/users", headers={**HEADERS, "Origin": "https://untrusted.test"}, json={}
        ).status_code
        == 403
    )


def test_revoked_full_session_pool_is_freed_immediately_after_password_change(
    tmp_path: Path,
) -> None:
    service = AuthService(tmp_path, True, "admin", ADMIN_PASSWORD)
    admin = service.require_store().by_name("admin")
    assert admin
    for index in range(MAX_SESSIONS):
        service.sessions[hashlib.sha256(f"test-token-{index}".encode()).hexdigest()] = LoginSession(
            admin.id, admin.version, service.clock() + SESSION_SECONDS
        )
    assert len(service.sessions) == MAX_SESSIONS
    service.update(admin.id, UserUpdate(password=SecretStr(NEW_PASSWORD)))
    assert not service.sessions
    token, user = service.login("admin", NEW_PASSWORD, "test-client")
    assert token and user and service.resolve(token)


def test_deleting_account_frees_its_sessions_without_revoking_other_users(tmp_path: Path) -> None:
    service = AuthService(tmp_path, True, "admin", ADMIN_PASSWORD, "viewer", READ_PASSWORD)
    admin_token, admin = service.login("admin", ADMIN_PASSWORD, "admin-client")
    viewer_token, viewer = service.login("viewer", READ_PASSWORD, "viewer-client")
    assert admin_token and admin and viewer_token and viewer
    service.delete(viewer.id, admin.id)
    assert len(service.sessions) == 1
    assert service.resolve(admin_token)
    assert service.resolve(viewer_token) is None
