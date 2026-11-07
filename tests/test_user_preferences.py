import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.account_backup import AccountRow, AccountSnapshots
from app.auth import AuthError, AuthService, AuthStore, UserPreferences, UserUpdate, password_hash
from app.main import Settings, create_app

PASSWORD = "test-only-language-preference-password"
HEADERS = {"X-NAT-Request": "1"}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(
            Settings(
                data_dir=tmp_path,
                auth_enabled=True,
                password=PASSWORD,
                read_password=PASSWORD,
            )
        )
    ) as connection:
        yield connection


def login(client: TestClient, username: str) -> dict[str, object]:
    result = client.post(
        "/api/login", headers=HEADERS, json={"username": username, "password": PASSWORD}
    )
    assert result.status_code == 200
    user: dict[str, object] = result.json()["user"]
    return user


@pytest.mark.parametrize("username", ["admin", "viewer"])
def test_language_is_private_to_account_and_does_not_revoke_sessions_or_change_network(
    client: TestClient, tmp_path: Path, username: str
) -> None:
    user = login(client, username)
    assert user["language"] == "ru"
    before = client.get("/api/state").json()
    with sqlite3.connect(tmp_path / "auth.sqlite3") as db:
        identities = db.execute(
            "SELECT id,password_hash,role,enabled,version,totp_secret,totp_recovery FROM users "
            "ORDER BY id"
        ).fetchall()
    result = client.put("/api/me/preferences", headers=HEADERS, json={"language": "en"})
    assert result.status_code == 200 and result.json() == {"language": "en"}
    assert result.headers["cache-control"] == "no-store"
    assert client.get("/api/me/preferences").json() == {"language": "en"}
    assert client.get("/api/session").json()["user"]["language"] == "en"
    after = client.get("/api/state").json()
    assert after["revision"] == before["revision"] and after["config"] == before["config"]
    with sqlite3.connect(tmp_path / "auth.sqlite3") as db:
        assert (
            identities
            == db.execute(
                "SELECT id,password_hash,role,enabled,version,totp_secret,totp_recovery FROM users "
                "ORDER BY id"
            ).fetchall()
        )
    assert client.post("/api/logout", headers=HEADERS).status_code == 200
    assert login(client, "viewer" if username == "admin" else "admin")["language"] == "ru"
    client.post("/api/logout", headers=HEADERS)
    assert login(client, username)["language"] == "en"


def test_preferences_require_own_session_and_same_origin(client: TestClient) -> None:
    assert client.get("/api/me/preferences").status_code == 401
    assert (
        client.put("/api/me/preferences", headers=HEADERS, json={"language": "en"}).status_code
        == 401
    )
    login(client, "viewer")
    assert client.put("/api/me/preferences", json={"language": "en"}).status_code == 403
    assert (
        client.put(
            "/api/me/preferences",
            headers={**HEADERS, "Origin": "https://untrusted.example"},
            json={"language": "en"},
        ).status_code
        == 403
    )
    assert client.get("/api/me/preferences").json() == {"language": "ru"}


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"language": None},
        {"language": "EN"},
        {"language": "de"},
        {"language": 1},
        {"language": "en", "user_id": "another-user"},
        {"language": "en", "role": "full"},
    ],
)
def test_preference_payload_accepts_only_supported_language_for_self(
    client: TestClient, body: dict[str, object]
) -> None:
    login(client, "viewer")
    assert client.put("/api/me/preferences", headers=HEADERS, json=body).status_code == 422
    assert client.get("/api/me/preferences").json() == {"language": "ru"}


def test_language_migration_and_restart_preserve_security_fields(tmp_path: Path) -> None:
    path = tmp_path / "auth.sqlite3"
    digest = password_hash(PASSWORD)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE users (id TEXT PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,"
            "role TEXT,enabled INTEGER,created_at REAL,version INTEGER)"
        )
        db.execute(
            "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
            ("legacy", "admin", digest, "full", 1, 10.0, 3),
        )
    store = AuthStore(path)
    current = store.by_id("legacy")
    assert current and current.language == "ru" and current.version == 3
    assert current.password == digest
    auth = AuthService(tmp_path, True, "admin", "")
    token, _ = auth.login("admin", PASSWORD, "test-client")
    assert token
    auth.set_preferences(token, UserPreferences(language="en"))
    restarted = AuthService(tmp_path, True, "admin", "")
    token, user = restarted.login("admin", PASSWORD, "test-client")
    assert token and user and user.language == "en"
    assert restarted.require_store().by_id("legacy") == store.by_id("legacy")


def test_preferences_reject_logged_out_or_changed_original_identity(tmp_path: Path) -> None:
    auth = AuthService(tmp_path, True, "admin", PASSWORD, "viewer", PASSWORD)
    token, user = auth.login("viewer", PASSWORD, "test-client")
    assert token and user
    actor = auth.authorize(token)
    auth.logout(token)
    with pytest.raises(AuthError) as expired:
        auth.set_preferences(token, UserPreferences(language="en"))
    assert expired.value.status == 401
    auth.require_store().update(user.id, UserUpdate(username="changed"), None)
    with pytest.raises(AuthError) as changed:
        auth.require_store().set_preferences(actor, UserPreferences(language="en"))
    assert changed.value.status == 401
    current = auth.require_store().by_id(user.id)
    assert current and current.language == "ru"


def test_account_snapshots_restore_language_and_accept_old_backups(tmp_path: Path) -> None:
    auth = AuthService(tmp_path, True, "admin", PASSWORD)
    token, user = auth.login("admin", PASSWORD, "test-client")
    assert token and user
    auth.set_preferences(token, UserPreferences(language="en"))
    snapshots = AccountSnapshots(auth)
    exported = snapshots.export()
    assert exported[0].language == "en"
    auth.set_preferences(token, UserPreferences(language="ru"))
    snapshots.replace(snapshots.prepare(exported))
    restored = auth.require_store().by_id(user.id)
    assert restored and restored.language == "en"
    old = exported[0].model_dump(mode="json", exclude={"language"})
    legacy = AccountRow.model_validate(old)
    assert legacy.language == "ru"
    snapshots.replace(snapshots.prepare([legacy]))
    restored = auth.require_store().by_id(user.id)
    assert restored and restored.language == "ru"
