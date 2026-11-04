import base64
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.auth import AuthError, AuthService, AuthStore, UserCreate, password_hash
from app.main import Settings, create_app
from app.totp import CredentialProof, TotpVault, code_at, matching_counter

PASSWORD = "test-only-authenticator-password"
HEADERS = {"X-NAT-Request": "1"}


def service(tmp_path: Path) -> tuple[AuthService, list[float]]:
    now = [1_700_000_010.0]
    return AuthService(tmp_path, True, "admin", PASSWORD, clock=lambda: now[0]), now


def enroll(auth: AuthService) -> tuple[str, list[str]]:
    token, actor = auth.login("admin", PASSWORD, "initial-login")
    assert actor and token
    setup = auth.totp_setup(actor, CredentialProof(password=SecretStr(PASSWORD)), "setup")
    code = code_at(setup.secret, int(auth.clock() // 30))
    result, token = auth.totp_confirm(
        actor, CredentialProof(password=SecretStr(PASSWORD), code=SecretStr(code)), "confirm"
    )
    assert auth.resolve(token) and auth.resolve(token).totp_enabled  # type: ignore[union-attr]
    return setup.secret, result.recovery_codes


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ],
)
def test_rfc6238_sha1_vectors(timestamp: int, expected: str) -> None:
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert code_at(secret, timestamp // 30, digits=8) == expected


def test_encryption_binds_user_and_purpose_and_requires_private_key(tmp_path: Path) -> None:
    vault = TotpVault(tmp_path / "key")
    ciphertext = vault.encrypt("one", "active", "SECRET")
    assert "SECRET" not in ciphertext
    assert vault.decrypt("one", "active", ciphertext) == "SECRET"
    for user, purpose in [("two", "active"), ("one", "pending")]:
        with pytest.raises(RuntimeError, match="Cannot decrypt"):
            vault.decrypt(user, purpose, ciphertext)
    with pytest.raises(RuntimeError, match="missing"):
        TotpVault(tmp_path / "missing", required=True)
    (tmp_path / "key").chmod(0o644)
    with pytest.raises(RuntimeError, match="private regular"):
        TotpVault(tmp_path / "key")


def test_window_rejects_replay_and_malformed_code() -> None:
    secret = base64.b32encode(b"12345678901234567890").decode()
    counter = 100
    assert matching_counter(secret, code_at(secret, counter), 3000) == counter
    assert matching_counter(secret, code_at(secret, counter - 1), 3000) == counter - 1
    assert matching_counter(secret, code_at(secret, counter), 3000, last=counter) is None
    assert matching_counter(secret, code_at(secret, counter - 2), 3000) is None
    for value in ["", "12345", "1234567", "１２３４５６", "abcdef"]:
        assert matching_counter(secret, value, 3000) is None


def test_migration_preserves_identity_password_and_defaults_to_disabled(tmp_path: Path) -> None:
    path = tmp_path / "auth.sqlite3"
    digest = password_hash(PASSWORD)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE users (id TEXT PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,"
            "role TEXT,enabled INTEGER,created_at REAL,version INTEGER)"
        )
        db.execute(
            "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
            ("existing", "admin", digest, "full", 1, 1, 2),
        )
    store = AuthStore(path)
    user = store.by_id("existing")
    assert user and user.version == 2 and user.password == digest and not user.totp_secret
    auth = AuthService(tmp_path, True, "admin", "")
    token, actor = auth.login("admin", PASSWORD, "one")
    assert token and actor and not actor.totp_enabled


def test_enable_revoke_replay_recovery_and_restart(tmp_path: Path) -> None:
    auth, now = service(tmp_path)
    old, _ = auth.login("admin", PASSWORD, "before")
    secret, recovery = enroll(auth)
    assert old and auth.resolve(old) is None
    assert len(recovery) == 8 and len(set(recovery)) == 8
    for code in ["", "000000", code_at(secret, int(now[0] // 30))]:
        with pytest.raises(AuthError):
            auth.login("admin", PASSWORD, "invalid-" + code, code)
    now[0] += 30
    code = code_at(secret, int(now[0] // 30))
    token, user = auth.login("admin", PASSWORD, "valid", code)
    assert token and user and user.totp_enabled
    with pytest.raises(AuthError):
        auth.login("admin", PASSWORD, "replay", code)
    restored = AuthService(tmp_path, True, "admin", "", clock=lambda: now[0])
    with pytest.raises(AuthError):
        restored.login("admin", PASSWORD, "after-restart", code)
    token, _ = restored.login("admin", PASSWORD, "recovery", recovery[0])
    assert token
    with pytest.raises(AuthError):
        restored.login("admin", PASSWORD, "used-recovery", recovery[0])
    with sqlite3.connect(tmp_path / "auth.sqlite3") as db:
        stored = db.execute("SELECT totp_secret,totp_recovery FROM users").fetchone()
    assert secret not in stored[0] and recovery[0] not in stored[1]


def test_concurrent_code_is_accepted_once(tmp_path: Path) -> None:
    auth, now = service(tmp_path)
    secret, _ = enroll(auth)
    now[0] += 30
    code = code_at(secret, int(now[0] // 30))

    def attempt(index: int) -> bool:
        try:
            return bool(auth.login("admin", PASSWORD, f"client-{index}", code)[0])
        except AuthError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(attempt, [1, 2])) == 1


def test_confirmation_code_attempts_are_bounded_and_setup_expires(tmp_path: Path) -> None:
    auth, now = service(tmp_path)
    _, actor = auth.login("admin", PASSWORD, "login")
    assert actor
    setup = auth.totp_setup(actor, CredentialProof(password=SecretStr(PASSWORD)), "setup")
    valid = code_at(setup.secret, int(now[0] // 30))
    wrong = "111111" if valid != "111111" else "222222"
    proof = CredentialProof(password=SecretStr(PASSWORD), code=SecretStr(wrong))
    for _ in range(5):
        with pytest.raises(AuthError) as error:
            auth.totp_confirm(actor, proof, "same")
        assert error.value.status == 400
    with pytest.raises(AuthError) as error:
        auth.totp_confirm(actor, proof, "same")
    assert error.value.status == 429
    now[0] += 601
    with pytest.raises(AuthError) as error:
        auth.totp_confirm(actor, proof, "expired")
    assert error.value.status == 409


def test_read_user_can_enroll_self_but_cannot_reset_or_write_config(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path, auth_enabled=True, password=PASSWORD, read_password=PASSWORD
    )
    with TestClient(create_app(settings)) as client:
        assert (
            client.post(
                "/api/login", headers=HEADERS, json={"username": "viewer", "password": PASSWORD}
            ).status_code
            == 200
        )
        status = client.get("/api/me/totp")
        assert status.json() == {"enabled": False, "recovery_codes_remaining": 0}
        result = client.post("/api/me/totp/setup", headers=HEADERS, json={"password": PASSWORD})
        assert result.status_code == 200 and result.headers["cache-control"] == "no-store"
        setup = result.json()
        assert setup["qr_data_url"].startswith("data:image/svg+xml;base64,")
        assert "otpauth://totp/" in setup["provisioning_uri"]
        assert client.put("/api/config", headers=HEADERS, json={}).status_code == 403
        assert (
            client.post(
                "/api/users/anything/totp/reset", headers=HEADERS, json={"password": PASSWORD}
            ).status_code
            == 403
        )
        code = code_at(setup["secret"], int(__import__("time").time() // 30))
        confirmed = client.post(
            "/api/me/totp/confirm", headers=HEADERS, json={"password": PASSWORD, "code": code}
        )
        assert confirmed.status_code == 200 and len(confirmed.json()["recovery_codes"]) == 8
        assert client.get("/api/me/totp").json()["enabled"]
        assert client.get("/api/session").json()["user"]["totp_enabled"]
        assert setup["secret"] not in client.get("/api/state").text
        recovery = confirmed.json()["recovery_codes"][0]
        disabled = client.post(
            "/api/me/totp/disable", headers=HEADERS, json={"password": PASSWORD, "code": recovery}
        )
        assert disabled.status_code == 200
        assert not client.get("/api/me/totp").json()["enabled"]


def test_missing_key_fails_closed_and_admin_reset_requires_proof(tmp_path: Path) -> None:
    auth, _ = service(tmp_path)
    secret, recovery = enroll(auth)
    _, actor = auth.login("admin", PASSWORD, "recovery", recovery[0])
    assert actor
    target = auth.create(UserCreate(username="second", password=SecretStr(PASSWORD)))
    with pytest.raises(AuthError):
        auth.totp_reset(target.id, actor, CredentialProof(password=SecretStr("wrong")), "proof")
    with pytest.raises(AuthError):
        auth.totp_reset(target.id, actor, CredentialProof(password=SecretStr(PASSWORD)), "proof2")
    auth.totp_reset(
        target.id,
        actor,
        CredentialProof(password=SecretStr(PASSWORD), code=SecretStr(recovery[1])),
        "proof3",
    )
    (tmp_path / "totp.key").unlink()
    with pytest.raises(RuntimeError, match="missing"):
        AuthService(tmp_path, True, "admin", "")
