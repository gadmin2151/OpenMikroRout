"""Credential, revocation and admission boundaries using isolated account stores."""

import asyncio
import json
import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.auth import (
    MAX_SESSION_LOGINS_PER_MINUTE,
    MAX_SESSIONS_PER_USER,
    AuthError,
    AuthService,
    UserCreate,
    UserRecord,
    UserUpdate,
    password_hash,
)
from app.main import Settings, create_app
from app.totp import CredentialProof, code_at

PASSWORD = "boundary-test-administrator-password"
READER = "boundary-test-reader-password"
NEW_PASSWORD = "boundary-test-new-account-password"
HEADERS = {"X-NAT-Request": "1"}
PROOF = {"password": PASSWORD}


def authenticated_service(tmp_path: Path) -> tuple[AuthService, str]:
    auth = AuthService(tmp_path, True, "admin", PASSWORD, "viewer", READER)
    token, _ = auth.login("admin", PASSWORD, "admin")
    assert token
    return auth, token


def revoke(auth: AuthService, token: str, change: str) -> None:
    actor = auth.authorize(token)
    store = auth.require_store()
    if change == "logout":
        auth.logout(token)
    elif change == "revoke":
        auth.revoke_user(actor.id)
    else:
        # A second administrator exists for legitimate demotion/deletion.
        store.create(
            UserCreate(username="other-admin", password=SecretStr(PASSWORD), role="full"),
            password_hash(PASSWORD),
        )
        if change == "delete":
            store.delete(actor.id, None)
        else:
            update = UserUpdate(role="read") if change == "demote" else UserUpdate(enabled=False)
            store.update(actor.id, update, None)


def test_account_api_requires_actor_proof_for_every_mutation(tmp_path: Path) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, password=PASSWORD, read_password=READER, auth_enabled=True)
    )
    with TestClient(app) as client:
        client.post(
            "/api/login", headers=HEADERS, json={"username": "admin", "password": PASSWORD}
        ).raise_for_status()
        users = client.get("/api/users").json()["users"]
        viewer = next(user for user in users if user["username"] == "viewer")
        operations = [
            (
                "POST",
                "/api/users",
                {"username": "created", "password": NEW_PASSWORD, "role": "full"},
            ),
            ("PUT", f"/api/users/{viewer['id']}", {"password": NEW_PASSWORD, "role": "full"}),
            ("DELETE", f"/api/users/{viewer['id']}", {}),
        ]
        for method, path, body in operations:
            assert client.request(method, path, headers=HEADERS, json=body).status_code == 422
            failed = client.request(
                method, path, headers=HEADERS, json={**body, "proof": {"password": NEW_PASSWORD}}
            )
            assert failed.status_code == 403
            assert NEW_PASSWORD not in failed.text
        assert client.get("/api/users").json()["users"] == users
        created = client.post(
            "/api/users", headers=HEADERS, json={**operations[0][2], "proof": PROOF}
        )
        assert created.status_code == 201
        assert (
            client.put(
                f"/api/users/{viewer['id']}", headers=HEADERS, json={"proof": PROOF}
            ).status_code
            == 422
        )
        assert (
            client.request(
                "DELETE",
                f"/api/users/{created.json()['id']}",
                headers=HEADERS,
                json={"proof": PROOF},
            ).status_code
            == 200
        )


def test_account_api_requires_fresh_totp_and_does_not_accept_new_account_password(
    tmp_path: Path,
) -> None:
    app = create_app(Settings(data_dir=tmp_path, password=PASSWORD, auth_enabled=True))
    with TestClient(app) as client:
        client.post(
            "/api/login", headers=HEADERS, json={"username": "admin", "password": PASSWORD}
        ).raise_for_status()
        setup = client.post("/api/me/totp/setup", headers=HEADERS, json=PROOF).json()
        auth: AuthService = app.state.auth
        code = code_at(setup["secret"], int(auth.clock() // 30))
        confirmation = client.post(
            "/api/me/totp/confirm", headers=HEADERS, json={**PROOF, "code": code}
        )
        confirmation.raise_for_status()
        recovery = confirmation.json()["recovery_codes"][0]
        payload = {"username": "created", "password": NEW_PASSWORD, "role": "full"}
        for proof in (PROOF, {**PROOF, "code": code}, {"password": NEW_PASSWORD, "code": recovery}):
            assert (
                client.post(
                    "/api/users", headers=HEADERS, json={**payload, "proof": proof}
                ).status_code
                == 403
            )
        created = client.post(
            "/api/users", headers=HEADERS, json={**payload, "proof": {**PROOF, "code": recovery}}
        )
        assert created.status_code == 201
        assert (
            client.put(
                f"/api/users/{created.json()['id']}",
                headers=HEADERS,
                json={"enabled": False, "proof": {**PROOF, "code": recovery}},
            ).status_code
            == 403
        )


@pytest.mark.parametrize("change", ["logout", "revoke", "demote", "disable", "delete"])
@pytest.mark.parametrize("path", ["/api/users", "/api/configuration/backup", "/api/config"])
def test_streamed_body_cannot_outlive_original_authorization(
    tmp_path: Path, change: str, path: str
) -> None:
    app = create_app(Settings(data_dir=tmp_path, password=PASSWORD, auth_enabled=True))
    auth: AuthService = app.state.auth
    token, _ = auth.login("admin", PASSWORD, "admin")
    assert token
    with TestClient(app):
        body: dict[str, Any]
        if path == "/api/users":
            body = {
                "username": "late-admin",
                "password": NEW_PASSWORD,
                "role": "full",
                "proof": PROOF,
            }
        elif path == "/api/configuration/backup":
            body = {"archive_password": NEW_PASSWORD, "proof": PROOF}
        else:
            state = app.state.service.state()
            body = {"revision": state["revision"], "config": state["config"]}
        revision = app.state.service.state()["revision"]

        async def run() -> int:
            waiting = asyncio.Event()
            release = asyncio.Event()
            encoded = json.dumps(body).encode()

            async def stream() -> AsyncIterator[bytes]:
                yield encoded[:1]
                waiting.set()
                await release.wait()
                yield encoded[1:]

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                request = asyncio.create_task(
                    client.request(
                        "PUT" if path == "/api/config" else "POST",
                        path,
                        headers={
                            **HEADERS,
                            "Cookie": f"nat_session={token}",
                            "Content-Type": "application/json",
                        },
                        content=stream(),
                    )
                )
                await asyncio.wait_for(waiting.wait(), 5)
                revoke(auth, token, change)
                release.set()
                return (await asyncio.wait_for(request, 5)).status_code

        assert asyncio.run(run()) == 401
        assert auth.require_store().by_name("late-admin") is None
        assert app.state.service.state()["revision"] == revision


@pytest.mark.parametrize("change", ["logout", "revoke", "demote", "disable", "delete"])
def test_account_write_rechecks_token_and_actor_after_password_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    auth, token = authenticated_service(tmp_path)
    waiting = threading.Event()
    release = threading.Event()

    def slow_hash(password: str) -> str:
        waiting.set()
        assert release.wait(5)
        return password_hash(password)

    monkeypatch.setattr("app.auth.password_hash", slow_hash)
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(
            auth.create,
            UserCreate(username="late-admin", password=SecretStr(NEW_PASSWORD), role="full"),
            token=token,
            proof=CredentialProof.model_validate(PROOF),
            client="admin",
        )
        assert waiting.wait(5)
        revoke(auth, token, change)
        release.set()
        with pytest.raises(AuthError) as error:
            result.result(timeout=5)
        assert error.value.status == 401
    assert auth.require_store().by_name("late-admin") is None


def test_privileged_proof_checks_current_role_but_read_self_security_remains_available(
    tmp_path: Path,
) -> None:
    auth, token = authenticated_service(tmp_path)
    actor = auth.authorize(token).public()
    revoke(auth, token, "demote")
    read_token, _ = auth.login("admin", PASSWORD, "new-login")
    assert read_token
    with pytest.raises(AuthError) as error:
        auth.reauthenticate(
            actor,
            CredentialProof.model_validate(PROOF),
            "proof",
            token=read_token,
            required_role="full",
        )
    assert error.value.status == 403
    assert (
        auth.reauthenticate(
            actor, CredentialProof.model_validate(PROOF), "self", token=read_token
        ).role
        == "read"
    )


def test_reader_session_churn_only_replaces_own_tokens_and_preserves_admin_capacity(
    tmp_path: Path,
) -> None:
    auth, admin_token = authenticated_service(tmp_path)
    reader_tokens = [
        auth.login("viewer", READER, "shared-proxy")[0]
        for _ in range(MAX_SESSION_LOGINS_PER_MINUTE)
    ]
    assert len(auth.sessions) == MAX_SESSIONS_PER_USER + 1
    assert all(
        token and auth.resolve(token) is None for token in reader_tokens[:-MAX_SESSIONS_PER_USER]
    )
    assert all(token and auth.resolve(token) for token in reader_tokens[-MAX_SESSIONS_PER_USER:])
    with pytest.raises(AuthError, match="Too many new sessions"):
        auth.login("viewer", READER, "shared-proxy")
    assert auth.resolve(admin_token)
    assert auth.login("admin", PASSWORD, "shared-proxy")[0]


@pytest.mark.parametrize("factor", ["totp", "recovery"])
def test_capacity_failure_does_not_consume_one_time_factor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, factor: str
) -> None:
    now = [1_700_000_010.0]
    auth = AuthService(tmp_path, True, "admin", PASSWORD, "viewer", READER, clock=lambda: now[0])
    initial_token, actor = auth.login("admin", PASSWORD, "admin")
    assert actor and initial_token
    setup = auth.totp_setup(
        actor, CredentialProof.model_validate(PROOF), "setup", token=initial_token
    )
    recovery, admin_token = auth.totp_confirm(
        actor,
        CredentialProof(
            password=SecretStr(PASSWORD),
            code=SecretStr(code_at(setup.secret, int(now[0] // 30))),
        ),
        "confirm",
        token=initial_token,
    )
    auth.logout(admin_token)
    reader_token, _ = auth.login("viewer", READER, "reader")
    assert reader_token
    monkeypatch.setattr("app.auth.MAX_SESSIONS", 1)
    now[0] += 30
    code = (
        code_at(setup.secret, int(now[0] // 30)) if factor == "totp" else recovery.recovery_codes[0]
    )
    before = auth.require_store().by_id(actor.id)
    with pytest.raises(AuthError, match="Session limit"):
        auth.login("admin", PASSWORD, "admin", code)
    assert auth.require_store().by_id(actor.id) == before
    assert auth.resolve(reader_token)
    auth.logout(reader_token)
    assert auth.login("admin", PASSWORD, "admin", code)[0]


def test_concurrent_session_replacement_keeps_per_identity_bound(tmp_path: Path) -> None:
    auth, admin_token = authenticated_service(tmp_path)

    def churn(_: int) -> None:
        for _ in range(MAX_SESSIONS_PER_USER + 1):
            auth.login("viewer", READER, "reader")

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(churn, [1, 2]))
    assert len(auth.sessions) == MAX_SESSIONS_PER_USER + 1
    assert auth.resolve(admin_token)
    assert auth.login("admin", PASSWORD, "admin")[0]


def test_unknown_identity_churn_cannot_evict_known_account_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth, token = authenticated_service(tmp_path)
    for _ in range(5):
        with pytest.raises(AuthError) as error:
            auth.login("viewer", "incorrect", "proxy")
        assert error.value.status == 401
    monkeypatch.setattr("app.auth.MAX_ATTEMPT_KEYS", 8)
    assert auth.hash_slots.acquire(blocking=False)
    assert auth.hash_slots.acquire(blocking=False)
    try:
        for index in range(20):
            with pytest.raises(AuthError) as error:
                auth.login(f"unknown-{index}", "incorrect", f"peer-{index}")
            assert error.value.status == 429
    finally:
        auth.hash_slots.release()
        auth.hash_slots.release()
    assert len(auth.unknown_attempts) == 8
    with pytest.raises(AuthError, match="Too many attempts"):
        auth.login("VIEWER", READER, "proxy")
    assert auth.login("viewer", READER, "different-peer")[0]
    assert auth.resolve(token)
    assert auth.login("admin", PASSWORD, "proxy")[0]


@pytest.mark.parametrize("path", ["/api/users", "/api/configuration/inspect"])
def test_body_deadline_returns_408_without_mutation_or_revoking_valid_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.setattr("app.main.REQUEST_BODY_SECONDS", 0.01)
    app = create_app(Settings(data_dir=tmp_path, password=PASSWORD, auth_enabled=True))
    auth: AuthService = app.state.auth
    token, _ = auth.login("admin", PASSWORD, "admin")
    assert token

    async def run() -> httpx.Response:
        async def stalled() -> AsyncIterator[bytes]:
            yield b"{"
            await asyncio.sleep(1)
            yield b"}"

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            return await client.post(
                path,
                headers={
                    **HEADERS,
                    "Cookie": f"nat_session={token}",
                    "Content-Type": "application/json",
                },
                content=stalled(),
            )

    with TestClient(app) as client:
        revision = app.state.service.state()["revision"]
        response = asyncio.run(run())
        assert response.status_code == 408
        assert response.json() == {"detail": "Request body timed out"}
        assert response.headers["cache-control"] == "no-store"
        assert app.state.service.state()["revision"] == revision
        assert auth.resolve(token)
        valid = client.post(
            "/api/users",
            headers={**HEADERS, "Cookie": f"nat_session={token}"},
            json={"username": "normal", "password": NEW_PASSWORD, "proof": PROOF},
        )
        assert valid.status_code == 201


@pytest.mark.parametrize("operation", ["setup", "confirm", "disable"])
@pytest.mark.parametrize("change", ["logout", "revoke", "version"])
@pytest.mark.parametrize("pause", ["password", "after_proof"])
def test_self_totp_mutation_remains_bound_to_original_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, change: str, pause: str
) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, password=PASSWORD, read_password=READER, auth_enabled=True)
    )
    auth: AuthService = app.state.auth
    token, actor = auth.login("viewer", READER, "reader")
    assert token and actor
    body = {"password": READER}
    waiting = threading.Event()
    release = threading.Event()
    with TestClient(app) as client:
        if operation != "setup":
            setup = client.post(
                "/api/me/totp/setup",
                headers={**HEADERS, "Cookie": f"nat_session={token}"},
                json=body,
            )
            setup.raise_for_status()
            body["code"] = code_at(setup.json()["secret"], int(auth.clock() // 30))
            if operation == "disable":
                confirmation = client.post(
                    "/api/me/totp/confirm",
                    headers={**HEADERS, "Cookie": f"nat_session={token}"},
                    json=body,
                )
                confirmation.raise_for_status()
                token = client.cookies["nat_session"]
                body["code"] = confirmation.json()["recovery_codes"][0]

        def pause_here() -> None:
            waiting.set()
            assert release.wait(5)

        if pause == "password":
            original_password = auth._password

            def held_password(*args: Any, **kwargs: Any) -> bool:
                pause_here()
                return original_password(*args, **kwargs)

            monkeypatch.setattr(auth, "_password", held_password)
        else:
            original_proof = auth.reauthenticate

            def held_proof(*args: Any, **kwargs: Any) -> UserRecord:
                verified = original_proof(*args, **kwargs)
                pause_here()
                return verified

            monkeypatch.setattr(auth, "reauthenticate", held_proof)

        assert token is not None
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(
                client.post,
                f"/api/me/totp/{operation}",
                headers={**HEADERS, "Cookie": f"nat_session={token}"},
                json=body,
            )
            assert waiting.wait(5)
            if change == "logout":
                auth.logout(token)
            elif change == "revoke":
                auth.revoke_user(actor.id)
            else:
                auth.require_store().update(actor.id, UserUpdate(username="renamed-viewer"), None)
            before_release = auth.require_store().by_id(actor.id)
            release.set()
            response = result.result(timeout=5)
        assert response.status_code == 401
        assert "set-cookie" not in response.headers
        assert auth.require_store().by_id(actor.id) == before_release
        assert all(session.user_id != actor.id for session in auth.sessions.values())


def test_login_and_proof_failures_are_isolated_between_independent_peers(tmp_path: Path) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, password=PASSWORD, read_password=READER, auth_enabled=True)
    )
    with (
        TestClient(app, client=("198.51.100.10", 41000)) as first,
        closing(TestClient(app, client=("198.51.100.20", 42000))) as second,
    ):
        for _ in range(5):
            assert (
                first.post(
                    "/api/login", headers=HEADERS, json={"username": "viewer", "password": "wrong"}
                ).status_code
                == 401
            )
        assert (
            first.post(
                "/api/login",
                headers={**HEADERS, "X-Forwarded-For": "198.51.100.20"},
                json={"username": "viewer", "password": READER},
            ).status_code
            == 429
        )
        assert (
            second.post(
                "/api/login", headers=HEADERS, json={"username": "viewer", "password": READER}
            ).status_code
            == 200
        )
        # A successful login at the other peer does not erase the first peer's window.
        assert (
            first.post(
                "/api/login", headers=HEADERS, json={"username": "viewer", "password": READER}
            ).status_code
            == 429
        )
        for client in (first, second):
            assert (
                client.post(
                    "/api/login", headers=HEADERS, json={"username": "admin", "password": PASSWORD}
                ).status_code
                == 200
            )
        for _ in range(5):
            assert (
                first.post(
                    "/api/me/totp/setup", headers=HEADERS, json={"password": "wrong"}
                ).status_code
                == 403
            )
        assert first.post("/api/me/totp/setup", headers=HEADERS, json=PROOF).status_code == 429
        assert second.post("/api/me/totp/setup", headers=HEADERS, json=PROOF).status_code == 200
