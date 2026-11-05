import base64
import time
from contextlib import closing
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.backup_archive import BackupError, decrypt_backup
from app.main import Settings, create_app
from app.totp import code_at

HEADERS = {"X-NAT-Request": "1"}
ADMIN = "test-only-administrator-password"
ARCHIVE = "test-only-backup-passphrase"


def login(client: TestClient, username: str = "admin", password: str = ADMIN) -> None:
    assert (
        client.post(
            "/api/login", headers=HEADERS, json={"username": username, "password": password}
        ).status_code
        == 200
    )


def make_backup(client: TestClient, password: str = ADMIN) -> bytes:
    response = client.post(
        "/api/configuration/backup",
        headers=HEADERS,
        json={
            "archive_password": ARCHIVE,
            "proof": {"password": password},
        },
    )
    assert response.status_code == 200, response.text
    return bytes(response.content)


def inspect(client: TestClient, blob: bytes) -> dict[str, Any]:
    revision = client.get("/api/state").json()["revision"]
    response = client.post(
        "/api/configuration/inspect",
        headers=HEADERS,
        json={
            "kind": "backup",
            "data": base64.b64encode(blob).decode(),
            "archive_password": ARCHIVE,
            "revision": revision,
        },
    )
    assert response.status_code == 200, response.text
    assert "password_hash" not in response.text and "totp_secret" not in response.text
    return {**response.json(), "revision": revision}


def stage(client: TestClient, preview: dict[str, Any], accounts: bool = True) -> None:
    response = client.post(
        "/api/configuration/stage",
        headers=HEADERS,
        json={
            "preview_id": preview["preview_id"],
            "revision": preview["revision"],
            "restore_accounts": accounts,
            "proof": {"password": ADMIN},
        },
    )
    assert response.status_code == 200, response.text


def apply(client: TestClient) -> dict[str, Any]:
    revision = client.get("/api/state").json()["revision"]
    response = client.post("/api/apply", headers=HEADERS, json={"revision": revision})
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json()["pending"])


def test_encrypted_backup_round_trip_and_tampering(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path, auth_enabled=True, password=ADMIN))
    with TestClient(app) as client:
        login(client)
        blob = make_backup(client)
        assert blob.startswith(b"OMRBACKUP") and ADMIN.encode() not in blob
        payload = decrypt_backup(blob, ARCHIVE)
        assert payload.accounts[0].username == "admin"
        assert payload.accounts[0].password_hash.encode() not in blob
        for raw, password in (
            (blob, "wrong"),
            (blob[:-1] + bytes([blob[-1] ^ 1]), ARCHIVE),
            (b"garbage", ARCHIVE),
        ):
            with pytest.raises(BackupError):
                decrypt_backup(raw, password)


def test_restore_accounts_waits_for_confirmation_and_invalidates_sessions(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path, auth_enabled=True, password=ADMIN))
    with TestClient(app) as client:
        login(client)
        blob = make_backup(client)
        assert (
            client.post(
                "/api/users",
                headers=HEADERS,
                json={"username": "later", "password": "test-only-extra-account", "role": "read"},
            ).status_code
            == 201
        )
        preview = inspect(client, blob)
        stage(client, preview)
        state = client.get("/api/state").json()
        assert state["dirty"] and state["restore_accounts"]
        assert len(client.get("/api/users").json()["users"]) == 2
        # Startup reconciliation must never confirm an un-applied restore plan,
        # even if the router configuration is identical to the current one.
        app.state.service.restore_confirmed()
        assert len(client.get("/api/users").json()["users"]) == 2
        assert client.get("/api/state").json()["restore_accounts"]
        pending = apply(client)
        assert len(client.get("/api/users").json()["users"]) == 2
        confirmed = client.post("/api/confirm", headers=HEADERS, json={"token": pending["token"]})
        assert confirmed.status_code == 200 and confirmed.json()["reauthenticate"]
        assert client.get("/api/state").status_code == 401
        login(client)
        assert len(client.get("/api/users").json()["users"]) == 1


def test_rollback_before_confirmation_keeps_current_accounts(tmp_path: Path) -> None:
    with TestClient(
        create_app(Settings(data_dir=tmp_path, auth_enabled=True, password=ADMIN))
    ) as client:
        login(client)
        blob = make_backup(client)
        client.post(
            "/api/users",
            headers=HEADERS,
            json={"username": "later", "password": "test-only-extra-account", "role": "read"},
        )
        stage(client, inspect(client, blob))
        apply(client)
        assert client.post("/api/rollback", headers=HEADERS).status_code == 200
        assert len(client.get("/api/users").json()["users"]) == 2


def test_restart_recovers_accounts_if_confirm_was_interrupted(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path, auth_enabled=True, password=ADMIN))
    with TestClient(app, raise_server_exceptions=False) as client:
        login(client)
        blob = make_backup(client)
        client.post(
            "/api/users",
            headers=HEADERS,
            json={"username": "later", "password": "test-only-extra-account", "role": "read"},
        )
        stage(client, inspect(client, blob))
        pending = apply(client)
        write = app.state.service.store.write

        def fail_confirm(values: dict[str, Any], event: str, detail: str = "") -> None:
            if event == "confirmed":
                raise OSError("simulated interrupted durable confirmation")
            write(values, event, detail)

        with patch.object(app.state.service.store, "write", side_effect=fail_confirm):
            assert (
                client.post(
                    "/api/confirm", headers=HEADERS, json={"token": pending["token"]}
                ).status_code
                == 500
            )
        # A retried confirm must retain the first undo image, including "later".
        with patch.object(app.state.service.store, "write", side_effect=fail_confirm):
            login(client)
            assert (
                client.post(
                    "/api/confirm", headers=HEADERS, json={"token": pending["token"]}
                ).status_code
                == 500
            )
        app.state.service.recover(startup=True)
        login(client)
        assert len(client.get("/api/users").json()["users"]) == 2


def test_exports_read_access_but_backup_and_import_need_full(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        auth_enabled=True,
        password=ADMIN,
        read_password="test-only-reader-password",
    )
    with TestClient(create_app(settings)) as client:
        login(client, "viewer", "test-only-reader-password")
        assert client.get("/api/configuration/export").text.startswith("# OpenMikroRout RSC 1")
        for path, body in (
            ("backup", {"archive_password": ARCHIVE}),
            ("inspect", {"kind": "rsc", "data": "", "revision": 0}),
            ("stage", {"preview_id": "x" * 32, "revision": 0}),
        ):
            assert (
                client.post("/api/configuration/" + path, headers=HEADERS, json=body).status_code
                == 403
            )


def test_rsc_preview_bound_to_revision(tmp_path: Path) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        text = client.get("/api/configuration/export?kind=rsc&source=draft").text
        preview = client.post(
            "/api/configuration/inspect",
            headers=HEADERS,
            json={"kind": "rsc", "data": text, "revision": 0},
        ).json()
        config = client.get("/api/state").json()["config"]
        client.put("/api/config", headers=HEADERS, json={"config": config, "revision": 0})
        assert (
            client.post(
                "/api/configuration/stage",
                headers=HEADERS,
                json={"preview_id": preview["preview_id"], "revision": 1},
            ).status_code
            == 409
        )


def test_import_preview_is_actor_bound_and_restore_can_keep_current_users(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path, auth_enabled=True, password=ADMIN))
    with TestClient(app) as first, closing(TestClient(app)) as second:
        login(first)
        blob = make_backup(first)
        first.post(
            "/api/users",
            headers=HEADERS,
            json={"username": "second", "password": ADMIN, "role": "full"},
        ).raise_for_status()
        preview = inspect(first, blob)
        login(second, "second")
        forbidden = second.post(
            "/api/configuration/stage",
            headers=HEADERS,
            json={
                "preview_id": preview["preview_id"],
                "revision": preview["revision"],
                "proof": {"password": ADMIN},
            },
        )
        assert forbidden.status_code == 409
        stage(first, preview, accounts=False)
        pending = apply(first)
        confirmed = first.post("/api/confirm", headers=HEADERS, json={"token": pending["token"]})
        assert confirmed.status_code == 200 and not confirmed.json()["reauthenticate"]
        assert first.get("/api/state").status_code == 200
        assert second.get("/api/state").status_code == 200
        assert len(first.get("/api/users").json()["users"]) == 2


def test_wireguard_and_totp_restore_with_different_destination_master_keys(tmp_path: Path) -> None:
    source = create_app(Settings(data_dir=tmp_path / "source", auth_enabled=True, password=ADMIN))
    target = create_app(Settings(data_dir=tmp_path / "target", auth_enabled=True, password=ADMIN))
    now = [float(int(time.time() // 30) * 30 + 5)]
    source.state.service.participant.auth.clock = lambda: now[0]
    target.state.service.participant.auth.clock = lambda: now[0]
    with TestClient(source) as original, TestClient(target) as restored:
        login(original)
        result = original.post(
            "/api/wireguard/server",
            headers=HEADERS,
            json={"revision": 0, "endpoint": "vpn.example.test"},
        )
        assert result.status_code == 200, result.text
        result = original.post(
            "/api/wireguard/peers",
            headers=HEADERS,
            json={"revision": 1, "interface": "wg-server", "name": "Phone"},
        )
        assert result.status_code == 200, result.text
        peer_id = result.json()["config"]["network"]["wireguard_peers"][0]["id"]
        profile = original.post(
            "/api/wireguard/export",
            headers=HEADERS,
            json={"object_id": peer_id, "proof": {"password": ADMIN}},
        ).json()["configuration"]
        pending = apply(original)
        assert (
            original.post(
                "/api/confirm", headers=HEADERS, json={"token": pending["token"]}
            ).status_code
            == 200
        )
        setup = original.post(
            "/api/me/totp/setup", headers=HEADERS, json={"password": ADMIN}
        ).json()
        secret = setup["secret"]
        assert (
            original.post(
                "/api/me/totp/confirm",
                headers=HEADERS,
                json={"password": ADMIN, "code": code_at(secret, int(now[0] // 30))},
            ).status_code
            == 200
        )
        now[0] += 30
        response = original.post(
            "/api/configuration/backup",
            headers=HEADERS,
            json={
                "archive_password": ARCHIVE,
                "proof": {"password": ADMIN, "code": code_at(secret, int(now[0] // 30))},
            },
        )
        assert response.status_code == 200, response.text
        blob = bytes(response.content)
        assert secret.encode() not in blob
        login(restored)
        preview = inspect(restored, blob)
        assert preview["accounts"][0]["totp_enabled"] and preview["private_keys"] == 3
        stage(restored, preview)
        pending = apply(restored)
        assert (
            restored.post(
                "/api/confirm", headers=HEADERS, json={"token": pending["token"]}
            ).status_code
            == 200
        )
        now[0] += 30
        assert (
            restored.post(
                "/api/login", headers=HEADERS, json={"username": "admin", "password": ADMIN}
            ).status_code
            == 401
        )
        assert (
            restored.post(
                "/api/login",
                headers=HEADERS,
                json={
                    "username": "admin",
                    "password": ADMIN,
                    "code": code_at(secret, int(now[0] // 30)),
                },
            ).status_code
            == 200
        )
        now[0] += 30
        response = restored.post(
            "/api/wireguard/export",
            headers=HEADERS,
            json={
                "object_id": peer_id,
                "proof": {"password": ADMIN, "code": code_at(secret, int(now[0] // 30))},
            },
        )
        assert response.status_code == 200 and response.json()["configuration"] == profile
        assert (tmp_path / "source" / "totp.key").read_bytes() != (
            tmp_path / "target" / "totp.key"
        ).read_bytes()
        assert (tmp_path / "source" / "demo-wireguard.key").read_bytes() != (
            tmp_path / "target" / "demo-wireguard.key"
        ).read_bytes()


def test_legacy_json_keeps_omitted_router_sections_and_web_domain(tmp_path: Path) -> None:
    import json

    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        original = client.get("/api/state").json()["config"]
        raw = {"version": 1, "config": {"rules": [], "address_lists": original["address_lists"]}}
        preview = client.post(
            "/api/configuration/inspect",
            headers=HEADERS,
            json={"kind": "json", "data": json.dumps(raw), "revision": 0},
        )
        assert preview.status_code == 200
        response = client.post(
            "/api/configuration/stage",
            headers=HEADERS,
            json={"preview_id": preview.json()["preview_id"], "revision": 0},
        )
        assert response.status_code == 200
        actual = response.json()["config"]
        assert actual["rules"] == [] and actual["network"] == original["network"]
        assert actual["filter_rules"] == original["filter_rules"]
        assert actual["web_domain"] == original["web_domain"]


def test_archive_decompression_is_bounded() -> None:
    import zlib

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from app.backup_archive import MAGIC, MAX_PLAINTEXT, derive_key

    salt, nonce = b"s" * 16, b"n" * 12
    cipher = AESGCM(derive_key(ARCHIVE, salt)).encrypt(
        nonce, zlib.compress(b"x" * (MAX_PLAINTEXT + 1)), MAGIC
    )
    with pytest.raises(BackupError):
        decrypt_backup(MAGIC + salt + nonce + cipher, ARCHIVE)


def test_large_backup_preview_is_not_limited_to_the_smaller_text_format(tmp_path: Path) -> None:
    from app.backup_archive import BackupPayload, encrypt_backup
    from app.models import Configuration
    from app.rsc import MAX_SCRIPT, ScriptError, export_rsc
    from app.version import VERSION

    config = Configuration.model_validate(
        {
            "rules": [
                {"name": str(i), "enabled": False, "action": "accept", "comment": "界" * 200}
                for i in range(512)
            ],
            "filter_rules": [
                {"name": str(i), "enabled": False, "comment": "界" * 200} for i in range(512)
            ],
            "network": {
                "dns_static": [
                    {"name": f"host{i}.test", "address": "192.0.2.1", "comment": "界" * 200}
                    for i in range(512)
                ]
            },
        }
    )
    with pytest.raises(ScriptError):
        export_rsc(config)
    payload = BackupPayload(
        version=VERSION,
        created_at=time.time(),
        hostname="test",
        config=config,
        accounts=[],
        keys=[],
    )
    app = create_app(Settings(data_dir=tmp_path))
    app.state.service.store.write(
        {"config": config.model_dump(mode="json"), "applied": config.model_dump(mode="json")},
        "test_large_configuration",
    )
    with TestClient(app) as client:
        for kind in ("rsc", "json"):
            response = client.get(f"/api/configuration/export?kind={kind}")
            assert response.status_code == 409 and "backup" in response.text
        preview = inspect(client, encrypt_backup(payload, ARCHIVE))
        assert len(preview["script"].encode()) > MAX_SCRIPT
        assert preview["after"]["rules"] == 512


def test_private_key_collision_rolls_back_all_imported_keys(tmp_path: Path) -> None:
    from uuid import uuid4

    from pydantic import SecretStr

    from app.wireguard_keys import generate_key
    from app.wireguard_vault import WireGuardVault

    vault = WireGuardVault(tmp_path)
    old = vault.create("interface")
    original = vault.secret(old.id, "interface")
    other, _ = generate_key("interface")
    inserted = uuid4()
    with pytest.raises(ValueError, match="conflict"):
        vault.import_keys(
            [(inserted, "interface", SecretStr(other)), (old.id, "interface", SecretStr(other))]
        )
    assert vault.secret(old.id, "interface") == original
    with pytest.raises(ValueError, match="missing"):
        vault.metadata(inserted, "interface")
