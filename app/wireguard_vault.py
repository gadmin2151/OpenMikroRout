"""Encrypted WireGuard key storage, separate from exported router configuration."""

import hmac
import os
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from pydantic import BaseModel, SecretStr

from app.totp import TotpVault
from app.wireguard_keys import KeyKind, derive_public, generate_key, key_bytes

if TYPE_CHECKING:
    from collections.abc import Iterator

    from app.network_models import NetworkConfiguration

MAX_KEYS = 10000


class WireGuardKey(BaseModel):
    id: UUID
    kind: KeyKind
    public_key: str
    created_at: float


class WireGuardVault:
    def __init__(self, data_dir: Path, *, demo: bool = False) -> None:
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        stem = "demo-wireguard" if demo else "wireguard"
        self.path = data_dir / (stem + ".sqlite3")
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        if self.path.is_symlink() or not self.path.is_file() or self.path.stat().st_mode & 0o077:
            raise RuntimeError("WireGuard vault must be a private regular database (0600)")
        with self.connection(write=True) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS keys ("
                "id TEXT PRIMARY KEY, kind TEXT NOT NULL, public_key TEXT NOT NULL, "
                "encrypted TEXT NOT NULL, created_at REAL NOT NULL)"
            )
            required = db.execute("SELECT EXISTS(SELECT 1 FROM keys)").fetchone()[0] == 1
        try:
            self.cipher = TotpVault(data_dir / (stem + ".key"), required=required)
        except RuntimeError as exc:
            raise RuntimeError(
                "WireGuard encryption key is unavailable; restore its private backup"
            ) from exc

    @contextmanager
    def connection(self, *, write: bool = False) -> "Iterator[sqlite3.Connection]":
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            if write:
                with db:
                    yield db
            else:
                yield db

    def create(self, kind: KeyKind, value: SecretStr | None = None) -> WireGuardKey:
        if value is None:
            secret, public = generate_key(kind)
        else:
            secret = value.get_secret_value().strip()
            key_bytes(secret)
            public = "" if kind == "preshared" else derive_public(secret)
        key_id = uuid4()
        encrypted = self.cipher.encrypt(str(key_id), kind, secret)
        created = time.time()
        with self.connection(write=True) as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM keys").fetchone()[0] >= MAX_KEYS:
                raise ValueError("WireGuard key vault is full; review retained keys and backups")
            db.execute(
                "INSERT INTO keys (id,kind,public_key,encrypted,created_at) VALUES (?,?,?,?,?)",
                (str(key_id), kind, public, encrypted, created),
            )
        return WireGuardKey(id=key_id, kind=kind, public_key=public, created_at=created)

    def metadata(self, key_id: UUID, kind: KeyKind) -> WireGuardKey:
        with self.connection() as db:
            row = db.execute(
                "SELECT id,kind,public_key,created_at FROM keys WHERE id=? AND kind=?",
                (str(key_id), kind),
            ).fetchone()
        if row is None:
            raise ValueError("WireGuard key is missing; import its private configuration first")
        return WireGuardKey(**dict(row))

    def import_keys(self, materials: list[tuple[UUID, KeyKind, SecretStr]]) -> None:
        """Import a complete backup atomically; never replace a key already used by this host."""
        pending = []
        for key_id, kind, wrapped in materials:
            secret = wrapped.get_secret_value()
            key_bytes(secret)
            public = "" if kind == "preshared" else derive_public(secret)
            pending.append((str(key_id), kind, public, secret))
        if len({row[0] for row in pending}) != len(pending):
            raise ValueError("Duplicate private-key identifiers")
        with self.connection(write=True) as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT count(*) FROM keys").fetchone()[0]
            for key_text, kind, public, secret in pending:
                old = db.execute(
                    "SELECT kind,encrypted FROM keys WHERE id=?", (key_text,)
                ).fetchone()
                if old:
                    if old["kind"] != kind or not hmac.compare_digest(
                        self.cipher.decrypt(key_text, kind, old["encrypted"]), secret
                    ):
                        raise ValueError("A backup key conflicts with an existing key")
                    continue
                count += 1
                if count > MAX_KEYS:
                    raise ValueError("WireGuard key vault is full")
                db.execute(
                    "INSERT INTO keys (id,kind,public_key,encrypted,created_at) VALUES (?,?,?,?,?)",
                    (
                        key_text,
                        kind,
                        public,
                        self.cipher.encrypt(key_text, kind, secret),
                        time.time(),
                    ),
                )

    def secret(self, key_id: UUID, kind: KeyKind) -> str:
        with self.connection() as db:
            row = db.execute(
                "SELECT encrypted FROM keys WHERE id=? AND kind=?", (str(key_id), kind)
            ).fetchone()
        if row is None:
            raise ValueError("WireGuard key is missing; restore its private backup")
        try:
            return self.cipher.decrypt(str(key_id), kind, row["encrypted"])
        except RuntimeError as exc:
            raise RuntimeError("Cannot decrypt WireGuard keys; restore the private backup") from exc

    def validate(self, config: "NetworkConfiguration") -> None:
        for interface in config.wireguard_interfaces:
            if (
                self.metadata(interface.private_key_id, "interface").public_key
                != interface.public_key
            ):
                raise ValueError("WireGuard interface public key does not match its private key")
        for peer in config.wireguard_peers:
            if peer.preshared_key_id:
                self.metadata(peer.preshared_key_id, "preshared")
            if peer.client_private_key_id and (
                self.metadata(peer.client_private_key_id, "peer-client").public_key
                != peer.public_key
            ):
                raise ValueError("WireGuard client public key does not match its private key")

    def seal_runtime(self, name: str, configuration: str) -> str:
        return self.cipher.encrypt(name, "wireguard-runtime", configuration)

    def open_runtime(self, name: str, encrypted: str) -> str:
        try:
            return self.cipher.decrypt(name, "wireguard-runtime", encrypted)
        except RuntimeError as exc:
            raise RuntimeError("WireGuard recovery cannot decrypt its private snapshot") from exc
