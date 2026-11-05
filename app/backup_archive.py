"""Password-encrypted, bounded, data-only OpenMikroRout backups."""

import json
import secrets
import zlib
from typing import Literal, Self
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.account_backup import AccountRow, validate_accounts
from app.models import Configuration
from app.updates import version_tuple
from app.version import VERSION
from app.wireguard_keys import KeyKind, derive_public, key_bytes

MAGIC = b"OMRBACKUP\x01"
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_PLAINTEXT = 8 * 1024 * 1024


class BackupError(ValueError):
    pass


class BackupKey(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    id: UUID
    kind: KeyKind
    secret: str = Field(min_length=44, max_length=44, repr=False)


def referenced_keys(config: Configuration) -> dict[UUID, KeyKind]:
    result: dict[UUID, KeyKind] = {}
    for interface in config.network.wireguard_interfaces:
        result[interface.private_key_id] = "interface"
    for peer in config.network.wireguard_peers:
        refs: list[tuple[UUID | None, KeyKind]] = [
            (peer.client_private_key_id, "peer-client"),
            (peer.preshared_key_id, "preshared"),
        ]
        for key_id, kind in refs:
            if key_id:
                if key_id in result and result[key_id] != kind:
                    raise ValueError("A private key is referenced with incompatible kinds")
                result[key_id] = kind
    return result


class BackupPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    format: Literal[1] = 1
    application: Literal["OpenMikroRout"] = "OpenMikroRout"
    version: str
    created_at: float = Field(ge=0, allow_inf_nan=False)
    hostname: str = Field(max_length=253)
    config: Configuration
    accounts: list[AccountRow] = Field(max_length=128, repr=False)
    keys: list[BackupKey] = Field(max_length=1536, repr=False)

    @model_validator(mode="after")
    def validate_contents(self) -> Self:
        if version_tuple(self.version) > version_tuple(VERSION):
            raise ValueError("Backup requires a newer application version")
        validate_accounts(self.accounts, required=bool(self.accounts))
        keys = {key.id: key for key in self.keys}
        if len(keys) != len(self.keys) or {
            key.id: key.kind for key in self.keys
        } != referenced_keys(self.config):
            raise ValueError("Backup private keys do not match configuration references")
        for key in self.keys:
            key_bytes(key.secret)
        for interface in self.config.network.wireguard_interfaces:
            if derive_public(keys[interface.private_key_id].secret) != interface.public_key:
                raise ValueError("WireGuard interface identity does not match its private key")
        for peer in self.config.network.wireguard_peers:
            if (
                peer.client_private_key_id
                and derive_public(keys[peer.client_private_key_id].secret) != peer.public_key
            ):
                raise ValueError("WireGuard client identity does not match its private key")
        return self


def derive_key(password: str, salt: bytes) -> bytes:
    if not 1 <= len(password) <= 512:
        raise BackupError("Недопустимый пароль резервной копии")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def encrypt_backup(payload: BackupPayload, password: str) -> bytes:
    if len(password) < 12:
        raise BackupError("Пароль резервной копии должен содержать минимум 12 символов")
    raw = payload.model_dump_json().encode()
    if len(raw) > MAX_PLAINTEXT:
        raise BackupError("Резервная копия слишком большая")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    result = (
        MAGIC
        + salt
        + nonce
        + AESGCM(derive_key(password, salt)).encrypt(nonce, zlib.compress(raw), MAGIC)
    )
    if len(result) > MAX_ARCHIVE:
        raise BackupError("Резервная копия превышает 8 MiB")
    return result


def decrypt_backup(blob: bytes, password: str) -> BackupPayload:
    if len(blob) > MAX_ARCHIVE or not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 44:
        raise BackupError("Неверный формат резервной копии OpenMikroRout")
    offset = len(MAGIC)
    salt, nonce, ciphertext = (
        blob[offset : offset + 16],
        blob[offset + 16 : offset + 28],
        blob[offset + 28 :],
    )
    try:
        compressed = AESGCM(derive_key(password, salt)).decrypt(nonce, ciphertext, MAGIC)
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, MAX_PLAINTEXT + 1)
        if (
            len(raw) > MAX_PLAINTEXT
            or decoder.unconsumed_tail
            or decoder.unused_data
            or not decoder.eof
        ):
            raise BackupError("Распакованная копия слишком большая или повреждена")
        return BackupPayload.model_validate(json.loads(raw))
    except (InvalidTag, ValueError, TypeError, RecursionError, zlib.error, UnicodeError) as exc:
        raise BackupError(
            "Неверный пароль, повреждённая или несовместимая резервная копия"
        ) from exc
