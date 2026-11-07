"""Portable account snapshots, re-encrypted into the destination's existing TOTP vault."""

import base64
import hmac
import json
from collections.abc import Callable
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth import HASH_ITERATIONS, MAX_USERS, AuthService, Language, normalize_username


class AccountRow(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    id: UUID
    username: str
    password_hash: str = Field(max_length=512, repr=False)
    role: Literal["read", "full"]
    language: Language = "ru"
    enabled: bool
    created_at: float = Field(ge=0, allow_inf_nan=False)
    version: int = Field(ge=1, le=2**63 - 2)
    totp_secret: str | None = Field(default=None, max_length=512, repr=False)
    totp_pending: str | None = Field(default=None, max_length=512, repr=False)
    totp_pending_at: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    totp_last_counter: int = Field(default=-1, ge=-1, le=2**63 - 1)
    totp_recovery: list[str] = Field(default_factory=list, max_length=8, repr=False)

    _username = field_validator("username")(normalize_username)

    @field_validator("password_hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        try:
            kind, work, salt, digest = value.split("$")
            valid = (
                kind == "pbkdf2_sha256"
                and HASH_ITERATIONS <= int(work) <= 5_000_000
                and len(base64.b64decode(salt, validate=True)) == 16
                and len(base64.b64decode(digest, validate=True)) == 32
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise ValueError("Unsupported account password hash")
        return value

    @field_validator("totp_recovery")
    @classmethod
    def validate_recovery(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values) or any(
            len(v) != 64 or any(c not in "0123456789abcdef" for c in v) for v in values
        ):
            raise ValueError("Invalid recovery-code hashes")
        return values


def validate_accounts(rows: list[AccountRow], required: bool = True) -> None:
    if (
        len(rows) > MAX_USERS
        or len({r.id for r in rows}) != len(rows)
        or len({r.username for r in rows}) != len(rows)
    ):
        raise ValueError("Invalid or duplicate backup accounts")
    if required and not any(r.enabled and r.role == "full" for r in rows):
        raise ValueError("A backup must contain an enabled full account")


class AccountSnapshots:
    def __init__(self, auth: AuthService) -> None:
        self.auth = auth

    @staticmethod
    def _row(raw: dict[str, Any]) -> AccountRow:
        value = dict(raw)
        value["enabled"] = bool(value["enabled"])
        value["totp_recovery"] = json.loads(value["totp_recovery"])
        return AccountRow.model_validate(value)

    def export(self) -> list[AccountRow]:
        if not self.auth.enabled:
            return []
        with self.auth.lock, self.auth.require_store().connection() as db:
            db.execute("BEGIN")
            rows = [
                self._row(dict(r))
                for r in db.execute("SELECT * FROM users LIMIT ?", (MAX_USERS + 1,))
            ]
            validate_accounts(rows)
            assert self.auth.vault is not None
            for row in rows:
                if row.totp_secret:
                    row.totp_secret = self.auth.vault.decrypt(
                        str(row.id), "active", row.totp_secret
                    )
                row.totp_pending = None
                row.totp_pending_at = None
            return rows

    def prepare(self, rows: list[AccountRow]) -> list[dict[str, Any]]:
        validate_accounts(rows)
        if not self.auth.enabled or self.auth.vault is None:
            raise ValueError("Enable authentication before restoring accounts")
        result = []
        for original in rows:
            row = original.model_copy(deep=True)
            # Source session versions are not meaningful on the destination.
            row.version = 1
            if row.totp_last_counter > int(self.auth.clock() // 30) + 1:
                raise ValueError("Backup authenticator counter is ahead of this server clock")
            if row.totp_secret:
                try:
                    decoded = base64.b32decode(row.totp_secret, casefold=False)
                except ValueError as exc:
                    raise ValueError("Invalid authenticator secret") from exc
                if len(decoded) != 20:
                    raise ValueError("Invalid authenticator secret")
                row.totp_secret = self.auth.vault.encrypt(str(row.id), "active", row.totp_secret)
            row.totp_pending = None
            row.totp_pending_at = None
            result.append(row.model_dump(mode="json"))
        return result

    def replace(
        self,
        values: list[dict[str, Any]],
        before_mutation: Callable[[list[dict[str, Any]]], None] | None = None,
    ) -> None:
        rows = [AccountRow.model_validate(row) for row in values]
        validate_accounts(rows)
        if not self.auth.enabled or self.auth.vault is None:
            raise ValueError("Authentication is unavailable")
        vault = self.auth.vault
        with self.auth.lock:
            with self.auth.require_store().connection(write=True) as db:
                current = {
                    str(row["id"]): self._row(dict(row))
                    for row in db.execute("SELECT * FROM users LIMIT ?", (MAX_USERS + 1,))
                }
                if before_mutation:
                    before_mutation([row.model_dump(mode="json") for row in current.values()])
                for row in rows:
                    old = current.get(str(row.id))
                    row.version = max(row.version, old.version if old else 0) + 1
                    if old:
                        row.totp_last_counter = max(row.totp_last_counter, old.totp_last_counter)
                        if (
                            row.totp_secret
                            and old.totp_secret
                            and hmac.compare_digest(
                                vault.decrypt(str(row.id), "active", row.totp_secret),
                                vault.decrypt(str(old.id), "active", old.totp_secret),
                            )
                        ):
                            row.totp_recovery = [
                                code for code in row.totp_recovery if code in old.totp_recovery
                            ]
                db.execute("DELETE FROM users")
                for row in rows:
                    raw = row.model_dump(mode="json")
                    raw["enabled"] = int(row.enabled)
                    raw["totp_recovery"] = json.dumps(row.totp_recovery)
                    columns = ",".join(AccountRow.model_fields)
                    placeholders = ",".join("?" for _ in raw)
                    db.execute(
                        f"INSERT INTO users ({columns}) VALUES ({placeholders})",
                        tuple(raw.values()),
                    )
            self.auth.sessions.clear()
