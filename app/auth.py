"""Persistent hashed accounts and bounded, revocable in-memory login sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Self, cast
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from app.totp import (
    ENROLLMENT_SECONDS,
    CredentialProof,
    TotpEnrollment,
    TotpRecovery,
    TotpStatus,
    TotpVault,
    enrollment,
    matching_counter,
    new_recovery_codes,
    new_secret,
    recovery_digest,
)

Role = Literal["read", "full"]
Language = Literal["ru", "en"]
HASH_ITERATIONS = 600_000
SESSION_SECONDS = 28_800
MAX_USERS = 128
MAX_SESSIONS_PER_USER = 5
# Every supported identity has its own capacity; one account cannot exhaust the pool.
MAX_SESSIONS = MAX_USERS * MAX_SESSIONS_PER_USER
MAX_SESSION_LOGINS_PER_MINUTE = 20
MAX_ATTEMPT_KEYS = 2048
USERNAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"


class AuthError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def normalize_username(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(USERNAME_PATTERN, value):
        raise ValueError("Username must be 1–64 letters, digits, dots, underscores or hyphens")
    return value.lower()


def validate_password(value: str) -> str:
    if not 12 <= len(value) <= 512:
        raise ValueError("Password must contain 12–512 characters")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Password contains invalid Unicode") from exc
    return value


def password_hash(password: str) -> str:
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, HASH_ITERATIONS)
    return "$".join(
        (
            "pbkdf2_sha256",
            str(HASH_ITERATIONS),
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )
    )


def password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, work, salt_text, digest_text = encoded.split("$")
        iterations = int(work)
        salt = base64.b64decode(salt_text, validate=True)
        expected = base64.b64decode(digest_text, validate=True)
        if algorithm != "pbkdf2_sha256" or not HASH_ITERATIONS <= iterations <= 5_000_000:
            return False
        if len(salt) != 16 or len(expected) != 32:
            return False
    except (ValueError, TypeError):
        return False
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, iterations)
    return hmac.compare_digest(actual, expected)


class PublicUser(BaseModel):
    id: str
    username: str
    role: Role
    totp_enabled: bool = False
    language: Language = "ru"


class UserPreferences(BaseModel):
    """Non-security account settings that either role may change for itself."""

    model_config = ConfigDict(extra="forbid")
    language: Language


class ManagedUser(PublicUser):
    enabled: bool
    created_at: float


class UserList(BaseModel):
    users: list[ManagedUser]


class SessionResponse(BaseModel):
    auth_enabled: bool
    user: PublicUser | None


class LoginResponse(SessionResponse):
    ok: bool = True


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=12, max_length=512)
    role: Role = "read"

    @field_validator("username")
    @classmethod
    def username_value(cls, value: str) -> str:
        return normalize_username(value)

    @field_validator("password")
    @classmethod
    def password_value(cls, value: SecretStr) -> SecretStr:
        validate_password(value.get_secret_value())
        return value


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str | None = Field(default=None, min_length=1, max_length=64)
    password: SecretStr | None = Field(default=None, min_length=12, max_length=512)
    role: Role | None = None
    enabled: bool | None = Field(default=None, strict=True)

    @field_validator("username")
    @classmethod
    def username_value(cls, value: str | None) -> str | None:
        return normalize_username(value) if value is not None else None

    @field_validator("password")
    @classmethod
    def password_value(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            validate_password(value.get_secret_value())
        return value

    @model_validator(mode="after")
    def provided_values(self) -> Self:
        fields = self.model_fields_set - {"proof"}
        if not fields:
            raise ValueError("Provide at least one account field")
        if any(getattr(self, name) is None for name in fields):
            raise ValueError("Account fields cannot be null")
        return self


class ProtectedUserCreate(UserCreate):
    proof: CredentialProof


class ProtectedUserUpdate(UserUpdate):
    proof: CredentialProof


class ProtectedUserDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proof: CredentialProof


@dataclass(frozen=True)
class UserRecord:
    id: str
    username: str
    role: Role
    enabled: bool
    created_at: float
    version: int
    password: str = field(repr=False)
    language: Language = "ru"
    totp_secret: str | None = field(default=None, repr=False)
    totp_pending: str | None = field(default=None, repr=False)
    totp_pending_at: float | None = None
    totp_last_counter: int = -1
    totp_recovery: str = field(default="[]", repr=False)

    def public(self) -> PublicUser:
        return PublicUser(
            id=self.id,
            username=self.username,
            role=self.role,
            totp_enabled=bool(self.totp_secret),
            language=self.language,
        )

    def managed(self) -> ManagedUser:
        return ManagedUser(
            **self.public().model_dump(), enabled=self.enabled, created_at=self.created_at
        )


def record(row: sqlite3.Row) -> UserRecord:
    return UserRecord(
        id=str(row["id"]),
        username=str(row["username"]),
        role=cast(Role, row["role"]),
        enabled=bool(row["enabled"]),
        created_at=float(row["created_at"]),
        version=int(row["version"]),
        password=str(row["password_hash"]),
        language=cast(Language, row["language"]),
        totp_secret=row["totp_secret"],
        totp_pending=row["totp_pending"],
        totp_pending_at=row["totp_pending_at"],
        totp_last_counter=int(row["totp_last_counter"]),
        totp_recovery=str(row["totp_recovery"]),
    )


class AuthStore:
    @staticmethod
    def has_users(path: Path) -> bool:
        if not path.exists():
            return False
        try:
            db = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
            try:
                return bool(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])
            finally:
                db.close()
        except sqlite3.Error as exc:
            # An unreadable existing identity database must never open anonymous access.
            raise RuntimeError(
                "Cannot read the account database; authentication remains required"
            ) from exc

    def has_enabled_full(self) -> bool:
        with self.connection() as db:
            return bool(
                db.execute("SELECT COUNT(*) FROM users WHERE enabled=1 AND role='full'").fetchone()[
                    0
                ]
            )

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        path.chmod(0o600)
        with self.connection(write=True) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('read','full')),
                enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
                created_at REAL NOT NULL,
                version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0)
            )""")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            additions = {
                "language": "TEXT NOT NULL DEFAULT 'ru' CHECK(language IN ('ru','en'))",
                "totp_secret": "TEXT",
                "totp_pending": "TEXT",
                "totp_pending_at": "REAL",
                "totp_last_counter": "INTEGER NOT NULL DEFAULT -1",
                "totp_recovery": "TEXT NOT NULL DEFAULT '[]'",
            }
            for name, definition in additions.items():
                if name not in columns:
                    db.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")

    @contextmanager
    def connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        try:
            db = sqlite3.connect(self.path, timeout=5)
        except sqlite3.Error as exc:
            raise AuthError(503, "Account storage is unavailable") from exc
        db.row_factory = sqlite3.Row
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise AuthError(409, "Username is already in use") from exc
        except sqlite3.Error as exc:
            db.rollback()
            raise AuthError(503, "Account storage is unavailable") from exc
        finally:
            db.close()

    def bootstrap(
        self, username: str, password: str, read_username: str, read_password: str
    ) -> None:
        with self.connection() as db:
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return
        admin = (normalize_username(username), password_hash(password), "full")
        reader = (
            (normalize_username(read_username), password_hash(read_password), "read")
            if read_password
            else None
        )
        if reader and reader[0] == admin[0]:
            raise RuntimeError("Administrator and read-only usernames must differ")
        with self.connection(write=True) as db:
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return
            for name, digest, role in [admin, *([reader] if reader else [])]:
                db.execute(
                    "INSERT INTO users (id,username,password_hash,role,created_at) "
                    "VALUES (?,?,?,?,?)",
                    (str(uuid4()), name, digest, role, time.time()),
                )

    def by_name(self, username: str) -> UserRecord | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return record(row) if row is not None else None

    def by_id(self, user_id: str) -> UserRecord | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return record(row) if row is not None else None

    def list_users(self) -> list[ManagedUser]:
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM users ORDER BY username LIMIT ?", (MAX_USERS,)
            ).fetchall()
        return [record(row).managed() for row in rows]

    def set_preferences(self, actor: UserRecord, body: UserPreferences) -> UserPreferences:
        with self.connection(write=True) as db:
            # Only the original enabled identity/version may change its preferences.
            # Account-security changes use a different path and invalidate sessions.
            cursor = db.execute(
                "UPDATE users SET language=? WHERE id=? AND enabled=1 AND version=?",
                (body.language, actor.id, actor.version),
            )
            if cursor.rowcount != 1:
                raise AuthError(401, "Account changed; sign in again")
        return body

    @staticmethod
    def guard_actor(db: sqlite3.Connection, actor: UserRecord | None) -> None:
        if actor is None:
            return  # Low-level provisioning/restore callers have no HTTP session.
        row = db.execute("SELECT * FROM users WHERE id=?", (actor.id,)).fetchone()
        if row is None:
            raise AuthError(401, "Account changed; sign in again")
        current = record(row)
        if not current.enabled or current.version != actor.version:
            raise AuthError(401, "Account changed; sign in again")
        if current.role != "full":
            raise AuthError(403, "Full access is required")

    def create(
        self, body: UserCreate, digest: str, *, actor: UserRecord | None = None
    ) -> ManagedUser:
        user_id = str(uuid4())
        with self.connection(write=True) as db:
            self.guard_actor(db, actor)
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= MAX_USERS:
                raise AuthError(409, "Account limit reached")
            db.execute(
                "INSERT INTO users (id,username,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                (user_id, body.username, digest, body.role, time.time()),
            )
            row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            assert row is not None
            return record(row).managed()

    @staticmethod
    def guard_last_full(db: sqlite3.Connection, current: UserRecord) -> None:
        if current.enabled and current.role == "full":
            count = db.execute(
                "SELECT COUNT(*) FROM users WHERE enabled = 1 AND role = 'full'"
            ).fetchone()[0]
            if count <= 1:
                raise AuthError(409, "The last enabled full-access account must remain available")

    def update(
        self,
        user_id: str,
        body: UserUpdate,
        digest: str | None,
        *,
        actor: UserRecord | None = None,
    ) -> ManagedUser:
        with self.connection(write=True) as db:
            self.guard_actor(db, actor)
            row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise AuthError(404, "Account not found")
            current = record(row)
            role = body.role if body.role is not None else current.role
            enabled = body.enabled if body.enabled is not None else current.enabled
            if role != "full" or not enabled:
                self.guard_last_full(db, current)
            name = body.username if body.username is not None else current.username
            # Any account edit invalidates all existing sessions for that identity.
            db.execute(
                "UPDATE users SET username=?,password_hash=?,role=?,enabled=?,version=version+1 "
                "WHERE id=?",
                (name, digest or current.password, role, int(enabled), user_id),
            )
            row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            assert row is not None
            return record(row).managed()

    def delete(
        self, user_id: str, actor_id: str | None, *, actor: UserRecord | None = None
    ) -> None:
        with self.connection(write=True) as db:
            self.guard_actor(db, actor)
            row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise AuthError(404, "Account not found")
            current = record(row)
            self.guard_last_full(db, current)
            if user_id == actor_id:
                raise AuthError(
                    409, "Sign in with another full-access account before deleting this account"
                )
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))


@dataclass(frozen=True)
class LoginSession:
    user_id: str
    version: int
    expires: float


class AuthService:
    def __init__(
        self,
        data_dir: Path,
        enabled: bool,
        username: str,
        password: str,
        read_username: str = "viewer",
        read_password: str = "",
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.enabled = enabled or AuthStore.has_users(data_dir / "auth.sqlite3")
        self.clock = clock
        self.store = AuthStore(data_dir / "auth.sqlite3") if self.enabled else None
        self.lock = threading.RLock()
        self.hash_slots = threading.BoundedSemaphore(2)
        self.sessions: dict[str, LoginSession] = {}
        self.attempts: OrderedDict[tuple[str, str], list[float]] = OrderedDict()
        self.unknown_attempts: OrderedDict[tuple[str, str], list[float]] = OrderedDict()
        self.session_logins: dict[str, list[float]] = {}
        self.dummy = password_hash(secrets.token_urlsafe(32)) if self.enabled else ""
        self.vault: TotpVault | None = None
        if self.store:
            self.store.bootstrap(username, password, read_username, read_password)
            if not self.store.has_enabled_full():
                raise RuntimeError("The account database requires an enabled full-access account")
            with self.store.connection() as db:
                required = bool(
                    db.execute(
                        "SELECT 1 FROM users WHERE totp_secret IS NOT NULL "
                        "OR totp_pending IS NOT NULL LIMIT 1"
                    ).fetchone()
                )
            self.vault = TotpVault(data_dir / "totp.key", required=required)

    def require_store(self) -> AuthStore:
        if self.store is None:
            raise AuthError(409, "Enable authentication before managing accounts")
        return self.store

    def resolve(self, token: str) -> PublicUser | None:
        if not self.enabled or not token or len(token) > 256:
            return None
        try:
            return self.authorize(token).public()
        except AuthError as exc:
            if exc.status == 401:
                return None
            raise

    def authorize(self, token: str, required_role: Role | None = None) -> UserRecord:
        if not self.enabled or not token or len(token) > 256:
            raise AuthError(401, "Sign in to manage the router")
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            session = self.sessions.get(key)
            if session is None:
                raise AuthError(401, "Sign in to manage the router")
            if session.expires <= self.clock():
                del self.sessions[key]
                raise AuthError(401, "Sign in to manage the router")
            current = self.require_store().by_id(session.user_id)
            if current is None or not current.enabled or current.version != session.version:
                self.sessions.pop(key, None)
                raise AuthError(401, "Account changed; sign in again")
            if required_role is not None and current.role != required_role:
                raise AuthError(403, "Full access is required")
            return current

    def _check_actor(self, token: str, actor: UserRecord, role: Role | None = None) -> None:
        current = self.authorize(token, role)
        if current.id != actor.id or current.version != actor.version:
            raise AuthError(401, "Account changed; sign in again")

    def set_preferences(self, token: str, body: UserPreferences) -> UserPreferences:
        # Serialize with logout, session revocation and account mutations. A harmless
        # preference must not consume an authenticator code or terminate sessions.
        with self.lock:
            actor = self.authorize(token)
            return self.require_store().set_preferences(actor, body)

    def _attempt(
        self, client: str, identity: str, *, known: bool = True
    ) -> tuple[tuple[str, str], ...]:
        now = self.clock()
        # Keep real account windows separate from arbitrary unknown-name/client churn.
        # A proxy/NAT peer must never lock out unrelated existing accounts.
        keys = ((client[:128], identity),) if known else ((client[:128], ""),)
        with self.lock:
            attempts = self.attempts if known else self.unknown_attempts
            for key in list(attempts):
                recent = [at for at in attempts[key] if now - at < 60]
                if recent:
                    attempts[key] = recent
                else:
                    del attempts[key]
            for key in keys:
                recent = attempts.get(key, [])
                if len(recent) >= 5:
                    raise AuthError(429, "Too many attempts. Try again in a minute.")
                # Preserve active peer/account histories. Unknown identities use
                # another bounded map and cannot force eviction of these windows.
                if known and key not in attempts and len(attempts) >= MAX_ATTEMPT_KEYS:
                    raise AuthError(429, "Authentication is busy. Try again shortly.")
                attempts[key] = [*recent, now]
                attempts.move_to_end(key)
            while len(self.unknown_attempts) > MAX_ATTEMPT_KEYS:
                self.unknown_attempts.popitem(last=False)
        return keys

    def _password(self, user: UserRecord | None, password: str) -> bool:
        if not self.hash_slots.acquire(blocking=False):
            raise AuthError(429, "Authentication is busy. Try again shortly.")
        try:
            return password_matches(password, user.password if user else self.dummy)
        finally:
            self.hash_slots.release()

    def _factor(self, db: sqlite3.Connection, user: UserRecord, code: str) -> None:
        if not user.totp_secret:
            return
        if self.vault is None:
            raise AuthError(503, "Authenticator storage is unavailable")
        secret = self.vault.decrypt(user.id, "active", user.totp_secret)
        counter = matching_counter(secret, code, self.clock(), user.totp_last_counter)
        if counter is not None:
            db.execute("UPDATE users SET totp_last_counter=? WHERE id=?", (counter, user.id))
            return
        codes = self._recovery(user)
        digest = recovery_digest(user.id, code)
        for index, expected in enumerate(codes):
            if hmac.compare_digest(digest, expected):
                del codes[index]
                db.execute(
                    "UPDATE users SET totp_recovery=? WHERE id=?", (json.dumps(codes), user.id)
                )
                return
        raise AuthError(401, "Incorrect password or authenticator code")

    @staticmethod
    def _recovery(user: UserRecord) -> list[str]:
        try:
            values = json.loads(user.totp_recovery)
            if not isinstance(values, list) or not all(
                isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in values
            ):
                raise ValueError("Invalid recovery data")
            return cast(list[str], values)
        except (ValueError, TypeError) as exc:
            raise AuthError(503, "Authenticator storage is unavailable") from exc

    def _session_plan(self, user: UserRecord) -> tuple[str, dict[str, LoginSession]]:
        """Plan admission under lock without evicting tokens or consuming a factor."""
        now = self.clock()
        sessions = {key: value for key, value in self.sessions.items() if value.expires > now}
        own = sorted(
            (key for key, value in sessions.items() if value.user_id == user.id),
            key=lambda key: sessions[key].expires,
        )
        while len(own) >= MAX_SESSIONS_PER_USER:
            del sessions[own.pop(0)]
        if len(sessions) >= MAX_SESSIONS:
            raise AuthError(429, "Session limit reached")
        token = secrets.token_urlsafe(32)
        sessions[hashlib.sha256(token.encode()).hexdigest()] = LoginSession(
            user.id, user.version, now + SESSION_SECONDS
        )
        return token, sessions

    def _session(self, user: UserRecord) -> tuple[str, PublicUser]:
        with self.lock:
            current = self.require_store().by_id(user.id)
            if current is None or not current.enabled or current.version != user.version:
                raise AuthError(401, "Account changed; sign in again")
            token, self.sessions = self._session_plan(current)
        return token, user.public()

    def login(
        self, username: str, password: str, client: str, code: str = ""
    ) -> tuple[str | None, PublicUser | None]:
        if not self.enabled:
            return None, None
        username = normalize_username(username)
        user = self.require_store().by_name(username)
        keys = self._attempt(client, user.id if user else "", known=user is not None)
        valid = self._password(user, password)
        if not user or not valid or not user.enabled:
            raise AuthError(401, "Incorrect username or password")
        with self.lock:
            now = self.clock()
            self.session_logins = {
                identity: recent
                for identity, timestamps in self.session_logins.items()
                if (recent := [at for at in timestamps if now - at < 60])
            }
            recent = self.session_logins.get(user.id, [])
            if len(recent) >= MAX_SESSION_LOGINS_PER_MINUTE:
                raise AuthError(429, "Too many new sessions. Try again in a minute.")
            with self.require_store().connection(write=True) as db:
                row = db.execute("SELECT * FROM users WHERE id=?", (user.id,)).fetchone()
                if row is None:
                    raise AuthError(401, "Incorrect username or password")
                current = record(row)
                if not current.enabled or current.version != user.version:
                    raise AuthError(401, "Incorrect username or password")
                token, sessions = self._session_plan(current)
                self._factor(db, current, code.strip())
            # Admission and factor commit are serialized with logout/account changes.
            self.sessions = sessions
            self.session_logins[user.id] = [*recent, now]
            for key in keys:
                self.attempts.pop(key, None)
        return token, current.public()

    def reauthenticate(
        self,
        actor: PublicUser,
        proof: CredentialProof,
        client: str,
        *,
        clear_attempts: bool = True,
        token: str | None = None,
        required_role: Role | None = None,
    ) -> UserRecord:
        keys = self._attempt("proof:" + client, actor.id)
        user = self.require_store().by_id(actor.id)
        if token is not None and user is not None:
            self._check_actor(token, user, required_role)
        if required_role is not None and (user is None or user.role != required_role):
            raise AuthError(403, "Full access is required")
        if (
            not self._password(user, proof.password.get_secret_value())
            or not user
            or not user.enabled
        ):
            raise AuthError(403, "Incorrect password or authenticator code")
        with self.lock:
            if token is not None:
                self._check_actor(token, user, required_role)
            with self.require_store().connection(write=True) as db:
                row = db.execute("SELECT * FROM users WHERE id=?", (user.id,)).fetchone()
                if row is None or record(row).version != user.version:
                    raise AuthError(401, "Account changed; sign in again")
                try:
                    self._factor(db, record(row), proof.code.get_secret_value().strip())
                except AuthError as exc:
                    if exc.status == 401:
                        raise AuthError(403, str(exc)) from exc
                    raise
            if clear_attempts:
                for key in keys:
                    self.attempts.pop(key, None)
        return user

    def totp_status(self, actor: PublicUser) -> TotpStatus:
        user = self.require_store().by_id(actor.id)
        if not user:
            raise AuthError(401, "Sign in again")
        return TotpStatus(
            enabled=bool(user.totp_secret), recovery_codes_remaining=len(self._recovery(user))
        )

    def totp_setup(
        self, actor: PublicUser, proof: CredentialProof, client: str, *, token: str
    ) -> TotpEnrollment:
        user = self.reauthenticate(actor, proof, client, token=token)
        if user.totp_secret:
            raise AuthError(409, "Disable the current authenticator before enrolling another one")
        assert self.vault is not None
        secret = new_secret()
        now = self.clock()
        with self.lock:
            self._check_actor(token, user)
            with self.require_store().connection(write=True) as db:
                cursor = db.execute(
                    "UPDATE users SET totp_pending=?,totp_pending_at=? WHERE id=? "
                    "AND version=? AND totp_secret IS NULL",
                    (self.vault.encrypt(user.id, "pending", secret), now, user.id, user.version),
                )
                if cursor.rowcount != 1:
                    raise AuthError(409, "Account changed; repeat authenticator setup")
        return enrollment(secret, user.username, now + ENROLLMENT_SECONDS)

    def totp_confirm(
        self, actor: PublicUser, proof: CredentialProof, client: str, *, token: str
    ) -> tuple[TotpRecovery, str]:
        # Password verification and pending-key validation are separate from active 2FA.
        user = self.reauthenticate(actor, proof, client, clear_attempts=False, token=token)
        assert self.vault is not None
        with self.lock:
            self._check_actor(token, user)
            with self.require_store().connection(write=True) as db:
                row = db.execute("SELECT * FROM users WHERE id=?", (user.id,)).fetchone()
                if row is None:
                    raise AuthError(401, "Sign in again")
                current = record(row)
                if (
                    current.version != user.version
                    or current.totp_secret
                    or not current.totp_pending
                    or current.totp_pending_at is None
                    or not 0 <= self.clock() - current.totp_pending_at <= ENROLLMENT_SECONDS
                ):
                    raise AuthError(409, "Authenticator setup expired or changed; start again")
                secret = self.vault.decrypt(user.id, "pending", current.totp_pending)
                counter = matching_counter(secret, proof.code.get_secret_value(), self.clock())
                if counter is None:
                    # The failure must count towards the same proof-attempt limit.
                    raise AuthError(400, "Incorrect authenticator code")
                codes = new_recovery_codes()
                digests = [recovery_digest(user.id, value) for value in codes]
                db.execute(
                    "UPDATE users SET totp_secret=?,totp_pending=NULL,totp_pending_at=NULL,"
                    "totp_last_counter=?,totp_recovery=?,version=version+1 WHERE id=?",
                    (
                        self.vault.encrypt(user.id, "active", secret),
                        counter,
                        json.dumps(digests),
                        user.id,
                    ),
                )
            self.revoke_user(user.id)
            self.attempts.pop((("proof:" + client)[:128], actor.id), None)
            updated = self.require_store().by_id(user.id)
            assert updated is not None
            replacement, _ = self._session(updated)
            return TotpRecovery(recovery_codes=codes), replacement

    def totp_disable(
        self, actor: PublicUser, proof: CredentialProof, client: str, *, token: str
    ) -> str:
        user = self.reauthenticate(actor, proof, client, token=token)
        with self.lock:
            self._check_actor(token, user)
            self._clear_totp(user.id, user.version)
            updated = self.require_store().by_id(user.id)
            assert updated is not None
            replacement, _ = self._session(updated)
            return replacement

    def _clear_totp(self, user_id: str, version: int) -> None:
        with self.require_store().connection(write=True) as db:
            cursor = db.execute(
                "UPDATE users SET totp_secret=NULL,totp_pending=NULL,totp_pending_at=NULL,"
                "totp_last_counter=-1,totp_recovery='[]',version=version+1 "
                "WHERE id=? AND version=?",
                (user_id, version),
            )
            if cursor.rowcount != 1:
                raise AuthError(409, "Account changed; repeat the operation")
        self.revoke_user(user_id)

    def totp_reset(
        self,
        target_id: str,
        actor: PublicUser,
        proof: CredentialProof,
        client: str,
        *,
        token: str,
    ) -> None:
        if actor.role != "full" or actor.id == target_id:
            raise AuthError(403, "Use your own security settings or another full-access account")
        verified = self.reauthenticate(actor, proof, client, token=token, required_role="full")
        with self.lock:
            self._check_actor(token, verified, "full")
            target = self.require_store().by_id(target_id)
            if not target:
                raise AuthError(404, "Account not found")
            self._clear_totp(target.id, target.version)

    def logout(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)

    def revoke_user(self, user_id: str) -> None:
        with self.lock:
            self.sessions = {
                key: session for key, session in self.sessions.items() if session.user_id != user_id
            }

    def _account_proof(self, token: str, proof: CredentialProof, client: str) -> UserRecord:
        actor = self.authorize(token, "full")
        return self.reauthenticate(actor.public(), proof, client, token=token, required_role="full")

    def delete(self, user_id: str, *, token: str, proof: CredentialProof, client: str) -> None:
        actor = self._account_proof(token, proof, client)
        with self.lock:
            self._check_actor(token, actor, "full")
            self.require_store().delete(user_id, actor.id, actor=actor)
            self.revoke_user(user_id)

    def create(
        self, body: UserCreate, *, token: str, proof: CredentialProof, client: str
    ) -> ManagedUser:
        actor = self._account_proof(token, proof, client)
        if not self.hash_slots.acquire(blocking=False):
            raise AuthError(429, "Account service is busy. Try again shortly.")
        try:
            digest = password_hash(body.password.get_secret_value())
        finally:
            self.hash_slots.release()
        with self.lock:
            self._check_actor(token, actor, "full")
            return self.require_store().create(body, digest, actor=actor)

    def update(
        self, user_id: str, body: UserUpdate, *, token: str, proof: CredentialProof, client: str
    ) -> ManagedUser:
        actor = self._account_proof(token, proof, client)
        digest = None
        if body.password is not None:
            if not self.hash_slots.acquire(blocking=False):
                raise AuthError(429, "Account service is busy. Try again shortly.")
            try:
                digest = password_hash(body.password.get_secret_value())
            finally:
                self.hash_slots.release()
        with self.lock:
            self._check_actor(token, actor, "full")
            result = self.require_store().update(user_id, body, digest, actor=actor)
            self.revoke_user(user_id)
            return result
