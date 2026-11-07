"""Secret-free authentication journal and durable projections of Fail2ban ban tickets."""

import ipaddress
import logging
import logging.handlers
import math
import os
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from app.display_filters import validate_display_negation
from app.fail2ban_models import (
    MAX_BAN_SECONDS,
    F2BConfiguration,
    F2BProfile,
    client_ipv4,
    profile_id,
)

MAX_ACTIVE_BANS = 65_536
MAX_EVENT_HISTORY = 20_000
MAX_RETAINED_BANS = MAX_ACTIVE_BANS * 2
RETENTION_SECONDS = MAX_BAN_SECONDS + 86400


class TemporarySets(Protocol):
    def ensure_temporary(self, name: str) -> None: ...
    def add_temporary(self, name: str, address: str, timeout: int) -> None: ...
    def delete_temporary(self, name: str, address: str) -> None: ...
    def temporary_entries(self, name: str) -> list[dict[str, Any]]: ...


class AuthenticationJournal:
    """Only this method accepts login failures; request bodies never reach the logger."""

    def __init__(self, data_dir: Path) -> None:
        directory = data_dir / "fail2ban"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / "auth.log"
        self.handler = logging.handlers.RotatingFileHandler(
            self.path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8", delay=False
        )
        os.chmod(self.path, 0o600)
        formatter = logging.Formatter(
            "%(asctime)s openmikrorout auth_failure src=%(message)s reason=credentials",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        formatter.converter = time.gmtime
        self.handler.setFormatter(formatter)
        self.lock = threading.Lock()

    def failure(self, config: F2BConfiguration, peer: str, forwarded_for: str = "") -> bool:
        if not config.enabled or not any(p.enabled and p.service == "web" for p in config.profiles):
            return False
        address = client_ipv4(config, peer, forwarded_for)
        if address is None:
            return False
        record = logging.LogRecord("openmikrorout.auth", logging.WARNING, "", 0, address, (), None)
        with self.lock:
            self.handler.handle(record)
            # Rollover opens a new file using the process umask; keep explicit private mode.
            os.chmod(self.path, 0o600)
        return True

    def close(self) -> None:
        self.handler.close()


class BanStore:
    def __init__(self, data_dir: Path, driver: TemporarySets) -> None:
        self.path = data_dir / "fail2ban.sqlite3"
        self.driver = driver
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS bans (
                    profile TEXT NOT NULL, address TEXT NOT NULL,
                    added_at REAL NOT NULL, expires_at REAL NOT NULL,
                    country TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'fail2ban',
                    PRIMARY KEY(profile,address)
                );
                CREATE INDEX IF NOT EXISTS bans_expiry ON bans(expires_at);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL,
                    profile TEXT NOT NULL, address TEXT NOT NULL, event TEXT NOT NULL
                );
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def permitted(profile: F2BProfile, address: str, country: str) -> bool:
        ip = ipaddress.IPv4Address(address)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return False
        if any(ip in ipaddress.IPv4Network(net) for net in profile.ignore_addresses):
            return False
        if country in profile.exclude_countries:
            return False
        return not profile.include_countries or country in profile.include_countries

    @staticmethod
    def _event(db: sqlite3.Connection, profile: str, address: str, event: str) -> None:
        db.execute(
            "INSERT INTO events(at,profile,address,event) VALUES(?,?,?,?)",
            (time.time(), profile, address, event),
        )
        db.execute(
            "DELETE FROM events WHERE id <= (SELECT MAX(id) - ? FROM events)",
            (MAX_EVENT_HISTORY,),
        )

    def ban(
        self, profile: F2BProfile, address: str, started: float, duration: int, country: str = ""
    ) -> bool:
        address = str(ipaddress.IPv4Address(address))
        now = time.time()
        if not math.isfinite(started) or not 1 <= duration <= MAX_BAN_SECONDS or started > now + 5:
            raise ValueError("Invalid Fail2ban ticket timestamp or finite duration")
        expiry = started + duration
        remaining = math.ceil(expiry - now)
        if remaining <= 0 or not self.permitted(profile, address, country):
            return False
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM bans WHERE added_at < ?", (now - RETENTION_SECONDS,))
            previous = db.execute(
                "SELECT added_at,expires_at FROM bans WHERE profile=? AND address=?",
                (profile.id, address),
            ).fetchone()
            if previous is not None:
                if previous["added_at"] > started:
                    return False
                if previous["added_at"] == started:
                    # A restored/duplicate event is the same ticket, never a new ban interval.
                    expiry = min(expiry, previous["expires_at"])
                    remaining = math.ceil(expiry - time.time())
                    if remaining <= 0:
                        return False
            elif (
                db.execute("SELECT COUNT(*) FROM bans WHERE expires_at>?", (now,)).fetchone()[0]
                >= MAX_ACTIVE_BANS
            ):
                raise ValueError("Fail2ban active-ban limit reached")
            if (
                previous is None
                and db.execute("SELECT COUNT(*) FROM bans").fetchone()[0] >= MAX_RETAINED_BANS
            ):
                raise ValueError("Fail2ban retained-ticket limit reached")
            self.driver.add_temporary(f"f2b_{profile.id}", address, remaining)
            db.execute(
                "INSERT INTO bans(profile,address,added_at,expires_at,country) VALUES(?,?,?,?,?) "
                "ON CONFLICT(profile,address) DO UPDATE SET added_at=excluded.added_at, "
                "expires_at=excluded.expires_at,country=excluded.country",
                (profile.id, address, started, expiry, country),
            )
            if previous is None or previous["added_at"] != started:
                self._event(db, profile.id, address, "ban")
        return True

    def unban(
        self,
        profile: str,
        address: str,
        started: float | None = None,
        *,
        require_ticket: bool = False,
    ) -> bool:
        profile_id(profile)
        address = str(ipaddress.IPv4Address(address))
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT added_at FROM bans WHERE profile=? AND address=?", (profile, address)
            ).fetchone()
            if previous is None and require_ticket:
                raise ValueError("Unknown Fail2ban ban ticket")
            if previous is not None and started is not None and previous["added_at"] > started:
                return False
            self.driver.delete_temporary(f"f2b_{profile}", address)
            # Keep the original expiry as a tombstone: stale delivery must not resurrect an unban.
            if previous is not None:
                db.execute(
                    "UPDATE bans SET expires_at=0 WHERE profile=? AND address=?", (profile, address)
                )
                self._event(db, profile, address, "unban")
        return previous is not None

    def restore(self, config: F2BConfiguration, lookup: Callable[[str], str]) -> None:
        if not config.enabled:
            return
        profiles = {p.id: p for p in config.profiles if p.enabled}
        with self.connection() as db:
            rows = db.execute(
                "SELECT profile,address,added_at,expires_at FROM bans WHERE expires_at>? LIMIT ?",
                (time.time(), MAX_ACTIVE_BANS),
            ).fetchall()
        for row in rows:
            profile = profiles.get(row["profile"])
            if profile is None:
                continue
            country = lookup(row["address"])
            if not self.permitted(profile, row["address"], country):
                self.unban(profile.id, row["address"])
                continue
            # original timestamps survive reboot; never restart the configured full ban_time.
            remaining = math.ceil(row["expires_at"] - time.time())
            if remaining > 0:
                self.driver.add_temporary(f"f2b_{profile.id}", row["address"], remaining)

    def page(
        self,
        profile: str = "",
        query: str = "",
        limit: int = 100,
        offset: int = 0,
        *,
        negate: str | list[str] = "",
    ) -> dict[str, Any]:
        limit = min(200, max(1, limit))
        offset = min(1_000_000, max(0, offset))
        query = query.strip()[:64]
        if profile:
            profile_id(profile)
        excluded = validate_display_negation(negate, {"query": query, "profile": profile})
        now = time.time()
        conditions = ["expires_at>?"]
        args: list[str | float] = [now]
        if profile:
            conditions.append("NOT (profile=?)" if "profile" in excluded else "profile=?")
            args.append(profile)
        if query:
            match = "(instr(address,?)>0 OR instr(lower(profile),lower(?))>0)"
            conditions.append(f"NOT {match}" if "query" in excluded else match)
            args.extend((query, query))
        where = " AND ".join(conditions)
        with self.connection() as db:
            total = db.execute(f"SELECT COUNT(*) FROM bans WHERE {where}", args).fetchone()[0]
            rows = db.execute(
                "SELECT profile,address,added_at,expires_at,country,source FROM bans "
                f"WHERE {where} "
                "ORDER BY expires_at DESC,profile,address LIMIT ? OFFSET ?",
                (*args, limit, offset),
            ).fetchall()
        actual: dict[str, set[str]] = {}
        for row in rows:
            if row["profile"] not in actual:
                actual[row["profile"]] = {
                    item["address"]
                    for item in self.driver.temporary_entries(f"f2b_{row['profile']}")
                }
        items = [
            {
                **dict(row),
                "remaining_seconds": max(0, math.ceil(row["expires_at"] - now)),
                "kernel_present": row["address"] in actual[row["profile"]],
            }
            for row in rows
        ]
        return {"items": items, "total": total, "limit": limit, "offset": offset}
