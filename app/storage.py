"""Small transactional SQLite store; no firewall state is held only in memory."""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from app.models import Configuration


class Store:
    def __init__(self, path: Path, initial: Configuration) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL, event TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
            """)
            for key, value in {
                "config": initial.model_dump(mode="json"),
                "applied": initial.model_dump(mode="json"),
                "revision": 0,
                "pending": None,
                "runtime_error": None,
            }.items():
                db.execute("INSERT OR IGNORE INTO state VALUES (?, ?)", (key, json.dumps(value)))
            # JSON schema evolution preserves every saved NAT rule and its order.
            # Demo examples are injected only for sections absent in the old schema.
            for key in ("config", "applied"):
                row = db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
                raw = json.loads(row[0])
                defaults = initial.model_dump(mode="json")
                for section in ("network", "filter_rules"):
                    raw.setdefault(section, defaults[section])
                canonical = Configuration.model_validate(raw).model_dump(mode="json")
                db.execute("UPDATE state SET value = ? WHERE key = ?", (json.dumps(canonical), key))
        path.chmod(0o600)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def read(self, key: str) -> Any:
        with self.connect() as db:
            row = db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
            if row is None:
                raise KeyError(key)
            return json.loads(row[0])

    def write(self, values: dict[str, Any], event: str, detail: str = "") -> None:
        with self.connect() as db:
            db.executemany(
                "UPDATE state SET value = ? WHERE key = ?",
                [(json.dumps(value), key) for key, value in values.items()],
            )
            db.execute(
                "INSERT INTO audit (at, event, detail) VALUES (?, ?, ?)",
                (time.time(), event, detail),
            )
            db.execute(
                "DELETE FROM audit WHERE id NOT IN "
                "(SELECT id FROM audit ORDER BY id DESC LIMIT 500)"
            )

    def audit(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id, at, event, detail FROM audit ORDER BY id DESC LIMIT 100"
                )
            ]
