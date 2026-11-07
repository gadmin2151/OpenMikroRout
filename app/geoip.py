"""Versioned, offline DB-IP Country Lite index and bounded monthly downloader."""

import csv
import gzip
import hashlib
import ipaddress
import re
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Generator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from app.compiler import FirewallError
from app.display_filters import validate_display_negation
from app.system_lists import country_code

SOURCE = "DB-IP Country Lite"
ATTRIBUTION = "https://db-ip.com"
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_ROWS = 2_000_000
MAX_LINE = 256
DOWNLOAD_TIMEOUT = 180
SPECIAL_NETWORKS = tuple(
    ipaddress.IPv4Network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)


def public_ranges(first: int, last: int) -> Iterator[tuple[int, int]]:
    """Special-use space is never a country match, even if a provider mislabels it."""
    cursor = first
    for network in SPECIAL_NETWORKS:
        low, high = int(network.network_address), int(network.broadcast_address)
        if high < cursor:
            continue
        if low > last:
            break
        if cursor < low:
            yield cursor, min(last, low - 1)
        cursor = max(cursor, high + 1)
        if cursor > last:
            return
    if cursor <= last:
        yield cursor, last


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise FirewallError("GeoIP download redirects are not permitted")


def validate_version(version: str) -> str:
    if not re.fullmatch(r"20[0-9]{2}-(0[1-9]|1[0-2])", version):
        raise ValueError("GeoIP version must be YYYY-MM")
    return version


def download_url(version: str) -> str:
    return f"https://download.db-ip.com/free/dbip-country-lite-{validate_version(version)}.csv.gz"


class GeoIPService:
    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = data_dir / "geoip.sqlite3"
        self.update_lock = threading.Lock()
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS versions (
                    version TEXT PRIMARY KEY, imported_at REAL NOT NULL,
                    row_count INTEGER NOT NULL, sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ranges (
                    version TEXT NOT NULL REFERENCES versions(version) ON DELETE CASCADE,
                    first INTEGER NOT NULL, last INTEGER NOT NULL, country TEXT NOT NULL,
                    PRIMARY KEY(version, first), CHECK(first <= last)
                );
                CREATE INDEX IF NOT EXISTS ranges_country ON ranges(version, country, first);
                CREATE TABLE IF NOT EXISTS country_counts (
                    version TEXT NOT NULL REFERENCES versions(version) ON DELETE CASCADE,
                    country TEXT NOT NULL, ranges INTEGER NOT NULL, networks INTEGER NOT NULL,
                    PRIMARY KEY(version,country)
                );
            """)
        self.path.chmod(0o600)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _meta(self, key: str) -> str:
        with self.connect() as db:
            row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
            return str(row[0]) if row else ""

    def _set_meta(self, values: dict[str, str]) -> None:
        with self.connect() as db:
            db.executemany(
                "INSERT INTO metadata VALUES (?,?) ON CONFLICT(key) "
                "DO UPDATE SET value=excluded.value",
                values.items(),
            )

    @property
    def active_version(self) -> str:
        return self._meta("active_version")

    def status(self) -> dict[str, Any]:
        version = self.active_version
        with self.connect() as db:
            row = db.execute(
                "SELECT imported_at,row_count,sha256 FROM versions WHERE version=?", (version,)
            ).fetchone()
        return {
            "source": SOURCE,
            "attribution": ATTRIBUTION,
            "version": version,
            "ready": bool(row),
            "imported_at": row[0] if row else None,
            "ranges": row[1] if row else 0,
            "sha256": row[2] if row else "",
            "last_check": float(self._meta("last_check") or 0),
            "last_error": self._meta("last_error"),
            "updating": self.update_lock.locked(),
            "candidate": self._meta("candidate"),
            "notice": "Country identifies an IP allocation, not a person's physical location.",
        }

    def require_version(self, version: str = "") -> str:
        version = version or self.active_version
        with self.connect() as db:
            found = db.execute("SELECT 1 FROM versions WHERE version=?", (version,)).fetchone()
        if not found:
            raise FirewallError("Download a valid GeoIP database before applying country rules")
        return version

    def lookup(self, address: str, version: str = "") -> dict[str, Any]:
        ip = ipaddress.IPv4Address(address)
        result: dict[str, Any] = {
            "address": str(ip),
            "country": None,
            "source": SOURCE,
            "version": version or self.active_version,
            "attribution": ATTRIBUTION,
        }
        if not ip.is_global or ip.is_multicast:
            return {**result, "status": "special"}
        if not result["version"]:
            return {**result, "status": "unavailable"}
        with self.connect() as db:
            row = db.execute(
                "SELECT last,country FROM ranges WHERE version=? AND first<=? "
                "ORDER BY first DESC LIMIT 1",
                (result["version"], int(ip)),
            ).fetchone()
        if row and int(ip) <= row[0]:
            return {**result, "country": row[1], "status": "known"}
        return {**result, "status": "unknown"}

    def countries(
        self,
        search: str = "",
        offset: int = 0,
        limit: int = 50,
        *,
        negate: str | list[str] = "",
    ) -> dict[str, Any]:
        self._page(offset, limit)
        if len(search) > 32:
            raise ValueError("Search is limited to 32 characters")
        version = self.active_version
        cleaned = search.upper().replace("%", "").replace("_", "")
        excluded = validate_display_negation(negate, {"query": cleaned})
        pattern = "%" + cleaned + "%"
        match = "country NOT LIKE ?" if "query" in excluded else "country LIKE ?"
        with self.connect() as db:
            total = db.execute(
                f"SELECT count(*) FROM country_counts WHERE version=? AND {match}",
                (version, pattern),
            ).fetchone()[0]
            rows = db.execute(
                "SELECT country,ranges,networks FROM country_counts WHERE version=? "
                f"AND {match} ORDER BY country LIMIT ? OFFSET ?",
                (version, pattern, limit, offset),
            ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
            "version": version,
            "source": SOURCE,
            "attribution": ATTRIBUTION,
        }

    def entries(
        self,
        country: str,
        offset: int = 0,
        limit: int = 50,
        query: str = "",
        *,
        negate: str | list[str] = "",
    ) -> dict[str, Any]:
        self._page(offset, limit)
        country = country_code(country)
        query = query.strip()
        excluded = validate_display_negation(negate, {"query": query})
        if len(query) > 32:
            raise ValueError("Search is limited to one IPv4 address or subnet")
        low, high = 0, 2**32 - 1
        if query:
            try:
                network = ipaddress.IPv4Network(query, strict=False)
            except ValueError as exc:
                raise ValueError("Enter a valid IPv4 address or subnet to search") from exc
            low, high = int(network.network_address), int(network.broadcast_address)
        version = self.active_version
        match = "first<=? AND last>=?"
        if "query" in excluded:
            match = f"NOT ({match})"
        where = f"version=? AND country=? AND ({match})"
        parameters = (version, country, high, low)
        with self.connect() as db:
            total = db.execute(f"SELECT count(*) FROM ranges WHERE {where}", parameters).fetchone()[
                0
            ]
            rows = db.execute(
                f"SELECT first,last FROM ranges WHERE {where} ORDER BY first LIMIT ? OFFSET ?",
                (*parameters, limit, offset),
            ).fetchall()
        return {
            "items": [
                {
                    "first": str(ipaddress.IPv4Address(row[0])),
                    "last": str(ipaddress.IPv4Address(row[1])),
                }
                for row in rows
            ],
            "total": total,
            "offset": offset,
            "limit": limit,
            "query": query,
            "country": country,
            "version": version,
            "source": SOURCE,
            "attribution": ATTRIBUTION,
        }

    @staticmethod
    def _page(offset: int, limit: int) -> None:
        if not 0 <= offset <= MAX_ROWS or not 1 <= limit <= 200:
            raise ValueError("Invalid pagination")

    def networks(self, country: str, version: str = "") -> Generator[str, None, None]:
        country = country_code(country)
        version = self.require_version(version)
        with self.connect() as db:
            count = db.execute(
                "SELECT networks FROM country_counts WHERE version=? AND country=?",
                (version, country),
            ).fetchone()
            if not count:
                raise FirewallError(f"The GeoIP database contains no ranges for {country}")
            cursor = db.execute(
                "SELECT first,last FROM ranges WHERE version=? AND country=? ORDER BY first",
                (version, country),
            )
            for row in cursor:
                yield from (
                    str(net)
                    for net in ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(row[0]), ipaddress.IPv4Address(row[1])
                    )
                )

    def import_csv(self, stream: BinaryIO, version: str, *, compressed: bool = True) -> str:
        """Stream an immutable candidate into one transaction; never change the live version."""
        version = validate_version(version)
        deadline = time.monotonic() + DOWNLOAD_TIMEOUT
        source = gzip.GzipFile(fileobj=stream) if compressed else stream
        digest = hashlib.sha256()
        counts: dict[str, tuple[int, int]] = {}
        expanded = 0
        ipv4_rows = 0
        previous: dict[int, int] = {4: -1, 6: -1}
        try:
            with self.connect() as db:
                if db.execute("SELECT 1 FROM versions WHERE version=?", (version,)).fetchone():
                    raise FirewallError("This GeoIP version is already imported")
                # Keep at most four immutable releases. Active and in-flight rollback
                # versions are pinned; SQLite reuses reclaimed pages on later imports.
                pinned = {
                    str(row[0])
                    for row in db.execute(
                        "SELECT value FROM metadata WHERE key IN "
                        "('active_version','activation_previous','activation_pending','candidate')"
                    )
                }
                old = [
                    str(row[0])
                    for row in db.execute("SELECT version FROM versions ORDER BY imported_at DESC")
                ]
                remaining = len(old)
                for expired in reversed(old):
                    if remaining < 4:
                        break
                    if expired not in pinned:
                        db.execute("DELETE FROM versions WHERE version=?", (expired,))
                        remaining -= 1
                if remaining >= 4:
                    raise FirewallError(
                        "GeoIP has too many pinned releases; complete recovery first"
                    )
                db.execute("INSERT INTO versions VALUES (?,?,0,'')", (version, time.time()))
                for index in range(MAX_ROWS + 1):
                    raw = source.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    expanded += len(raw)
                    if (
                        len(raw) > MAX_LINE
                        or expanded > MAX_EXPANDED
                        or index == MAX_ROWS
                        or time.monotonic() > deadline
                    ):
                        raise FirewallError("GeoIP database exceeds import limits")
                    digest.update(raw)
                    row = next(csv.reader([raw.decode("utf-8").rstrip("\r\n")], strict=True))
                    if len(row) != 3:
                        raise FirewallError("GeoIP CSV must contain start IP, end IP and country")
                    first, last = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
                    # DB-IP uses ZZ for unknown/unallocated ranges. Keep them unknown,
                    # never turn the sentinel into an allow/block country.
                    country = "ZZ" if row[2] == "ZZ" else country_code(row[2])
                    if first.version != last.version or int(first) > int(last):
                        raise FirewallError("GeoIP contains an invalid address range")
                    if int(first) <= previous[first.version]:
                        raise FirewallError("GeoIP ranges overlap or are not sorted")
                    previous[first.version] = int(last)
                    if first.version == 6 or country == "ZZ":
                        continue
                    for low, high in public_ranges(int(first), int(last)):
                        networks = sum(
                            1
                            for _ in ipaddress.summarize_address_range(
                                ipaddress.IPv4Address(low), ipaddress.IPv4Address(high)
                            )
                        )
                        old_count, old_networks = counts.get(country, (0, 0))
                        counts[country] = old_count + 1, old_networks + networks
                        db.execute(
                            "INSERT INTO ranges VALUES (?,?,?,?)", (version, low, high, country)
                        )
                        ipv4_rows += 1
                if ipv4_rows == 0:
                    raise FirewallError("GeoIP database has no IPv4 ranges")
                db.executemany(
                    "INSERT INTO country_counts VALUES (?,?,?,?)",
                    [(version, code, count, nets) for code, (count, nets) in counts.items()],
                )
                db.execute(
                    "UPDATE versions SET row_count=?,sha256=? WHERE version=?",
                    (ipv4_rows, digest.hexdigest(), version),
                )
                db.execute(
                    "INSERT INTO metadata VALUES ('candidate',?) ON CONFLICT(key) "
                    "DO UPDATE SET value=excluded.value",
                    (version,),
                )
        except (ValueError, UnicodeError, csv.Error, gzip.BadGzipFile, EOFError, OSError) as exc:
            raise FirewallError("GeoIP database is malformed or unreadable") from exc
        finally:
            if compressed:
                source.close()
        return version

    def activate(self, version: str, apply: Callable[[str], None] | None = None) -> None:
        version = self.require_version(version)
        old = self.active_version
        # Activation intent survives a crash. The runtime recovers the old kernel sets first.
        self._set_meta({"activation_previous": old, "activation_pending": version})
        try:
            if apply:
                apply(version)
            self._set_meta(
                {
                    "active_version": version,
                    "candidate": "",
                    "last_error": "",
                    "activation_pending": "",
                    "activation_previous": "",
                }
            )
        except Exception as exc:
            # A failure after kernel swaps but before SQLite commit must restore the old
            # projection as well. Intent stays durable if compensation itself fails.
            try:
                if apply and old:
                    apply(old)
                self._set_meta(
                    {"active_version": old, "activation_pending": "", "activation_previous": ""}
                )
            except Exception as recovery:
                raise FirewallError(
                    "GeoIP activation requires recovery; old database retained"
                ) from recovery
            raise exc

    def recover_activation(self) -> str | None:
        if not self._meta("activation_pending"):
            return None
        old = self._meta("activation_previous")
        self._set_meta({"active_version": old})
        return old

    def finish_recovery(self) -> None:
        self._set_meta({"activation_pending": "", "activation_previous": ""})

    def update(
        self, apply: Callable[[str], None] | None = None, version: str = ""
    ) -> dict[str, Any]:
        version = validate_version(version or datetime.now(UTC).strftime("%Y-%m"))
        if not self.update_lock.acquire(blocking=False):
            raise FirewallError("A GeoIP update is already running")
        try:
            self._set_meta({"last_check": str(time.time())})
            if version == self.active_version:
                return {**self.status(), "updating": False}
            with self.connect() as db:
                exists = db.execute("SELECT 1 FROM versions WHERE version=?", (version,)).fetchone()
            if not exists:
                opener = urllib.request.build_opener(NoRedirect())
                request = urllib.request.Request(
                    download_url(version),
                    headers={"User-Agent": "OpenMikroRout-GeoIP/1", "Accept-Encoding": "identity"},
                )
                started = time.monotonic()
                with (
                    opener.open(request, timeout=15) as response,
                    tempfile.TemporaryFile() as stream,
                ):
                    if response.status != 200 or response.geturl() != download_url(version):
                        raise FirewallError("Unexpected GeoIP download response")
                    size = 0
                    while chunk := response.read(65536):
                        size += len(chunk)
                        if size > MAX_DOWNLOAD or time.monotonic() - started > DOWNLOAD_TIMEOUT:
                            raise FirewallError("GeoIP download exceeds size/time limit")
                        stream.write(chunk)
                    stream.seek(0)
                    self.import_csv(stream, version)
            if apply:
                # The caller holds the firewall lock around activate() so DB pointer and
                # kernel swaps share one critical section with configuration application.
                apply(version)
            else:
                self.activate(version)
            return {**self.status(), "updating": False}
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            message = "GeoIP download failed; the previous database remains active"
            self._set_meta({"last_error": message})
            raise FirewallError(message) from exc
        except FirewallError as exc:
            self._set_meta({"last_error": str(exc)[:300]})
            raise
        finally:
            self.update_lock.release()
