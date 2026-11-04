"""Private, bounded SQLite history sampled independently of browser sessions."""

from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, Field

from app.telemetry import (
    IFNAME,
    INTERFACE_LIMIT,
    InterfaceTelemetry,
    TelemetryCollector,
    TelemetrySnapshot,
)

log = logging.getLogger(__name__)
RETENTION_SECONDS = 3600
SAMPLE_SECONDS = 1
MAX_POINTS = RETENTION_SECONDS + 1
MAX_SAMPLE_BYTES = 65536
RATE_NAMES = ("rx_bps", "tx_bps", "rx_pps", "tx_pps")
COUNTER_NAMES = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")


class HistoryRates(BaseModel):
    rx_bps: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    tx_bps: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    rx_pps: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    tx_pps: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class HistoryInterface(HistoryRates):
    name: str = Field(min_length=1, max_length=15, pattern=r"^[A-Za-z0-9_.:@-]+$")


class HistoryPoint(BaseModel):
    timestamp: float = Field(ge=0, allow_inf_nan=False)
    demo: bool
    traffic: HistoryRates
    interfaces: list[HistoryInterface] = Field(max_length=INTERFACE_LIMIT)


class HistoryResponse(BaseModel):
    available: bool
    demo: bool
    timestamp: float
    interval_seconds: int = SAMPLE_SECONDS
    retention_seconds: int = RETENTION_SECONDS
    points: list[HistoryPoint] = Field(default_factory=list)
    error: str = ""


def interface_rates(
    current: InterfaceTelemetry, previous: InterfaceTelemetry | None, elapsed: float | None
) -> HistoryInterface:
    rates: dict[str, float | None] = dict.fromkeys(RATE_NAMES)
    if previous is not None and elapsed is not None:
        for index, (rate, counter) in enumerate(zip(RATE_NAMES, COUNTER_NAMES, strict=True)):
            difference = getattr(current, counter) - getattr(previous, counter)
            # The live collector also invalidates rates when an interface identity changes.
            if difference >= 0 and getattr(current, rate) is not None:
                rates[rate] = difference / elapsed * (8 if index < 2 else 1)
    return HistoryInterface(name=current.name, **rates)


class TelemetryHistory:
    def __init__(
        self,
        source: TelemetryCollector,
        data_dir: Path,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.source, self.clock, self.monotonic = source, clock, monotonic
        self.demo = source.demo
        self.path = data_dir / ("demo-telemetry.sqlite3" if self.demo else "telemetry.sqlite3")
        self.lock = threading.Lock()
        self.previous: TelemetrySnapshot | None = None
        self.previous_at: float | None = None
        self.error = ""
        self.initialized = False
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.cache: OrderedDict[tuple[int, float | None, str], tuple[float, HistoryResponse]] = (
            OrderedDict()
        )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=2)

    def _initialize(self) -> None:
        if self.initialized:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise OSError("Telemetry history must be a regular database")
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if not self.path.is_file():
                raise OSError("Telemetry history must be a regular database") from None
        else:
            os.close(descriptor)
        # SQLite creates WAL/SHM with the database's mode, so protect it before opening.
        self.path.chmod(0o600)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS samples ("
                "bucket INTEGER PRIMARY KEY, timestamp REAL NOT NULL, payload TEXT NOT NULL)"
            )
        self.initialized = True

    def _failure(self, exc: Exception) -> None:
        if not self.error:
            log.error("Persistent telemetry history unavailable: %s", exc)
        self.error = "История временно недоступна. Проверьте журнал сервиса."
        self.cache.clear()

    def record(self) -> HistoryPoint:
        # Never run neighbor/conntrack inventory from the background history sampler.
        snapshot = self.source.snapshot(fast=True)
        now = self.monotonic()
        previous = self.previous
        elapsed = now - self.previous_at if self.previous_at is not None else None
        if (
            elapsed is None
            or not 0 < elapsed <= 5
            or previous is None
            or snapshot.timestamp <= previous.timestamp
            or snapshot.timestamp - previous.timestamp > 5
        ):
            elapsed = None
        old = {item.name: item for item in previous.interfaces} if previous else {}
        interfaces = [
            interface_rates(item, old.get(item.name), elapsed)
            for item in snapshot.interfaces[:INTERFACE_LIMIT]
        ]
        self.previous, self.previous_at = snapshot, now
        selected = [item for item in interfaces if item.name in snapshot.traffic.interfaces]
        totals: dict[str, float | None] = {}
        for key in RATE_NAMES:
            readings = [getattr(item, key) for item in selected]
            totals[key] = (
                sum(readings) if readings and all(x is not None for x in readings) else None
            )
        point = HistoryPoint(
            timestamp=snapshot.timestamp,
            demo=self.demo,
            traffic=HistoryRates(**totals),
            interfaces=interfaces,
        )
        payload = point.model_dump_json()
        if len(payload.encode()) > MAX_SAMPLE_BYTES:
            raise ValueError("Telemetry sample exceeds the history size limit")
        with self.lock:
            self._initialize()
            with self._connect() as db:
                db.execute(
                    "INSERT OR REPLACE INTO samples VALUES (?, ?, ?)",
                    (math.floor(point.timestamp), point.timestamp, payload),
                )
                # The future bound also repairs history after a backwards wall-clock correction.
                db.execute(
                    "DELETE FROM samples WHERE bucket < ? OR bucket > ?",
                    (math.floor(point.timestamp) - RETENTION_SECONDS, math.floor(point.timestamp)),
                )
            self.cache.clear()
            if self.error:
                log.info("Persistent telemetry history recovered")
            self.error = ""
        return point

    def snapshot(
        self, seconds: int = 60, after: float | None = None, interface: str = ""
    ) -> HistoryResponse:
        if not 60 <= seconds <= RETENTION_SECONDS or (
            after is not None and (not math.isfinite(after) or after < 0)
        ):
            raise ValueError("Invalid telemetry history range")
        if interface and not IFNAME.fullmatch(interface):
            raise ValueError("Invalid telemetry interface")
        now = self.clock()
        with self.lock:
            key = (seconds, after, interface)
            cached = self.cache.get(key)
            if cached is not None and 0 <= self.monotonic() - cached[0] < 1:
                return cached[1].model_copy(deep=True)
            try:
                self._initialize()
                cutoff = max(now - seconds, after if after is not None else now - seconds)
                points = []
                with self._connect() as db:
                    rows = db.execute(
                        "SELECT payload FROM samples WHERE bucket >= ? AND bucket <= ? "
                        "AND timestamp > ? AND timestamp <= ? ORDER BY bucket LIMIT ?",
                        (math.floor(cutoff), math.floor(now), cutoff, now, MAX_POINTS),
                    )
                    for (payload,) in rows:
                        if len(payload.encode()) > MAX_SAMPLE_BYTES:
                            raise ValueError("Stored telemetry sample exceeds its size limit")
                        raw = json.loads(payload)
                        if (
                            not isinstance(raw, dict)
                            or not isinstance(raw.get("interfaces"), list)
                            or len(raw["interfaces"]) > INTERFACE_LIMIT
                        ):
                            raise ValueError("Invalid stored telemetry sample")
                        # Stream one bounded JSON row, and instantiate only the requested series.
                        raw["interfaces"] = (
                            [
                                item
                                for item in raw["interfaces"]
                                if isinstance(item, dict) and item.get("name") == interface
                            ][:1]
                            if interface
                            else []
                        )
                        point = HistoryPoint.model_validate(raw)
                        if point.demo != self.demo:
                            raise ValueError("Telemetry history mode mismatch")
                        points.append(point)
                result = HistoryResponse(
                    available=not self.error,
                    demo=self.demo,
                    timestamp=now,
                    points=points,
                    error=self.error,
                )
                self.cache[key] = (self.monotonic(), result)
                self.cache.move_to_end(key)
                while len(self.cache) > 8:
                    self.cache.popitem(last=False)
                return result.model_copy(deep=True)
            except (sqlite3.Error, OSError, ValueError) as exc:
                self._failure(exc)
                return HistoryResponse(
                    available=False, demo=self.demo, timestamp=now, error=self.error
                )

    def start(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()

        def sample() -> None:
            while not self.stop_event.is_set():
                started = self.monotonic()
                try:
                    self.record()
                except (sqlite3.Error, OSError, ValueError) as exc:
                    with self.lock:
                        self._failure(exc)
                self.stop_event.wait(max(0.1, SAMPLE_SECONDS - (self.monotonic() - started)))

        self.thread = threading.Thread(target=sample, daemon=True, name="telemetry-history")
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                log.error("Persistent telemetry sampler did not stop within five seconds")
