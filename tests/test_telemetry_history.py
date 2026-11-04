import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import Settings, create_app
from app.telemetry import (
    InterfaceTelemetry,
    TelemetryCollector,
    TelemetrySnapshot,
    TrafficTelemetry,
)
from app.telemetry_history import RETENTION_SECONDS, TelemetryHistory


class Clock:
    def __init__(self) -> None:
        self.value = 10000.0

    def __call__(self) -> float:
        return self.value


def sample(clock: Clock, count: int, *, known: bool = True) -> TelemetrySnapshot:
    return TelemetrySnapshot(
        timestamp=clock(),
        demo=False,
        sample_seconds=0.2,
        traffic=TrafficTelemetry(available=True, interfaces=["eth0"]),
        interfaces=[
            InterfaceTelemetry(
                name="eth0",
                state="UP",
                physical=True,
                rx_bytes=count,
                tx_bytes=count * 2,
                rx_packets=count // 100,
                tx_packets=count // 50,
                rx_bps=1 if known else None,
                tx_bps=1 if known else None,
                rx_pps=1 if known else None,
                tx_pps=1 if known else None,
            )
        ],
    )


def history(tmp_path: Path, clock: Clock) -> TelemetryHistory:
    source = TelemetryCollector("linux", tmp_path)
    return TelemetryHistory(source, tmp_path, clock=clock, monotonic=clock)


def test_persistence_and_rates_are_independent_of_live_poll_interval(tmp_path: Path) -> None:
    clock = Clock()
    stored = history(tmp_path, clock)
    with patch.object(stored.source, "snapshot", return_value=sample(clock, 1000)) as reader:
        assert stored.record().traffic.rx_bps is None
        reader.assert_called_once_with(fast=True)
    clock.value += 1
    with patch.object(stored.source, "snapshot", return_value=sample(clock, 2000)):
        point = stored.record()
    assert point.traffic.rx_bps == 8000 and point.traffic.tx_bps == 16000
    assert point.interfaces[0].rx_pps == 10
    reopened = history(tmp_path, clock)
    result = reopened.snapshot(interface="eth0")
    assert result.available and len(result.points) == 2
    assert result.points[-1] == point
    assert reopened.path.stat().st_mode & 0o777 == 0o600
    assert reopened.snapshot(after=result.points[0].timestamp, interface="eth0").points == [point]


def test_responses_include_only_the_requested_series_without_losing_stored_interfaces(
    tmp_path: Path,
) -> None:
    clock = Clock()
    stored = history(tmp_path, clock)
    source = sample(clock, 1000)
    source.interfaces.append(source.interfaces[0].model_copy(update={"name": "eth1"}))
    with patch.object(stored.source, "snapshot", return_value=source):
        point = stored.record()
    assert len(point.interfaces) == 2
    assert stored.snapshot().points[0].interfaces == []
    assert [item.name for item in stored.snapshot(interface="eth0").points[0].interfaces] == [
        "eth0"
    ]
    assert [item.name for item in stored.snapshot(interface="eth1").points[0].interfaces] == [
        "eth1"
    ]
    assert stored.snapshot(interface="missing").points[0].interfaces == []
    assert stored.snapshot().points[0].traffic == point.traffic
    with sqlite3.connect(stored.path) as db:
        assert '"eth0"' in db.execute("SELECT payload FROM samples").fetchone()[0]
        assert '"eth1"' in db.execute("SELECT payload FROM samples").fetchone()[0]


def test_counter_reset_identity_change_and_sampling_outage_break_lines(tmp_path: Path) -> None:
    clock = Clock()
    stored = history(tmp_path, clock)
    for count, delay, known, expected in [
        (1000, 0, True, None),
        (2000, 1, True, 8000),
        (100, 1, True, None),
        (1000, 1, False, None),
        (2000, 10, True, None),
        (3000, -20, True, None),
    ]:
        clock.value += delay
        with patch.object(
            stored.source, "snapshot", return_value=sample(clock, count, known=known)
        ):
            assert stored.record().traffic.rx_bps == expected
    assert all(point.timestamp <= clock() for point in stored.snapshot().points)
    reopened = history(tmp_path, clock)
    clock.value += 1
    with patch.object(reopened.source, "snapshot", return_value=sample(clock, 4000)):
        assert reopened.record().traffic.rx_bps is None
    assert len(reopened.snapshot().points) >= 2


def test_history_retention_query_limits_and_incremental_cursor(tmp_path: Path) -> None:
    clock = Clock()
    stored = history(tmp_path, clock)
    with patch.object(stored.source, "snapshot", return_value=sample(clock, 1000)):
        stored.record()
    clock.value += RETENTION_SECONDS + 5
    with patch.object(stored.source, "snapshot", return_value=sample(clock, 2000)):
        stored.record()
    assert len(stored.snapshot(3600).points) == 1
    with sqlite3.connect(stored.path) as db:
        assert db.execute("SELECT count(*) FROM samples").fetchone()[0] == 1
    assert stored.snapshot(after=clock()).points == []
    for index in range(12):
        stored.snapshot(after=clock() - index)
    assert len(stored.cache) <= 8


def test_demo_and_live_history_are_separate(tmp_path: Path) -> None:
    clock = Clock()
    live = history(tmp_path, clock)
    demo = TelemetryHistory(TelemetryCollector("demo", tmp_path), tmp_path)
    demo.record()
    assert demo.path != live.path
    assert demo.snapshot().demo and demo.snapshot().points[0].demo
    assert live.snapshot().points == []


def test_corrupt_history_is_reported_without_disrupting_router(tmp_path: Path) -> None:
    clock = Clock()
    stored = history(tmp_path, clock)
    stored.path.write_bytes(b"not a database")
    result = stored.snapshot()
    assert not result.available and result.error and result.points == []
    assert stored.path.read_bytes() == b"not a database"


def test_background_sampling_runs_without_requests_and_stops(tmp_path: Path) -> None:
    source = TelemetryCollector("demo", tmp_path)
    stored = TelemetryHistory(source, tmp_path)
    stored.start()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if len(stored.snapshot().points) >= 2:
                break
            time.sleep(0.05)
        assert len(stored.snapshot().points) >= 2
    finally:
        stored.stop()
    assert stored.thread is not None and not stored.thread.is_alive()
    before = stored.snapshot().points
    stored.stop()
    assert stored.snapshot().points == before


def test_history_api_is_authenticated_read_only_and_survives_app_restart(tmp_path: Path) -> None:
    password = "test-only-history-password"
    settings = Settings(
        data_dir=tmp_path, auth_enabled=True, password=password, read_password=password
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/telemetry/history").status_code == 401
        client.post(
            "/api/login",
            headers={"X-NAT-Request": "1"},
            json={"username": "viewer", "password": password},
        )
        result = client.get("/api/telemetry/history?seconds=60")
        assert result.status_code == 200 and result.json()["available"]
        assert result.headers["cache-control"] == "no-store"
        for query in [
            "seconds=0",
            "seconds=999999",
            "after=-1",
            "after=nan",
            "after=inf",
            "interface=eth0;id",
            "interface=0123456789012345",
        ]:
            assert client.get("/api/telemetry/history?" + query).status_code == 422
    with TestClient(create_app(settings)) as client:
        client.post(
            "/api/login",
            headers={"X-NAT-Request": "1"},
            json={"username": "viewer", "password": password},
        )
        result = client.get("/api/telemetry/history?seconds=3600").json()
        assert result["available"] and result["points"]
