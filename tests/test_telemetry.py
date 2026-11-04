import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.firewall import DemoDriver
from app.main import Settings, create_app
from app.models import Configuration
from app.telemetry import (
    FLOW_LIMIT,
    READ_LIMIT,
    TelemetryCollector,
    command_output,
    observed_devices,
    parse_destinations,
    parse_interfaces,
    read_bounded,
)


class Clock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def interface(
    root: Path, name: str, index: int, *, physical: bool = True, mac: str = "02:00:00:00:00:01"
) -> None:
    write(root / name / "operstate", "up\n")
    write(root / name / "ifindex", str(index))
    write(root / name / "address", mac)
    if physical:
        (root / name / "device").mkdir()


def netdev(root: Path, rows: dict[str, tuple[int, int, int, int]]) -> None:
    lines = [
        "Inter-| Receive | Transmit",
        " face |bytes packets errs drop |bytes packets errs drop",
    ]
    for name, (rx_bytes, tx_bytes, rx_packets, tx_packets) in rows.items():
        lines.append(
            f"{name}: {rx_bytes} {rx_packets} 2 3 0 0 0 0 {tx_bytes} {tx_packets} 4 5 0 0 0 0"
        )
    write(root / "net/dev", "\n".join(lines))


def collector(tmp_path: Path, clock: Clock) -> TelemetryCollector:
    return TelemetryCollector(
        "linux",
        tmp_path / "data",
        proc_root=tmp_path / "proc",
        sys_root=tmp_path / "sys",
        monotonic=clock,
        clock=clock,
        command=lambda _args: (None, False),
    )


def test_rates_use_monotonic_elapsed_and_physical_ports_only(tmp_path: Path) -> None:
    clock = Clock()
    source = collector(tmp_path, clock)
    interface(tmp_path / "sys", "eth0", 2)
    interface(tmp_path / "sys", "br-lan", 3, physical=False)
    netdev(tmp_path / "proc", {"eth0": (1000, 2000, 10, 20), "br-lan": (9000, 9000, 90, 90)})
    first = source.snapshot()
    assert first.traffic.available
    assert first.traffic.interfaces == ["eth0"]
    assert first.traffic.rx_bytes == 1000
    assert first.traffic.rx_bps is None
    assert first.traffic.rx_dropped == 3
    clock.value += 4
    netdev(tmp_path / "proc", {"eth0": (1500, 3000, 50, 100), "br-lan": (19000, 19000, 190, 190)})
    second = source.snapshot()
    assert second.sample_seconds == 4
    assert second.traffic.rx_bps == 1000
    assert second.traffic.tx_bps == 2000
    assert second.traffic.rx_pps == 10
    assert second.traffic.tx_pps == 20
    assert second.interfaces[1].rx_bps == 20000
    assert second.traffic.scope == "physical_interfaces"


def test_reset_replaced_and_disappearing_interfaces_never_produce_spikes(tmp_path: Path) -> None:
    clock = Clock()
    source = collector(tmp_path, clock)
    interface(tmp_path / "sys", "eth0", 2)
    netdev(tmp_path / "proc", {"eth0": (1000, 2000, 10, 20)})
    source.snapshot()
    clock.value += 3
    netdev(tmp_path / "proc", {"eth0": (10, 3000, 1, 50)})
    reset = source.snapshot()
    assert reset.traffic.rx_bps is None
    assert reset.traffic.tx_bps == 8000 / 3
    clock.value += 3
    write(tmp_path / "sys/eth0/ifindex", "4")
    netdev(tmp_path / "proc", {"eth0": (99999, 99999, 999, 999)})
    assert source.snapshot().traffic.tx_bps is None
    clock.value += 3
    netdev(tmp_path / "proc", {})
    assert not source.snapshot().traffic.available
    clock.value += 3
    netdev(tmp_path / "proc", {"eth0": (199999, 199999, 1999, 1999)})
    assert source.snapshot().traffic.rx_bps is None


def test_cache_returns_independent_snapshot_and_fallback_is_explicit(tmp_path: Path) -> None:
    clock = Clock()
    source = collector(tmp_path, clock)
    interface(tmp_path / "sys", "eth0", 2, physical=False)
    interface(tmp_path / "sys", "br0", 3, physical=False)
    netdev(tmp_path / "proc", {"eth0": (1000, 2000, 10, 20), "br0": (900, 900, 9, 9)})
    first = source.snapshot()
    assert first.traffic.scope == "primary_interface_fallback"
    assert first.traffic.interfaces == ["eth0"]
    first.interfaces.clear()
    clock.value += 0.05
    netdev(tmp_path / "proc", {})
    cached = source.snapshot()
    assert len(cached.interfaces) == 2
    assert cached.timestamp == 1000
    clock.value += 0.15
    assert not source.snapshot().traffic.available


def test_fast_samples_update_every_200ms_without_inventory_commands(tmp_path: Path) -> None:
    clock = Clock()
    calls: list[list[str]] = []

    def command(args: list[str]) -> tuple[str | None, bool]:
        calls.append(args)
        return ("[]" if "neigh" in args else ""), False

    source = TelemetryCollector(
        "linux",
        tmp_path / "data",
        proc_root=tmp_path / "proc",
        sys_root=tmp_path / "sys",
        monotonic=clock,
        clock=clock,
        command=command,
    )
    interface(tmp_path / "sys", "eth0", 2)
    with patch("app.telemetry.shutil.which", side_effect=lambda binary: f"/bin/{binary}"):
        netdev(tmp_path / "proc", {"eth0": (1000, 2000, 10, 20)})
        source.snapshot()
        assert len(calls) == 2
        for index in range(1, 21):
            clock.value = 1000 + index * 0.2
            netdev(tmp_path / "proc", {"eth0": (1000 + index * 100, 2000, 10 + index, 20)})
            sample = source.snapshot(fast=True)
            assert sample.timestamp == clock.value
            assert sample.traffic.rx_bytes == 1000 + index * 100
            assert sample.traffic.rx_bps is not None
            assert abs(sample.traffic.rx_bps - 4000) < 0.001
            assert not sample.details_included
            assert sample.devices.items == []
        assert len(calls) == 2
        source.snapshot()
        assert len(calls) == 2
        clock.value = 1005
        source.snapshot()
        assert len(calls) == 4


def test_slow_inventory_never_blocks_fast_counter_requests(tmp_path: Path) -> None:
    clock = Clock()
    entered = threading.Event()
    release = threading.Event()

    def command(_args: list[str]) -> tuple[str | None, bool]:
        entered.set()
        assert release.wait(3), "Test did not release inventory command"
        return "[]", False

    source = TelemetryCollector(
        "linux",
        tmp_path / "data",
        proc_root=tmp_path / "proc",
        sys_root=tmp_path / "sys",
        monotonic=clock,
        clock=clock,
        command=command,
    )
    interface(tmp_path / "sys", "eth0", 2)
    netdev(tmp_path / "proc", {"eth0": (1000, 2000, 10, 20)})
    with patch("app.telemetry.shutil.which", return_value="/bin/ip"), ThreadPoolExecutor(2) as pool:
        slow = pool.submit(source.snapshot)
        try:
            assert entered.wait(1)
            fast = pool.submit(source.snapshot, fast=True).result(timeout=1)
            assert fast.traffic.rx_bytes == 1000
            assert not slow.done()
        finally:
            release.set()
        assert slow.result(timeout=1).details_included


def test_missing_metrics_are_null_and_do_not_break_system_metrics(tmp_path: Path) -> None:
    clock = Clock()
    source = collector(tmp_path, clock)
    write(tmp_path / "proc/uptime", "42.5 12.0")
    write(tmp_path / "proc/meminfo", "MemTotal: 1024 kB\nMemAvailable: 256 kB\n")
    write(tmp_path / "proc/stat", "cpu 100 0 100 800 0 0 0 0 50 0\n")
    first = source.snapshot()
    assert first.traffic.rx_bytes is None
    assert first.connections.active is None
    assert first.devices.count is None
    assert not first.top_destinations.available
    assert first.system.uptime_seconds == 42.5
    assert first.system.memory_total_bytes == 1024 * 1024
    assert first.system.memory_used_bytes == 768 * 1024
    assert first.system.cpu_percent is None
    clock.value += 3
    write(tmp_path / "proc/stat", "cpu 150 0 150 900 0 0 0 0 70 0\n")
    write(tmp_path / "proc/sys/net/netfilter/nf_conntrack_count", "0")
    second = source.snapshot()
    assert second.connections.available
    assert second.connections.active == 0
    assert second.system.cpu_percent == 50


def test_devices_dedupe_dhcp_neighbors_and_ignore_expired_failed_own_multicast() -> None:
    neighbors = json.dumps(
        [
            {
                "dst": "192.168.1.2",
                "lladdr": "02:00:00:00:00:02",
                "dev": "br0",
                "state": ["REACHABLE"],
            },
            {
                "dst": "192.168.1.20",
                "lladdr": "02:00:00:00:00:02",
                "dev": "br0",
                "state": ["STALE"],
            },
            {"dst": "192.168.1.3", "lladdr": "02:00:00:00:00:03", "state": ["FAILED"]},
            {"dst": "192.168.1.4", "lladdr": "02:00:00:00:00:04", "state": ["INCOMPLETE"]},
            {"dst": "192.168.1.5", "lladdr": "01:00:5e:00:00:05", "state": ["STALE"]},
            {"dst": "192.168.1.1", "lladdr": "02:00:00:00:00:01", "state": ["STALE"]},
        ]
    )
    leases = (
        "2000 02:00:00:00:00:02 192.168.1.2 laptop *\n"
        "0 02:00:00:00:00:09 192.168.1.9 static-client *\n"
        "999 02:00:00:00:00:08 192.168.1.8 expired *\n"
        "invalid\n"
    )
    result = observed_devices(neighbors, leases, 1000, {"02:00:00:00:00:01"})
    assert result.count == 2
    assert result.neighbors == 1
    assert result.dhcp_leases == 2
    laptop = next(item for item in result.items if item.hostname == "laptop")
    assert laptop.interface == "br0"
    assert laptop.source == "neighbor+dhcp"
    assert observed_devices(None, "", 1000, set()).count == 0
    assert observed_devices("broken json", None, 1000, set()).count is None


def flow(destination: str, *, byte_count: int | None = 100, port: int = 443) -> str:
    accounting = f"packets=3 bytes={byte_count} " if byte_count is not None else ""
    return (
        f"ipv4 2 tcp 6 120 ESTABLISHED src=192.168.1.10 dst={destination} "
        f"sport=50000 dport={port} {accounting}src=10.0.0.20 dst=192.168.1.10 "
        "sport=443 dport=50000 packets=900 bytes=999999 mark=0 use=1"
    )


def test_destinations_use_original_tuple_accounting_and_top_ten() -> None:
    text = "\n".join(
        [
            flow("203.0.113.2", byte_count=200),
            flow("203.0.113.2", byte_count=300),
            flow("203.0.113.3", byte_count=900),
        ]
    )
    result = parse_destinations(text)
    assert result.basis == "bytes"
    assert [item.address for item in result.items] == ["203.0.113.3", "203.0.113.2"]
    assert result.items[1].bytes == 500
    assert result.items[1].packets == 6
    assert result.items[1].connections == 2
    assert result.items[1].port == 443
    assert "10.0.0.20" not in {item.address for item in result.items}
    many = parse_destinations("\n".join(flow(f"203.0.113.{index}") for index in range(1, 30)))
    assert len(many.items) == 10


def test_destinations_without_accounting_use_connection_counts_and_bounds() -> None:
    result = parse_destinations(
        "\n".join([flow("203.0.113.2", byte_count=None)] * 3 + [flow("203.0.113.3")])
    )
    assert result.basis == "connections"
    assert result.items[0].address == "203.0.113.2"
    assert result.items[0].bytes is None
    assert result.items[0].packets is None
    assert parse_destinations(None).available is False
    assert parse_destinations("").available is True
    bounded = parse_destinations("\n".join([flow("203.0.113.2")] * (FLOW_LIMIT + 1)))
    assert bounded.partial
    assert bounded.items[0].connections == FLOW_LIMIT


def test_bounded_reads_commands_and_invalid_interface_names(tmp_path: Path) -> None:
    write(tmp_path / "big", "a" * (READ_LIMIT + 10))
    text, truncated = read_bounded(tmp_path / "big")
    assert text is not None and len(text) == READ_LIMIT and truncated
    output, truncated = command_output([sys.executable, "-c", f"print('x'*{READ_LIMIT + 100})"])
    assert output is not None and len(output) == READ_LIMIT and truncated
    netdev(tmp_path, {"../oops": (1, 2, 3, 4), "lo": (1, 2, 3, 4)})
    assert parse_interfaces((tmp_path / "net/dev").read_text(), tmp_path / "sys") == []


def test_demo_is_explicit_cache_safe_and_cumulative_counters_are_monotonic(tmp_path: Path) -> None:
    clock = Clock()
    source = TelemetryCollector("demo", tmp_path, monotonic=clock, clock=clock)
    first = source.snapshot()
    assert first.demo
    assert first.traffic.rx_bps is not None and first.traffic.rx_bps > 0
    assert first.devices.count == 8
    for delta in (3, 100, 1000, 10000):
        clock.value += delta
        second = source.snapshot()
        assert second.traffic.rx_bytes is not None and first.traffic.rx_bytes is not None
        assert second.traffic.rx_bytes >= first.traffic.rx_bytes
        first = second


def test_telemetry_endpoint_requires_linux_session_and_never_changes_config(tmp_path: Path) -> None:
    settings = Settings(mode="linux", data_dir=tmp_path, password="test-only-strong-password")
    application = create_app(settings, DemoDriver(Configuration()))
    with TestClient(application) as client:
        assert client.get("/api/telemetry").status_code == 401
        client.post(
            "/api/login", headers={"X-NAT-Request": "1"}, json={"password": settings.password}
        )
        before = client.get("/api/state").json()
        with patch("app.telemetry.shutil.which", return_value=None):
            response = client.get("/api/telemetry")
        fast = client.get("/api/telemetry?fast=true")
        assert fast.status_code == 200
        assert fast.json()["details_included"] is False
        assert response.status_code == 200
        assert response.json()["demo"] is False
        assert response.headers["cache-control"] == "no-store"
        after = client.get("/api/state").json()
        assert after["revision"] == before["revision"]
        assert after["config"] == before["config"]
