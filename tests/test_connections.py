import json
import socket
import struct
from pathlib import Path

from fastapi.testclient import TestClient

from app.connections import (
    EVENT_LIMIT,
    ConnectionMonitor,
    ConnectionQuery,
    matches,
    parse_conntrack,
    parse_packet,
)
from app.main import Settings, create_app

FLOW = (
    "ipv4 2 tcp 6 120 ESTABLISHED src=198.51.100.9 dst=203.0.113.10 "
    "sport=50000 dport=3389 packets=2 bytes=120 src=192.168.10.10 "
    "dst=198.51.100.9 sport=3389 dport=50000 packets=3 bytes=240 [ASSURED] mark=0 use=1"
)


def packet(
    *, flags: int = 2, protocol: int = 6, fragment: int = 0, source: str = "198.51.100.9"
) -> bytes:
    payload = b"SECRET-PAYLOAD-NEVER-STORED"
    transport = struct.pack("!HH", 50000, 3389) + b"\0" * 8 + bytes([0x50, flags]) + b"\0" * 6
    header = (
        bytes([0x45, 0])
        + struct.pack("!HHH", 20 + len(transport) + len(payload), 0, fragment)
        + bytes([64, protocol])
        + b"\0\0"
        + socket.inet_aton(source)
        + socket.inet_aton("203.0.113.10")
    )
    return header + transport + payload


def test_conntrack_original_reply_nat_and_accounting() -> None:
    rows = parse_conntrack(FLOW, {"203.0.113.10": "eth0"})
    assert len(rows) == 1
    row = rows[0]
    assert row.source == "198.51.100.9" and row.destination == "203.0.113.10"
    assert row.translated_destination == "192.168.10.10" and row.translated_port == 3389
    assert row.state == "ESTABLISHED" and row.interface == "eth0"
    assert row.packets == 5 and row.bytes == 360
    assert row.expires_in == 120


def test_outgoing_and_malformed_flows_are_not_reported_as_incoming() -> None:
    outgoing = FLOW.replace(
        "src=198.51.100.9 dst=203.0.113.10", "src=192.168.10.10 dst=198.51.100.9"
    ).replace(
        "src=192.168.10.10 dst=198.51.100.9 sport=3389",
        "src=198.51.100.9 dst=203.0.113.10 sport=3389",
    )
    assert not parse_conntrack(outgoing, {"203.0.113.10": "eth0"})
    for value in [
        "garbage",
        FLOW.replace("sport=50000", "sport=999999"),
        FLOW.replace("198.51.100.9", "invalid"),
        FLOW.replace("src=192.168.10.10", "missing=192.168.10.10"),
    ]:
        assert not parse_conntrack(value, {"203.0.113.10": "eth0"})


def test_port_only_dnat_is_reported_with_translated_port() -> None:
    redirected = FLOW.replace("src=192.168.10.10", "src=203.0.113.10").replace(
        "sport=3389", "sport=3390"
    )
    rows = parse_conntrack(redirected, {})
    assert len(rows) == 1
    assert rows[0].destination_port == 3389
    assert rows[0].translated_destination == "203.0.113.10"
    assert rows[0].translated_port == 3390


def test_attempts_parse_headers_only_and_ignore_ack_fragments() -> None:
    row = parse_packet(packet(), "eth0", 1000)
    assert row and row.state == "SYN" and row.destination_port == 3389
    assert "SECRET" not in row.model_dump_json()
    assert parse_packet(packet(flags=18), "eth0", 1000) is None
    assert parse_packet(packet(fragment=1), "eth0", 1000) is None
    assert parse_packet(b"short", "eth0", 1000) is None
    udp = parse_packet(packet(protocol=17), "eth0", 1000)
    assert udp and udp.state == "DATAGRAM"


def test_attempt_storage_is_bounded_deduplicated_and_expires() -> None:
    clock = [1000.0]
    monitor = ConnectionMonitor(False, clock=lambda: clock[0])
    row = parse_packet(packet(), "eth0", clock[0])
    assert row
    monitor.observe(row)
    row2 = parse_packet(packet(), "eth0", clock[0])
    assert row2
    monitor.observe(row2)
    assert len(monitor.events) == 1 and next(iter(monitor.events.values())).observations == 2
    for index in range(EVENT_LIMIT + 3):
        value = row.model_copy(update={"id": str(index)})
        monitor.observe(value)
    assert len(monitor.events) == EVENT_LIMIT
    clock[0] += 3601
    assert monitor.snapshot(ConnectionQuery(kind="attempts")).total == 0


def test_connection_filters_are_composable_and_do_not_change_data() -> None:
    row = parse_conntrack(FLOW, {"203.0.113.10": "eth0"})[0]
    assert matches(
        row,
        ConnectionQuery(
            source="198.51.100.0/24",
            port="3389,443",
            protocol="tcp",
            state="ESTABLISHED",
            interface="eth0",
        ),
    )
    for query in [
        ConnectionQuery(source="192.0.2.0/24"),
        ConnectionQuery(port="80"),
        ConnectionQuery(protocol="udp"),
        ConnectionQuery(state="SYN_SENT"),
        ConnectionQuery(search="not-present"),
    ]:
        assert not matches(row, query)


def test_api_filters_validate_and_read_accounts_can_monitor(tmp_path: Path) -> None:
    password = "test-only-connections-password"
    with TestClient(
        create_app(
            Settings(
                data_dir=tmp_path, auth_enabled=True, password=password, read_password=password
            )
        )
    ) as client:
        assert client.get("/api/connections").status_code == 401
        client.post(
            "/api/login",
            headers={"X-NAT-Request": "1"},
            json={"username": "viewer", "password": password},
        )
        result = client.get("/api/connections?kind=attempts&protocol=tcp&port=3389")
        assert result.status_code == 200 and result.json()["demo"] and result.json()["matched"] == 1
        for query in [
            "source=::/0",
            "source=invalid",
            "port=0",
            "limit=9999",
            "interface=eth0;id",
            "kind=shell",
            "protocol=unknown",
        ]:
            assert client.get("/api/connections?" + query).status_code == 422, query
        assert client.get("/api/connections?source=192.0.2.0/24").json()["items"] == []


def test_live_reader_uses_bounded_fixed_commands_and_reports_missing_source(tmp_path: Path) -> None:
    (tmp_path / "net").mkdir()
    (tmp_path / "net/nf_conntrack").write_text(FLOW)

    def command(args: list[str]) -> tuple[str | None, bool]:
        if "address" in args:
            return json.dumps([{"ifname": "eth0", "addr_info": [{"local": "203.0.113.10"}]}]), False
        if "route" in args:
            return '[{"dev":"eth0"}]', False
        return None, False

    monitor = ConnectionMonitor(False, proc_root=tmp_path, command=command)
    snapshot = monitor.snapshot(ConnectionQuery())
    assert snapshot.available and snapshot.total == 1
    disabled = ConnectionMonitor(False, enabled=False)
    disabled.start()
    disabled.stop()
    assert not disabled.snapshot(ConnectionQuery(kind="attempts")).available
