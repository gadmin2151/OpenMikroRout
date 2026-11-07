import json
import socket
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

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


@pytest.mark.parametrize(
    ("field", "matching", "different"),
    [
        ("source", "198.51.100.0/24", "192.0.2.0/24"),
        ("destination", "203.0.113.0/24", "192.0.2.0/24"),
        ("port", "3389,443", "80,443"),
        ("protocol", "tcp", "udp"),
        ("state", "ESTABLISHED", "SYN_SENT"),
        ("interface", "eth0", "eth1"),
        ("search", "EsTaBlIsHeD", "not-present"),
    ],
)
def test_each_negation_inverts_the_whole_criterion(
    field: str, matching: str, different: str
) -> None:
    row = parse_conntrack(FLOW, {"203.0.113.10": "eth0"})[0]
    before = row.model_dump()
    assert matches(row, ConnectionQuery.model_validate({field: matching}))
    assert not matches(row, ConnectionQuery.model_validate({field: matching, "negate": [field]}))
    assert not matches(row, ConnectionQuery.model_validate({field: different}))
    assert matches(row, ConnectionQuery.model_validate({field: different, "negate": [field]}))
    assert row.model_dump() == before


def test_negated_destination_preserves_original_only_and_port_matches_any_tuple() -> None:
    row = parse_conntrack(FLOW, {"203.0.113.10": "eth0"})[0]
    row.translated_port = 3390
    assert matches(row, ConnectionQuery(destination="203.0.113.10"))
    assert not matches(row, ConnectionQuery(destination="203.0.113.10", negate=["destination"]))
    # Destination has always described the original tuple. DNAT is searchable
    # through free text; adding ! must not silently change positive IP matching.
    assert not matches(row, ConnectionQuery(destination="192.168.10.0/24"))
    assert matches(row, ConnectionQuery(destination="192.168.10.0/24", negate=["destination"]))
    for port in ("3389", "3390", "50000", "80,3380-3400"):
        assert matches(row, ConnectionQuery(port=port))
        assert not matches(row, ConnectionQuery(port=port, negate=["port"]))
    assert matches(row, ConnectionQuery(destination="192.0.2.0/24", negate=["destination"]))
    assert matches(row, ConnectionQuery(port="80,443", negate=["port"]))


def test_negated_filters_combine_with_positive_filters_using_and() -> None:
    row = parse_conntrack(FLOW, {"203.0.113.10": "eth0"})[0]
    query = ConnectionQuery(
        source="192.0.2.0/24",
        destination="203.0.113.0/24",
        protocol="udp",
        port="3389",
        negate=["source", "protocol"],
    )
    assert matches(row, query)
    query.state = "SYN_SENT"
    assert not matches(row, query)
    query.state = "ESTABLISHED"
    query.source = "198.51.100.0/24"
    assert not matches(row, query)


@pytest.mark.parametrize(
    "values",
    [
        {"negate": ["source"]},
        {"source": "", "negate": ["source"]},
        {"source": "192.0.2.1", "negate": [""]},
        {"source": "192.0.2.1", "negate": ["source,"]},
        {"source": "192.0.2.1", "negate": ["limit"]},
        {"source": "192.0.2.1", "negate": ["source;id"]},
        {"source": "192.0.2.1", "negate": ["source"] * 8},
        {"source": "192.0.2.1", "negate": ["source," * 8]},
        {"source": "192.0.2.1", "negate": ["s" * 101]},
        {"source": "192.0.2.1", "negate": [1]},
    ],
)
def test_negated_filter_validation_rejects_unbounded_unknown_or_empty(values: object) -> None:
    with pytest.raises(ValidationError):
        ConnectionQuery.model_validate(values)


def test_negated_csv_filter_query_is_typed_and_deduplicated() -> None:
    query = ConnectionQuery.model_validate(
        {"source": "192.0.2.1", "port": "443", "negate": ["source,port", "source"]}
    )
    assert query.negate == ["source", "port"]
    assert query.source == "192.0.2.1/32"


def test_advanced_expression_combines_groups_and_legacy_filters() -> None:
    expression = {
        "kind": "group",
        "join": "and",
        "children": [
            {
                "kind": "group",
                "join": "or",
                "children": [
                    {
                        "kind": "condition",
                        "field": "source",
                        "op": "in",
                        "value": "198.51.100.0/24",
                    },
                    {"kind": "condition", "field": "interface", "op": "eq", "value": "eth1"},
                ],
            },
            {"kind": "condition", "field": "port", "op": "not_in", "value": "80,443"},
            {"kind": "condition", "field": "bytes", "op": "gte", "value": "360"},
        ],
    }
    row = parse_conntrack(FLOW, {"203.0.113.10": "eth0"})[0]
    query = ConnectionQuery(expression=json.dumps(expression), protocol="tcp")
    assert matches(row, query)
    query.protocol = "udp"
    assert not matches(row, query)
    row.translated_port = 443
    query.protocol = "tcp"
    assert not matches(row, query)  # Exclude the entire original/translated port union.


def test_read_api_advanced_filters_are_validated_and_apply_before_counts(tmp_path: Path) -> None:
    password = "test-only-connections-password"
    with TestClient(
        create_app(
            Settings(
                data_dir=tmp_path, auth_enabled=True, password=password, read_password=password
            )
        )
    ) as client:
        expression = {
            "kind": "condition",
            "field": "source",
            "op": "not_in",
            "value": "192.0.2.0/24",
        }
        assert (
            client.get(
                "/api/connections", params={"expression": json.dumps(expression)}
            ).status_code
            == 401
        )
        client.post(
            "/api/login",
            headers={"X-NAT-Request": "1"},
            json={"username": "viewer", "password": password},
        )
        for kind in ("active", "attempts"):
            response = client.get(
                "/api/connections", params={"kind": kind, "expression": json.dumps(expression)}
            )
            assert response.status_code == 200, response.text
            assert response.json()["total"] == response.json()["matched"] == 1
            response = client.get(
                "/api/connections",
                params={"kind": kind, "protocol": "udp", "expression": json.dumps(expression)},
            )
            assert response.status_code == 200 and response.json()["matched"] == 0
        target_expression = {
            "kind": "group",
            "join": "and",
            "children": [
                {
                    "kind": "group",
                    "join": "or",
                    "children": [
                        {
                            "kind": "condition",
                            "field": "translated_destination",
                            "op": "in",
                            "value": "192.168.10.0/24",
                        },
                        {"kind": "condition", "field": "source", "op": "eq", "value": "192.0.2.1"},
                    ],
                },
                {"kind": "condition", "field": "destination_port", "op": "eq", "value": "3389"},
                {"kind": "condition", "field": "translated_port", "op": "in", "value": "3380-3390"},
                {"kind": "condition", "field": "source_port", "op": "gt", "value": "50000"},
            ],
        }
        response = client.get(
            "/api/connections", params={"expression": json.dumps(target_expression)}
        )
        assert response.status_code == 200, response.text
        assert response.json()["matched"] == 1
        # Quick destination remains the original tuple even with a DNAT expression.
        response = client.get(
            "/api/connections",
            params={"destination": "192.168.10.0/24", "expression": json.dumps(target_expression)},
        )
        assert response.status_code == 200 and response.json()["matched"] == 0
        for invalid in (
            {**expression, "field": "password"},
            {**expression, "op": "shell"},
            {**expression, "value": "::/0"},
            {**expression, "value": 1},
            {**expression, "extra": True},
            "[" * 1500 + "0" + "]" * 1500,
        ):
            encoded = invalid if isinstance(invalid, str) else json.dumps(invalid)
            assert client.get("/api/connections", params={"expression": encoded}).status_code == 422


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
            "negate=source",
            "source=192.0.2.1&negate=limit",
            "source=192.0.2.1&negate=",
            "source=192.0.2.1&negate=source,",
            "source=192.0.2.1&negate=" + ",".join(["source"] * 8),
        ]:
            assert client.get("/api/connections?" + query).status_code == 422, query
        assert client.get("/api/connections?source=192.0.2.0/24").json()["items"] == []
        for kind in ("active", "attempts"):
            positive = client.get(
                "/api/connections",
                params={"kind": kind, "source": "192.0.2.0/24", "protocol": "udp"},
            )
            assert positive.status_code == 200 and positive.json()["matched"] == 0
            negative = client.get(
                "/api/connections",
                params={
                    "kind": kind,
                    "source": "192.0.2.0/24",
                    "protocol": "udp",
                    "negate": "source,protocol",
                },
            )
            assert negative.status_code == 200, negative.text
            assert negative.json()["total"] == 1 and negative.json()["matched"] == 1
            excluded = client.get(
                "/api/connections",
                params={"kind": kind, "destination": "203.0.113.0/24", "negate": "destination"},
            )
            assert excluded.status_code == 200 and excluded.json()["matched"] == 0
        repeated = client.get(
            "/api/connections?source=192.0.2.1&protocol=udp&negate=source&negate=protocol"
        )
        assert repeated.status_code == 200 and repeated.json()["matched"] == 1


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
