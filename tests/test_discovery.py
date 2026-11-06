import json
import struct
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.discovery import DiscoveryService
from app.discovery_models import DiscoverySettings, ScanRequest, ScanSettings
from app.discovery_protocols import parse_arp, parse_lldp, parse_mndp


def tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, len(value)) + value


def test_settings_are_disabled_and_require_explicit_interfaces() -> None:
    assert not DiscoverySettings().enabled
    assert not ScanSettings().enabled
    with pytest.raises(ValidationError):
        DiscoverySettings(enabled=True)
    with pytest.raises(ValidationError):
        ScanSettings(enabled=True, interfaces=["eth0;id"])
    with pytest.raises(ValidationError):
        ScanSettings(enabled=True, interfaces=["lo"])
    assert DiscoverySettings(interfaces=["eth0", "eth0"]).interfaces == ["eth0"]


def test_mndp_decodes_fields_with_bounds_and_no_control_characters() -> None:
    packet = b"\0\0\0\1" + b"".join(
        [
            tlv(1, bytes.fromhex("000c42000102")),
            tlv(5, b"Router\x00<script>"),
            tlv(7, b"7.15"),
            tlv(8, b"MikroTik"),
            tlv(12, b"RB5009"),
            tlv(16, b"ether2"),
            tlv(10, struct.pack("<I", 12345)),
            tlv(17, bytes([192, 168, 10, 1])),
        ]
    )
    row = parse_mndp(packet, "eth0", "192.168.10.2")
    assert row
    assert row["mac"] == "00:0c:42:00:01:02"
    assert row["hostname"] == "Router<script>"
    assert row["uptime_seconds"] == 12345
    assert row["addresses"] == ["192.168.10.1", "192.168.10.2"]
    assert parse_mndp(packet[:-1], "eth0", "192.168.10.2") is None
    assert parse_mndp(b"\0" * 20000, "eth0", "192.168.10.2") is None
    assert parse_mndp(b"\0" * 4 + tlv(5, b"no mac"), "eth0", "192.168.10.2") is None


def test_lldp_json0_preserves_segment_protocol_and_announced_capabilities() -> None:
    row = {
        "name": "eth0",
        "via": "CDP",
        "chassis": [
            {
                "id": [{"type": "mac", "value": "00:0c:42:00:01:02"}],
                "name": [{"value": "switch<script>"}],
                "descr": [{"value": "Model X / release Y"}],
                "mgmt-ip": [{"value": "192.168.10.1"}, {"value": "fe80::1"}],
                "capability": [
                    {"type": "Router", "enabled": True},
                    {"type": "Wlan", "enabled": False},
                ],
            }
        ],
        "port": [{"id": [{"value": "gi1/0/1"}], "ttl": [{"value": "120"}]}],
    }
    result = parse_lldp(json.dumps({"lldp": [{"interface": [row]}]}), {"eth0"})
    assert len(result) == 1
    assert result[0]["source"] == "cdp"
    assert result[0]["capabilities"] == ["Router"]
    assert result[0]["addresses"] == ["192.168.10.1"]
    assert parse_lldp(json.dumps({"lldp": [{"interface": [row]}]}), {"eth1"}) == []
    assert parse_lldp('{"lldp":null}', {"eth0"}) == []
    assert parse_lldp('{"lldp":[{"interface":[{"name":[]}]}]}', {"eth0"}) == []
    with pytest.raises(ValueError):
        parse_lldp("not json", {"eth0"})


def test_arp_rejects_incomplete_multicast_and_other_interfaces() -> None:
    rows = [
        {"dev": "eth0", "lladdr": "00:0c:42:00:01:02", "dst": "10.0.0.2", "state": ["REACHABLE"]},
        {"dev": "eth0", "lladdr": "00:0c:42:00:01:03", "dst": "10.0.0.3", "state": ["FAILED"]},
        {"dev": "eth1", "lladdr": "00:0c:42:00:01:04", "dst": "10.0.0.4", "state": ["STALE"]},
        {"dev": "eth0", "lladdr": "01:0c:42:00:01:05", "dst": "10.0.0.5", "state": ["STALE"]},
    ]
    result = parse_arp(json.dumps(rows), {"eth0"})
    assert len(result) == 1
    assert result[0]["addresses"] == ["10.0.0.2"]
    assert parse_arp('[{"dev": []}]', {"eth0"}) == []


def test_inventory_keeps_provenance_multiple_ips_and_distinct_segments(tmp_path: Path) -> None:
    service = DiscoveryService(tmp_path, True, DiscoverySettings)
    now = time.time()
    service.ingest(
        {
            "interface": "eth0",
            "source": "arp",
            "mac": "00:0c:42:00:01:02",
            "addresses": ["10.0.0.2"],
        },
        now - 5,
    )
    service.ingest(
        {
            "interface": "eth0",
            "source": "mndp",
            "mac": "00:0c:42:00:01:02",
            "addresses": ["10.0.0.3"],
            "hostname": "Router",
            "model": "RB5009",
        },
        now,
    )
    service.ingest(
        {
            "interface": "eth1",
            "source": "mndp",
            "mac": "00:0c:42:00:01:02",
            "addresses": ["10.0.0.2"],
        },
        now,
    )
    page = service.hosts()
    assert page["total"] == 2
    host = service.hosts(interface="eth0")["items"][0]
    assert host["addresses"] == ["10.0.0.2", "10.0.0.3"]
    assert host["sources"] == ["arp", "mndp"]
    assert host["first_seen"] == now - 5
    assert service.hosts(query="Router")["total"] == 1
    assert service.hosts(query="%") == {
        "items": [],
        "total": 0,
        "offset": 0,
        "limit": 50,
        "demo": True,
    }
    assert service.hosts(limit=1)["total"] == 2
    assert len(service.hosts(offset=1, limit=1)["items"]) == 1
    assert service.host(host["id"])["model"] == "RB5009"
    assert service.path.stat().st_mode & 0o777 == 0o600


def test_scan_address_merges_only_unambiguous_same_segment_and_flags_conflict(
    tmp_path: Path,
) -> None:
    service = DiscoveryService(tmp_path, True, DiscoverySettings)
    service.ingest_scan(
        "eth0",
        [
            {
                "state": "up",
                "addresses": ["10.0.0.2"],
                "ports": [{"port": 22, "state": "open"}],
                "os_guesses": ["Linux"],
            }
        ],
    )
    service.ingest(
        {
            "interface": "eth0",
            "source": "arp",
            "mac": "00:0c:42:00:01:02",
            "addresses": ["10.0.0.2"],
        }
    )
    assert service.hosts()["total"] == 1
    assert service.hosts()["items"][0]["sources"] == ["arp", "scan"]
    assert service.hosts()["items"][0]["os_guesses"] == ["Linux"]
    service.ingest(
        {
            "interface": "eth0",
            "source": "arp",
            "mac": "00:0c:42:00:01:03",
            "addresses": ["10.0.0.2"],
        }
    )
    assert service.hosts()["total"] == 2
    assert all(host["conflicting_addresses"] == ["10.0.0.2"] for host in service.hosts()["items"])


def test_expiry_survives_restart_and_demo_never_starts_listener(tmp_path: Path) -> None:
    settings = DiscoverySettings(enabled=True, interfaces=["eth0"], stale_seconds=30)
    service = DiscoveryService(tmp_path, True, lambda: settings)
    service.ingest(
        {
            "interface": "eth0",
            "source": "mndp",
            "mac": "00:0c:42:00:01:02",
            "addresses": ["10.0.0.2"],
        },
        time.time() - 60,
    )
    service.maintain()
    assert not service.socket
    assert service.hosts()["items"][0]["stale"]
    service.close()
    recovered = DiscoveryService(tmp_path, True, lambda: settings)
    assert recovered.hosts()["items"][0]["stale"]
    with pytest.raises(KeyError):
        recovered.host("not-known")
    with pytest.raises(ValueError):
        recovered.hosts(limit=500)


@pytest.mark.parametrize(
    "fields",
    [
        {"target": "--script=evil"},
        {"target": "http://10.0.0.2"},
        {"target": "::1"},
        {"profile": "custom", "ports": "80;id"},
        {"profile": "udp", "ports": "1-129"},
        {"profile": "custom", "ports": "65535-1"},
        {"profile": "full", "ports": "22"},
    ],
)
def test_scan_request_rejects_injection_and_unbounded_udp(fields: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        ScanRequest.model_validate(
            {"kind": "ports", "interface": "eth0", "target": "10.0.0.2", **fields}
        )
