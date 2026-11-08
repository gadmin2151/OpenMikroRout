"""Exercise the native classifier and policy contract with synthetic local PCAPs."""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

BINARY = str(Path(sys.argv[1]).resolve())
LICENSE_PROFILE = sys.argv[2] if len(sys.argv) > 2 else "lgpl-only"
if LICENSE_PROFILE not in ("lgpl-only", "not-for-profit", "commercial-license"):
    raise SystemExit("Invalid declared engine license profile")


def policy(action: str = "allow") -> dict[str, Any]:
    return {
        "schema": 1,
        "generation": "a" * 64,
        "epoch": 7,
        "mode": "observe",
        "engine_license_profile": LICENSE_PROFILE,
        "interfaces": ["lo"],
        "source_networks": ["192.0.2.0/24"],
        "ct_mask": 0xFFFFFF,
        "ct_valid_bit": 64,
        "ct_pending_bit": 128,
        "ct_epoch_shift": 8,
        "state_shifts": {"NEW": 0, "ESTABLISHED": 2, "RELATED": 4},
        "rules": [
            {
                "id": "rule-bittorrent",
                "action": action,
                "application_ids": ["app.bittorrent"],
                "connection_states": [],
            }
        ],
        "catalog": {
            "version": "test",
            "entries": [
                {
                    "id": "app.bittorrent",
                    "protocol_names": ["BitTorrent"],
                    "allow_over_port_deny": True,
                },
                {
                    "id": "app.youtube",
                    "protocol_names": ["YouTube"],
                    "domains": ["youtube.com"],
                    "allow_over_port_deny": False,
                },
            ],
        },
    }


def packet(
    payload: bytes = b"",
    *,
    reverse: bool = False,
    seq: int = 1001,
    ack: int = 2001,
    flags: int = 0x18,
    client_port: int = 40000,
) -> bytes:
    source, destination, sport, dport = "192.0.2.10", "198.51.100.20", client_port, 443
    if reverse:
        source, destination, sport, dport = destination, source, dport, sport
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    return ip + tcp + payload


def pcap(path: Path, packets: list[bytes]) -> None:
    content = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    for index, data in enumerate(packets):
        content += struct.pack("<IIII", index + 1, 0, len(data), len(data)) + data
    path.write_bytes(content)


def run(*arguments: str, ok: bool = True) -> dict[str, Any] | None:
    result = subprocess.run(
        [BINARY, *arguments], capture_output=True, text=True, timeout=15, check=False
    )
    if ok:
        assert result.returncode == 0, (arguments, result.stderr, result.stdout)
        value = json.loads(result.stdout)
        assert isinstance(value, dict)
        return cast(dict[str, Any], value)
    assert result.returncode != 0, arguments
    return None


caps = run("capabilities", "--json", "--license-profile", LICENSE_PROFILE)
assert caps and caps["engine"]["commit"] == "cd1d03a52f0c968f1835110d70f5da652171a5d5"
assert caps["ct_mask"] == 0xFFFFFF and caps["ct_pending_bit"] == 128
assert any(item["name"].lower() == "bittorrent" for item in caps["protocols"])
handshake = b"\x13BitTorrent protocol" + b"\0" * 8 + b"I" * 20 + b"-OM0001-" + b"P" * 12
assert len(handshake) == 68
packets = [
    packet(seq=1000, ack=0, flags=2),
    packet(reverse=True, seq=2000, ack=1001, flags=18),
    packet(seq=1001, ack=2001, flags=16),
    packet(handshake),
    packet(handshake, reverse=True, seq=2001, ack=1069),
]
with tempfile.TemporaryDirectory(prefix="omr-native-test-") as name:
    root = Path(name)
    config, capture = root / "policy.json", root / "traffic.pcap"
    data = policy()
    config.write_text(json.dumps(data))
    assert run("validate", "--policy", str(config), "--json") == {"schema": 1, "valid": True}
    pcap(capture, packets)
    result = run("replay", "--policy", str(config), "--pcap", str(capture), "--json")
    assert result and len(result["items"]) == 1, result
    flow = result["items"][0]
    assert flow["application_id"] == "app.bittorrent", flow
    assert flow["method"] == "dpi" and flow["decision"] == "allow", flow
    assert flow["packets"] == 5 and flow["bytes"] == sum(map(len, packets)), flow
    assert not flow["pending"] and flow["classification_state"] == "detected", flow
    data["rules"][0]["action"] = "block"
    config.write_text(json.dumps(data))
    blocked = run("replay", "--policy", str(config), "--pcap", str(capture))
    assert blocked and blocked["items"][0]["decision"] == "block", blocked
    # A different application on the same port never inherits the BitTorrent exception.
    data = policy()
    config.write_text(json.dumps(data))
    for host in (b"example.org", b"youtube.com"):
        pcap(capture, packets[:3] + [packet(b"GET / HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")])
        other = run("replay", "--policy", str(config), "--pcap", str(capture))
        assert other and all(
            item["decision"] in ("fallback", "block") for item in other["items"]
        ), other
    # Explicit protocol mapping alone does not grant an allow capability.
    data["catalog"]["entries"][0]["allow_over_port_deny"] = False
    config.write_text(json.dumps(data))
    pcap(capture, packets)
    weak = run("replay", "--policy", str(config), "--pcap", str(capture))
    assert weak and weak["items"][0]["decision"] != "allow", weak
    # Resource admission failure follows failure_policy, not the permissive
    # unknown-policy fallback. The second simultaneous pending flow must block.
    data = policy()
    data["unknown_policy"] = "firewall"
    data["failure_policy"] = "block"
    data["limits"] = {"max_pending": 1}
    config.write_text(json.dumps(data))
    pcap(capture, [packet(flags=2), packet(flags=2, client_port=40001)])
    capacity = run("replay", "--policy", str(config), "--pcap", str(capture))
    assert capacity and any(
        item["decision"] == "block" and item["reason"] == "pending_capacity"
        for item in capacity["items"]
    ), capacity
    data["limits"] = {}
    config.write_text(json.dumps(data))
    pcap(capture, [packet(flags=2, client_port=40000 + index) for index in range(21)])
    limited = run("replay", "--policy", str(config), "--pcap", str(capture))
    assert limited and any(
        item["decision"] == "block" and item["reason"] == "new_flow_rate"
        for item in limited["items"]
    ), limited
    # Malformed headers and oversized records are rejected, not interpreted as app traffic.
    pcap(capture, [b"\x45" * 19, bytes(40), packet(b"\x16\x03\x03\xff\xff")])
    run("replay", "--policy", str(config), "--pcap", str(capture))
    capture.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
        + struct.pack("<IIII", 0, 0, 1000000, 1000000)
    )
    run("replay", "--policy", str(config), "--pcap", str(capture), ok=False)
    changes: tuple[dict[str, Any], ...] = (
        {"ct_mask": 0xFFFFFFFF},
        {"epoch": 0},
        {"interfaces": []},
        {"source_networks": ["bad"]},
        {"ct_pending_bit": 0},
        {"mode": "disabled"},
    )
    for change in changes:
        invalid = policy() | change
        config.write_text(json.dumps(invalid))
        run("validate", "--policy", str(config), ok=False)
    config.write_text(json.dumps(policy()))
    alias = root / "symlink.json"
    alias.symlink_to(config)
    run("validate", "--policy", str(alias), ok=False)
    config.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    run("validate", "--policy", str(config), ok=False)
print(
    "Native policy, real nDPI BitTorrent DPI, allow/block, "
    "negative and bounded replay checks passed."
)
