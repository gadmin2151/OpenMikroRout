"""Opt-in tcpdump checks limited to synthetic loopback TCP/UDP in the test container."""

import asyncio
import os
import shutil
import socket
import struct
import subprocess
import sys
from contextlib import aclosing
from pathlib import Path
from typing import Literal

import pytest

from app.packet_capture import CaptureRequest, PacketCapture, capture_command

pytestmark = pytest.mark.skipif(
    sys.platform != "linux"
    or os.environ.get("NAT_RUN_KERNEL_TESTS") != "1"
    or not shutil.which("tcpdump"),
    reason="Opt-in Linux/NET_RAW test requires tcpdump and synthetic loopback traffic",
)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_native_tcpdump_streams_headers_before_stop_and_never_prints_payload(
    protocol: Literal["tcp", "udp"],
) -> None:
    secret = b"TEST-PAYLOAD-MUST-NOT-APPEAR-IN-CAPTURE"

    async def scenario() -> None:
        kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            if protocol == "tcp":
                receiver.listen(1)
            port = receiver.getsockname()[1]
            capture = PacketCapture(False)
            output = ""
            async with (
                asyncio.timeout(8),
                aclosing(
                    capture.stream(CaptureRequest(interface="lo", protocol=protocol, port=port))
                ) as stream,
            ):
                started = await anext(stream)
                assert started and started["type"] == "started"
                # libpcap opens the listener before tcpdump prints its readiness
                # message. Do not race the synthetic packet against startup.
                while "listening on" not in output:
                    event = await anext(stream)
                    if event is not None:
                        assert event["type"] != "completed", event
                        output += event.get("text", "")
                with socket.socket(socket.AF_INET, kind) as sender:
                    sender.settimeout(2)
                    if protocol == "tcp":
                        sender.connect(("127.0.0.1", port))
                        connection, _ = receiver.accept()
                        with connection:
                            connection.settimeout(2)
                            sender.sendall(secret)
                            assert connection.recv(256) == secret
                    else:
                        sender.sendto(secret, ("127.0.0.1", port))
                        assert receiver.recvfrom(256)[0] == secret
                while f"127.0.0.1.{port}" not in output:
                    event = await anext(stream)
                    if event is not None:
                        assert event["type"] != "completed", event
                        output += event.get("text", "")
                assert protocol.upper() in output.upper()
                assert secret.decode() not in output
                assert capture.lock.locked()  # Results arrived while capture was still active.
            assert not capture.lock.locked()

    asyncio.run(scenario())


def test_native_negated_bpf_selects_only_expected_synthetic_packets(tmp_path: Path) -> None:
    """Exercise libpcap's real parser and matching without observing host traffic."""
    rows = [
        (17, "192.0.2.1", "203.0.113.1", 41001, 53),
        (17, "192.0.2.2", "203.0.113.1", 41002, 53),
        (17, "192.0.2.2", "203.0.113.2", 41003, 53),
        (17, "192.0.2.2", "203.0.113.2", 41004, 54),
        (6, "192.0.2.2", "203.0.113.2", 41005, 54),
        (1, "192.0.2.99", "203.0.113.2", 0, 0),
        (6, "192.0.2.2", "203.0.113.2", 41007, 55),
        (17, "192.0.2.8", "203.0.113.2", 53, 55),
    ]
    # DLT_RAW pcap consists entirely of packets made here; no packet bytes from
    # the router, workstation or other interfaces are read by the test.
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    patterns: list[str] = []
    for protocol, source, destination, sport, dport in rows:
        if protocol == 17:
            transport = struct.pack("!HHHH", sport, dport, 8, 0)
        elif protocol == 6:
            transport = struct.pack("!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | 2, 0, 0, 0)
        else:
            transport = b"\x08\x00\x00\x00\x00\x01\x00\x01"
        packet = (
            struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(transport), 0, 0, 64, protocol, 0)
            + socket.inet_aton(source)
            + socket.inet_aton(destination)
            + transport
        )
        data += struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet
        patterns.append(
            f"{source}.{sport} > {destination}.{dport}"
            if protocol != 1
            else f"{source} > {destination}: ICMP"
        )
    capture = tmp_path / "synthetic.pcap"
    capture.write_bytes(data)
    cases: list[tuple[dict[str, object], set[int]]] = [
        ({}, set(range(8))),
        ({"source": "192.0.2.1", "negate": ["source"]}, {1, 2, 3, 4, 5, 6, 7}),
        ({"destination": "203.0.113.1", "negate": ["destination"]}, {2, 3, 4, 5, 6, 7}),
        ({"port": 53, "negate": ["port"]}, {3, 4, 6}),
        ({"protocol": "tcp", "negate": ["protocol"]}, {0, 1, 2, 3, 5, 7}),
        ({"protocol": "tcp", "port": 54, "negate": ["protocol"]}, {3}),
        ({"protocol": "icmp", "port": 54, "negate": ["protocol"]}, {3, 4}),
        ({"protocol": "udp", "port": 54, "negate": ["protocol", "port"]}, {6}),
        (
            {
                "protocol": "udp",
                "source": "192.0.2.1",
                "destination": "203.0.113.1",
                "port": 53,
                "negate": ["source", "destination", "port"],
            },
            {3},
        ),
    ]

    def term(field: str, op: str, value: str = "") -> dict[str, object]:
        return {"kind": "condition", "field": field, "op": op, "value": value}

    cases += [
        (
            {
                "expression": {
                    "kind": "group",
                    "join": "or",
                    "children": [
                        term("source", "eq", "192.0.2.1"),
                        term("port", "eq", "55"),
                    ],
                }
            },
            {0, 6, 7},
        ),
        (
            {
                "expression": {
                    "kind": "group",
                    "join": "or",
                    "children": [
                        term("protocol", "eq", "icmp"),
                        term("port", "neq", "53"),
                    ],
                }
            },
            {3, 4, 5, 6},
        ),
        (
            {
                "expression": {
                    "kind": "group",
                    "join": "or",
                    "children": [
                        term("protocol", "eq", "icmp"),
                        term("port", "gt", "41004"),
                    ],
                }
            },
            {4, 5, 6},
        ),
        (
            {
                "expression": {
                    "kind": "group",
                    "join": "or",
                    "children": [
                        term("protocol", "eq", "icmp"),
                        term("port", "gt", "65535"),
                    ],
                }
            },
            {5},
        ),
        ({"expression": term("port", "empty")}, {5}),
        ({"expression": term("port", "not_empty")}, {0, 1, 2, 3, 4, 6, 7}),
        (
            {
                "protocol": "udp",
                "expression": {
                    "kind": "group",
                    "join": "or",
                    "children": [
                        term("source", "eq", "192.0.2.1"),
                        term("port", "gt", "41003"),
                    ],
                },
            },
            {0, 3},
        ),
        (
            {
                "expression": {
                    "kind": "group",
                    "join": "or",
                    "children": [
                        {
                            "kind": "group",
                            "join": "and",
                            "children": [
                                term("protocol", "eq", "tcp"),
                                term("port", "gt", "41005"),
                            ],
                        },
                        {
                            "kind": "group",
                            "join": "and",
                            "children": [
                                term("source", "eq", "192.0.2.1"),
                                term("port", "neq", "53"),
                            ],
                        },
                    ],
                }
            },
            {6},
        ),
    ]
    for parameters, expected in cases:
        request = CaptureRequest.model_validate({"interface": "lo", **parameters})
        command = capture_command("tcpdump", request)
        condition = command[command.index("--") + 1 :]
        result = subprocess.run(
            [
                "tcpdump",
                "-nn",
                "-q",
                "-r",
                str(capture),
                *(["-Z", "root"] if os.geteuid() == 0 else []),
                "--",
                *condition,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        assert result.returncode == 0, (parameters, result.stderr)
        actual = {index for index, pattern in enumerate(patterns) if pattern in result.stdout}
        assert actual == expected, (parameters, actual, expected, result.stdout)
        assert len(result.stdout.splitlines()) == len(expected), result.stdout


def test_native_advanced_ports_include_zero_and_handle_missing_headers(tmp_path: Path) -> None:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for index, (protocol, fragment, transport) in enumerate(
        [
            (17, 0, struct.pack("!HHHH", 0, 0, 8, 0)),
            (6, 0, struct.pack("!HHIIHHHH", 0, 0, 0, 0, (5 << 12) | 2, 0, 0, 0)),
            (17, 0, b""),
            (17, 1, b"fragment"),
        ],
        start=1,
    ):
        packet = (
            struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(transport), 0, fragment, 64, protocol, 0)
            + socket.inet_aton(f"192.0.2.{index}")
            + socket.inet_aton("203.0.113.1")
            + transport
        )
        data += struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet
    path = tmp_path / "ports-zero-or-missing.pcap"
    path.write_bytes(data)
    for operation, value, expected in [
        ("lt", "1", {1, 2}),
        ("lte", "1", {1, 2}),
        ("empty", "", {3, 4}),
        ("not_empty", "", {1, 2}),
        ("neq", "1", {1, 2, 3, 4}),
    ]:
        request = CaptureRequest.model_validate(
            {
                "interface": "lo",
                "expression": {
                    "kind": "condition",
                    "field": "port",
                    "op": operation,
                    "value": value,
                },
            }
        )
        args = capture_command("tcpdump", request)
        result = subprocess.run(
            [
                "tcpdump",
                "-nn",
                "-q",
                "-r",
                str(path),
                *(["-Z", "root"] if os.geteuid() == 0 else []),
                "--",
                *args[args.index("--") + 1 :],
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        assert result.returncode == 0, (operation, result.stderr)
        actual = {index for index in range(1, 5) if f"192.0.2.{index}" in result.stdout}
        assert actual == expected, (operation, actual, expected, result.stdout)
