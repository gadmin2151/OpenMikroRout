"""Opt-in tcpdump checks limited to synthetic loopback TCP/UDP in the test container."""

import asyncio
import os
import shutil
import socket
import sys
from contextlib import aclosing
from typing import Literal

import pytest

from app.packet_capture import CaptureRequest, PacketCapture

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
