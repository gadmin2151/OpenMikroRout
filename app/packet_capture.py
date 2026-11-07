"""Opt-in IPv4 header summaries on local interfaces, with no packet files or shell filters."""

import ipaddress
import os
import shutil
import socket
import threading
import time
from collections import deque
from collections.abc import AsyncGenerator
from contextlib import aclosing
from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from app.diagnostics import DiagnosticEvent, rolling_output, stream_process_output
from app.link_models import LinkModel, interface_name
from app.wireguard import WireGuardError

MAX_OUTPUT_BYTES = 32768
MAX_BATCH_BYTES = 8192
FLUSH_SECONDS = 0.2
HEARTBEAT_SECONDS = 0.1


def capture_interface(value: str) -> str:
    # Loopback and Linux's aggregate capture device are useful explicit choices;
    # other names use the same literal-device grammar as managed router links.
    return value if value in ("lo", "any") else interface_name(value)


class CaptureRequest(LinkModel):
    interface: str = Field(min_length=1, max_length=15)
    protocol: Literal["all", "tcp", "udp", "icmp"] = "all"
    source: str = Field(default="", max_length=18)
    destination: str = Field(default="", max_length=18)
    port: int | None = Field(default=None, ge=1, le=65535, strict=True)

    _interface = field_validator("interface")(capture_interface)

    @field_validator("source", "destination")
    @classmethod
    def ipv4_network(cls, value: str) -> str:
        return str(ipaddress.IPv4Network(value, strict=False)) if value else ""

    @model_validator(mode="after")
    def protocol_port(self) -> Self:
        if self.protocol == "icmp" and self.port is not None:
            raise ValueError("ICMP does not have TCP/UDP ports")
        return self


def capture_command(binary: str, request: CaptureRequest) -> list[str]:
    # These tokens are generated exclusively from typed fields. Names/addresses
    # are never command fragments, BPF source, file names or additional options.
    condition = ["ip"]
    if request.protocol != "all":
        condition += ["and", request.protocol]
    elif request.port is not None:
        condition += ["and", "(", "tcp", "or", "udp", ")"]
    if request.source:
        condition += ["and", "src", "net", request.source]
    if request.destination:
        condition += ["and", "dst", "net", request.destination]
    if request.port is not None:
        condition += ["and", "port", str(request.port)]
    return [
        binary,
        "-nn",
        "-l",
        "-tttt",
        "-q",
        "-p",
        "-i",
        request.interface,
        "-s",
        "96",
        # Native service capabilities deliberately omit CAP_KILL. Keep the
        # caller's UID so its child remains signalable on Stop/disconnect,
        # rather than tcpdump implicitly switching to another account.
        *(["-Z", "root"] if os.geteuid() == 0 else []),
        "--",
        *condition,
    ]


class PacketCapture:
    def __init__(self, demo: bool) -> None:
        self.demo = demo
        # A capture is independent of Ping and other active diagnostics.
        self.lock = threading.Lock()
        self.requests: deque[float] = deque()

    def interfaces(self) -> list[str]:
        if self.demo:
            return ["any", "eth0", "eth1", "br-lan", "wg0"]
        try:
            rows = socket.if_nameindex()
        except OSError as exc:
            raise WireGuardError("Cannot enumerate local capture interfaces") from exc
        names = set()
        for _, name in rows:
            try:
                names.add(capture_interface(name))
            except ValueError:
                continue
        return ["any", *sorted(names - {"any"})]

    def status(self) -> dict[str, Any]:
        try:
            names, error = self.interfaces(), ""
        except WireGuardError as exc:
            names, error = [], str(exc)
        return {
            "available": not error and (self.demo or bool(shutil.which("tcpdump"))),
            "interfaces": names,
            "demo": self.demo,
            "error": error,
            "active": self.lock.locked(),
        }

    async def stream(self, request: CaptureRequest) -> AsyncGenerator[DiagnosticEvent | None, None]:
        if not self.lock.acquire(blocking=False):
            raise WireGuardError("Another packet capture is running; stop it first")
        try:
            if request.interface not in self.interfaces():
                raise WireGuardError("The selected capture interface is not available on this host")
            binary = shutil.which("tcpdump") if not self.demo else ""
            if not self.demo and not binary:
                raise WireGuardError("Install tcpdump to capture packet headers")
            started = time.monotonic()
            while self.requests and self.requests[0] < started - 60:
                self.requests.popleft()
            if len(self.requests) >= 12:
                raise WireGuardError("Packet captures are limited to 12 starts per minute")
            self.requests.append(started)
            yield {
                "type": "started",
                "tool": "capture",
                "target": request.interface,
                "interface": request.interface,
                "protocol": request.protocol,
                "continuous": True,
            }
            if self.demo:
                output = "Demo mode: packet capture is disabled; no host traffic is inspected."
                yield {"type": "output", "text": output}
                yield {
                    "type": "completed",
                    "result": self.result(request, started, output, False, False),
                }
                return
            output = pending = ""
            total = 0
            truncated = False
            success = False
            flushed = heartbeat = started
            async with aclosing(
                stream_process_output(
                    capture_command(binary or "tcpdump", request), None, continuous=True
                )
            ) as events:
                async for event in events:
                    now = time.monotonic()
                    if event is not None:
                        if "text" in event:
                            text = event["text"]
                            total += len(text.encode("utf-8"))
                            truncated |= total > MAX_OUTPUT_BYTES
                            output = rolling_output(output, text, MAX_OUTPUT_BYTES)
                            truncated |= len((pending + text).encode("utf-8")) > MAX_BATCH_BYTES
                            pending = rolling_output(pending, text, MAX_BATCH_BYTES)
                        else:
                            success = event["exit_code"] == 0
                    # Limit browser writes independently of packet frequency. Even
                    # during a flood, idle ticks reach the transport for fresh auth
                    # and disconnect checks at least every 0.1 seconds.
                    if pending and now - flushed >= FLUSH_SECONDS:
                        yield {"type": "output", "text": pending}
                        pending, flushed = "", now
                    if event is None or now - heartbeat >= HEARTBEAT_SECONDS:
                        yield None
                        heartbeat = now
            if pending:
                yield {"type": "output", "text": pending}
            yield {
                "type": "completed",
                "result": self.result(request, started, output, success, truncated),
            }
        finally:
            self.lock.release()

    def result(
        self, request: CaptureRequest, started: float, output: str, success: bool, truncated: bool
    ) -> dict[str, Any]:
        return {
            "tool": "capture",
            "target": request.interface,
            "interface": request.interface,
            "address": "",
            "demo": self.demo,
            "success": success,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "output": output,
            "output_truncated": truncated,
        }
