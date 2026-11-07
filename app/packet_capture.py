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
from app.display_filters import validate_display_negation
from app.link_models import LinkModel, interface_name
from app.list_filters import (
    Condition,
    FieldSpec,
    FilterNode,
    Group,
    parse_expression,
    port_intervals,
)
from app.wireguard import WireGuardError

MAX_OUTPUT_BYTES = 32768
MAX_BATCH_BYTES = 8192
FLUSH_SECONDS = 0.2
HEARTBEAT_SECONDS = 0.1
CaptureMatchField = Literal["source", "destination", "port", "protocol"]
CAPTURE_FILTERS = {
    "source": FieldSpec("ipv4", operators=("eq", "neq", "in", "not_in")),
    "destination": FieldSpec("ipv4", operators=("eq", "neq", "in", "not_in")),
    "protocol": FieldSpec(
        "enum", operators=("eq", "neq", "in", "not_in"), options=("tcp", "udp", "icmp")
    ),
    "port": FieldSpec("ports"),
}


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
    negate: list[CaptureMatchField] = Field(default_factory=list, max_length=4)
    expression: FilterNode | None = None

    _interface = field_validator("interface")(capture_interface)

    @field_validator("expression", mode="before")
    @classmethod
    def expression_node(cls, value: object) -> FilterNode | None:
        return parse_expression(value, CAPTURE_FILTERS)

    @field_validator("source", "destination")
    @classmethod
    def ipv4_network(cls, value: str) -> str:
        return str(ipaddress.IPv4Network(value, strict=False)) if value else ""

    @field_validator("negate")
    @classmethod
    def unique_negated_filters(cls, values: list[CaptureMatchField]) -> list[CaptureMatchField]:
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def protocol_port(self) -> Self:
        validate_display_negation(
            self.negate,
            {
                "source": self.source,
                "destination": self.destination,
                "port": self.port,
                "protocol": self.protocol if self.protocol != "all" else "",
            },
            maximum=4,
        )
        if self.protocol == "icmp" and "protocol" not in self.negate and self.port is not None:
            raise ValueError("ICMP does not have TCP/UDP ports")
        return self


def capture_expression_tokens(node: FilterNode) -> list[str]:
    """Only fixed BPF vocabulary and already validated typed values are emitted."""
    if isinstance(node, Group):
        result = ["("]
        for index, child in enumerate(node.children):
            if index:
                result.append(node.join)
            result.extend(capture_expression_tokens(child))
        return [*result, ")"]
    condition: Condition = node
    negative = condition.op in ("neq", "not_in")
    if condition.field == "protocol":
        values = condition.value.split(",")
        tokens = ["("]
        for index, protocol in enumerate(values):
            tokens += [*(["or"] if index else []), protocol]
        tokens.append(")")
    elif condition.field in ("source", "destination"):
        direction = "src" if condition.field == "source" else "dst"
        tokens = ["("]
        for index, network in enumerate(condition.value.split(",")):
            tokens += [*(["or"] if index else []), direction, "net", network]
        tokens.append(")")
    else:
        # A negative port condition includes packets with no TCP/UDP ports.
        # Keep this guard LOCAL to the leaf so OR groups remain meaningful.
        present = [
            "(",
            "(",
            "tcp",
            "or",
            "udp",
            ")",
            "and",
            "ip[6:2]",
            "&",
            "0x1fff",
            "=",
            "0",
            "and",
            "(",
            "ip[0]",
            "&",
            "0x0f",
            ")",
            ">=",
            "5",
            "and",
            "ip[2:2]",
            ">=",
            "(",
            "(",
            "(",
            "ip[0]",
            "&",
            "0x0f",
            ")",
            "<<",
            "2",
            ")",
            "+",
            "4",
            ")",
            ")",
        ]
        if condition.op in ("empty", "not_empty"):
            return ["not", "(", *present, ")"] if condition.op == "empty" else present
        intervals = port_intervals(condition.value)
        if condition.op in ("gt", "gte", "lt", "lte"):
            threshold = intervals[0][0]
            low = threshold + (condition.op == "gt") if condition.op in ("gt", "gte") else 0
            high = threshold - (condition.op == "lt") if condition.op in ("lt", "lte") else 65535
            intervals = [(low, high)] if low <= high else []
        alternatives = ["("]
        for index, (low, high) in enumerate(intervals):
            alternatives += [
                *(["or"] if index else []),
                "port" if low == high else "portrange",
                str(low) if low == high else f"{low}-{high}",
            ]
        if not intervals:
            alternatives += ["ip", "and", "not", "ip"]
        alternatives.append(")")
        tokens = ["(", *present, "and", *alternatives, ")"]
    return ["not", "(", *tokens, ")"] if negative else tokens


def capture_command(binary: str, request: CaptureRequest) -> list[str]:
    # These tokens are generated exclusively from typed fields. Names/addresses
    # are never command fragments, BPF source, file names or additional options.
    condition = ["ip"]
    if request.protocol != "all":
        protocol = [request.protocol]
        condition += [
            "and",
            *(["not", "(", *protocol, ")"] if "protocol" in request.negate else protocol),
        ]
    if request.port is not None and (request.protocol == "all" or "protocol" in request.negate):
        condition += ["and", "(", "tcp", "or", "udp", ")"]
    filters: tuple[tuple[CaptureMatchField, str | int | None, list[str]], ...] = (
        ("source", request.source, ["src", "net"]),
        ("destination", request.destination, ["dst", "net"]),
        ("port", request.port, ["port"]),
    )
    for field, value, prefix in filters:
        if value:
            tokens = [*prefix, str(value)]
            condition += [
                "and",
                *(["not", "(", *tokens, ")"] if field in request.negate else tokens),
            ]
    if request.expression is not None:
        condition += ["and", *capture_expression_tokens(request.expression)]
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
