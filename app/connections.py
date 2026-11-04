"""Bounded IPv4 connection inspection and payload-free ingress attempt observations."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import socket
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.models import port_spec
from app.telemetry import FLOW_LIMIT, IFNAME, command_output, read_bounded

EVENT_LIMIT = 1000
EVENT_TTL = 3600
CAPTURE_RATE = 2000
PROTOCOLS = {"tcp", "udp", "icmp", "gre", "esp", "ah"}
STATES = {
    "SYN_SENT",
    "SYN_RECV",
    "ESTABLISHED",
    "FIN_WAIT",
    "CLOSE_WAIT",
    "LAST_ACK",
    "TIME_WAIT",
    "CLOSE",
    "LISTEN",
    "NONE",
}


class ConnectionRow(BaseModel):
    id: str
    protocol: str
    source: str
    destination: str
    source_port: int | None = None
    destination_port: int | None = None
    translated_destination: str = ""
    translated_port: int | None = None
    state: str
    interface: str = ""
    packets: int | None = None
    bytes: int | None = None
    expires_in: int | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    observations: int = 1


class ConnectionQuery(BaseModel):
    kind: Literal["active", "attempts"] = "active"
    protocol: Literal["", "tcp", "udp", "icmp", "gre", "esp", "ah"] = ""
    source: str = Field(default="", max_length=32)
    destination: str = Field(default="", max_length=32)
    port: str = Field(default="", max_length=200)
    state: str = Field(default="", max_length=32, pattern=r"^[A-Z_]*$")
    interface: str = Field(default="", max_length=15, pattern=r"^[A-Za-z0-9_.:@-]*$")
    search: str = Field(default="", max_length=100)
    limit: int = Field(default=200, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=FLOW_LIMIT)

    @field_validator("source", "destination")
    @classmethod
    def subnet(cls, value: str) -> str:
        return str(ipaddress.IPv4Network(value, strict=False)) if value else ""

    @field_validator("port")
    @classmethod
    def ports(cls, value: str) -> str:
        return port_spec(value)


class ConnectionSnapshot(BaseModel):
    kind: str
    available: bool
    demo: bool
    timestamp: float
    total: int
    matched: int
    items: list[ConnectionRow]
    partial: bool = False
    interfaces: list[str] = Field(default_factory=list)
    error: str = ""


def connection_id(*values: object) -> str:
    return hashlib.sha256("|".join(map(str, values)).encode()).hexdigest()[:24]


def parse_conntrack(text: str, local: dict[str, str]) -> list[ConnectionRow]:
    result = []
    for line in text.splitlines()[:FLOW_LIMIT]:
        words = line.split()
        proto = next((word for word in words[:5] if word in PROTOCOLS), None)
        if not proto:
            continue
        fields: dict[str, list[str]] = {}
        for key, value in re.findall(
            r"(?:^|\s)(src|dst|sport|dport|packets|bytes|zone)=(\S+)", line
        ):
            fields.setdefault(key, []).append(value)
        try:
            sources, destinations = fields["src"], fields["dst"]
            if len(sources) != 2 or len(destinations) != 2:
                continue
            source = str(ipaddress.IPv4Address(sources[0]))
            destination = str(ipaddress.IPv4Address(destinations[0]))
            reply_source = str(ipaddress.IPv4Address(sources[1]))
            if ipaddress.IPv4Address(source).is_loopback:
                continue
            sport = int(fields["sport"][0]) if "sport" in fields else None
            dport = int(fields["dport"][0]) if "dport" in fields else None
            reply_port = int(fields["sport"][1]) if "sport" in fields else None
            dnat = destination != reply_source or (
                dport is not None and reply_port is not None and dport != reply_port
            )
            if destination not in local and not dnat:
                continue
            translated_port = reply_port if dnat else None
            if any(
                port is not None and not 0 <= port <= 65535 for port in (sport, dport, reply_port)
            ):
                continue
            counts = {}
            for key in ("packets", "bytes"):
                values = [int(value) for value in fields.get(key, [])]
                counts[key] = (
                    sum(values)
                    if len(values) == 2 and all(0 <= value < 2**64 for value in values)
                    else None
                )
            state = next(
                (word for word in words[:9] if word in STATES),
                "UNREPLIED"
                if "[UNREPLIED]" in words
                else "ASSURED"
                if "[ASSURED]" in words
                else "TRACKED",
            )
            index = words.index(proto)
            expires = int(words[index + 2])
            result.append(
                ConnectionRow(
                    id=connection_id(
                        proto, source, destination, sport, dport, fields.get("zone", ["0"])[0]
                    ),
                    protocol=proto,
                    source=source,
                    destination=destination,
                    source_port=sport,
                    destination_port=dport,
                    translated_destination=reply_source if dnat else "",
                    translated_port=translated_port,
                    state=state,
                    interface=local.get(destination, ""),
                    packets=counts["packets"],
                    bytes=counts["bytes"],
                    expires_in=expires if 0 <= expires <= 2**32 else None,
                )
            )
        except (KeyError, ValueError, IndexError):
            continue
    return result


def parse_packet(data: bytes, interface: str, now: float) -> ConnectionRow | None:
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    header = (data[0] & 15) * 4
    if header < 20 or header > 60 or len(data) < header + 8:
        return None
    total = int.from_bytes(data[2:4], "big")
    if total < header + 8 or int.from_bytes(data[6:8], "big") & 0x1FFF:
        return None
    proto = {6: "tcp", 17: "udp"}.get(data[9])
    if not proto:
        return None
    if proto == "tcp":
        if len(data) < header + 20 or total < header + 20:
            return None
        flags = data[header + 13]
        if not flags & 2 or flags & 16:
            return None
    source = socket.inet_ntoa(data[12:16])
    destination = socket.inet_ntoa(data[16:20])
    sport = int.from_bytes(data[header : header + 2], "big")
    dport = int.from_bytes(data[header + 2 : header + 4], "big")
    return ConnectionRow(
        id=connection_id(interface, proto, source, destination, sport, dport),
        protocol=proto,
        source=source,
        destination=destination,
        source_port=sport,
        destination_port=dport,
        state="SYN" if proto == "tcp" else "DATAGRAM",
        interface=interface,
        packets=1,
        bytes=total,
        first_seen=now,
        last_seen=now,
    )


def matches(row: ConnectionRow, query: ConnectionQuery) -> bool:
    if query.protocol and row.protocol != query.protocol:
        return False
    if query.state and row.state != query.state:
        return False
    if query.interface and row.interface != query.interface:
        return False
    for value, address in ((query.source, row.source), (query.destination, row.destination)):
        if value and ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(value):
            return False
    if query.port:
        ranges = [list(map(int, part.split("-"))) for part in query.port.split(",")]
        ports = [row.source_port, row.destination_port, row.translated_port]
        if not any(
            port is not None and bounds[0] <= port <= bounds[-1]
            for bounds in ranges
            for port in ports
        ):
            return False
    if query.search:
        text = " ".join(str(value or "") for value in row.model_dump().values()).lower()
        if query.search.lower() not in text:
            return False
    return True


class ConnectionMonitor:
    def __init__(
        self,
        demo: bool,
        *,
        enabled: bool = True,
        proc_root: Path = Path("/proc"),
        command: Callable[[list[str]], tuple[str | None, bool]] = command_output,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.demo, self.enabled, self.proc_root = demo, enabled, proc_root
        self.command, self.clock = command, clock
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.events: OrderedDict[str, ConnectionRow] = OrderedDict()
        self.wan: set[str] = set()
        self.local: dict[str, str] = {}
        self.network_at = 0.0
        self.cached_at = 0.0
        self.cached: list[ConnectionRow] = []
        self.available = False
        self.partial = False
        self.capture_available = demo
        self.capture_error = ""
        self.sampled = False

    def _network(self) -> None:
        if self.demo:
            self.local = {"203.0.113.10": "eth0"}
            self.wan = {"eth0"}
            return
        binary = shutil.which("ip")
        if not binary:
            return
        addresses, _ = self.command([binary, "-j", "-4", "address", "show"])
        routes, _ = self.command([binary, "-j", "-4", "route", "show", "default"])
        try:
            if addresses is not None:
                self.local = {
                    str(ipaddress.IPv4Address(item["local"])): str(row["ifname"])
                    for row in json.loads(addresses)[:128]
                    for item in row.get("addr_info", [])[:64]
                    if IFNAME.fullmatch(str(row["ifname"]))
                }
            if routes is not None:
                self.wan = {
                    str(row["dev"])
                    for row in json.loads(routes)[:32]
                    if IFNAME.fullmatch(str(row.get("dev", "")))
                }
        except (ValueError, TypeError, KeyError):
            self.capture_error = "Не удалось определить входящие интерфейсы."
        self.network_at = self.clock()

    def start(self) -> None:
        if self.demo or not self.enabled or not hasattr(socket, "AF_PACKET"):
            if not self.demo:
                self.capture_error = "Пассивный монитор входящих попыток выключен или недоступен."
            return
        self.thread = threading.Thread(target=self._capture, name="ingress-headers", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)

    def _capture(self) -> None:
        try:
            with socket.socket(
                socket.AddressFamily["AF_PACKET"], socket.SOCK_DGRAM, socket.htons(0x0800)
            ) as channel:
                channel.settimeout(0.5)
                channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                with self.lock:
                    self.capture_available = True
                tick, count = int(self.clock()), 0
                while not self.stop_event.is_set():
                    if self.clock() - self.network_at >= 10:
                        with self.lock:
                            self._network()
                    second = int(self.clock())
                    if second != tick:
                        tick, count = second, 0
                    if count >= CAPTURE_RATE:
                        self.sampled = True
                        self.stop_event.wait(0.05)
                        continue
                    try:
                        data, address = channel.recvfrom(96)
                    except TimeoutError:
                        continue
                    count += 1
                    interface = str(address[0])
                    if address[2] != 0 or interface not in self.wan:
                        continue
                    row = parse_packet(data, interface, self.clock())
                    if row:
                        self.observe(row)
        except OSError:
            with self.lock:
                self.capture_available = False
                self.capture_error = "Нет доступа к пассивному монитору входящих интерфейсов."

    def observe(self, row: ConnectionRow) -> None:
        with self.lock:
            self._expire()
            previous = self.events.pop(row.id, None)
            if previous:
                row.first_seen = previous.first_seen
                row.observations += previous.observations
                row.packets = (previous.packets or 0) + (row.packets or 0)
                row.bytes = (previous.bytes or 0) + (row.bytes or 0)
            self.events[row.id] = row
            while len(self.events) > EVENT_LIMIT:
                self.events.popitem(last=False)

    def _expire(self) -> None:
        expired = [
            key
            for key, row in self.events.items()
            if self.clock() - (row.last_seen or 0) > EVENT_TTL
        ]
        for key in expired:
            del self.events[key]

    def _active(self) -> None:
        if self.clock() - self.cached_at < 2 and self.cached_at:
            return
        self._network()
        text, partial = read_bounded(self.proc_root / "net/nf_conntrack")
        if text is None:
            text, partial = read_bounded(self.proc_root / "net/ip_conntrack")
        binary = shutil.which("conntrack")
        if text is None and binary:
            text, partial = self.command([binary, "-L", "-f", "ipv4", "-o", "extended"])
        self.available = text is not None
        self.cached = parse_conntrack(text, self.local) if text is not None else []
        self.partial = partial or bool(text and len(text.splitlines()) > FLOW_LIMIT)
        self.cached_at = self.clock()

    def snapshot(self, query: ConnectionQuery) -> ConnectionSnapshot:
        with self.lock:
            now = self.clock()
            if self.demo:
                self._network()
                rows = [
                    ConnectionRow(
                        id="demo-rdp",
                        protocol="tcp",
                        source="198.51.100.24",
                        destination="203.0.113.10",
                        source_port=51234,
                        destination_port=3389,
                        translated_destination="192.168.10.10",
                        translated_port=3389,
                        state="ESTABLISHED" if query.kind == "active" else "SYN",
                        interface="eth0",
                        packets=14,
                        bytes=24576,
                        first_seen=now - 30,
                        last_seen=now,
                        observations=2,
                    )
                ]
                available, partial, error = True, False, ""
            elif query.kind == "active":
                self._active()
                rows, available, partial = self.cached, self.available, self.partial
                error = "" if available else "Таблица активных соединений conntrack недоступна."
            else:
                self._expire()
                rows = list(reversed(self.events.values()))
                available, partial, error = self.capture_available, self.sampled, self.capture_error
            filtered = [row for row in rows if matches(row, query)]
            return ConnectionSnapshot(
                kind=query.kind,
                available=available,
                demo=self.demo,
                timestamp=now,
                total=len(rows),
                matched=len(filtered),
                items=[
                    row.model_copy(deep=True)
                    for row in filtered[query.offset : query.offset + query.limit]
                ],
                partial=partial,
                interfaces=sorted(self.wan),
                error=error,
            )
