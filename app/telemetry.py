"""Bounded, read-only host telemetry; no probes, packet capture or network changes."""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import re
import selectors
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)
READ_LIMIT = 2_097_152
INTERFACE_LIMIT = 128
DEVICE_LIMIT = 512
FLOW_LIMIT = 20_000
# Coalesce simultaneous tabs without hiding the next 200 ms browser sample.
CACHE_SECONDS = 0.1
DETAILS_CACHE_SECONDS = 5.0
COUNTERS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
IFNAME = re.compile(r"[A-Za-z0-9_.:@-]{1,15}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")


class InterfaceTelemetry(BaseModel):
    name: str
    state: str
    physical: bool
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_bps: float | None = None
    tx_bps: float | None = None
    rx_pps: float | None = None
    tx_pps: float | None = None


class TrafficTelemetry(BaseModel):
    available: bool = False
    scope: str = "unavailable"
    interfaces: list[str] = Field(default_factory=list)
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    rx_bps: float | None = None
    tx_bps: float | None = None
    rx_pps: float | None = None
    tx_pps: float | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    rx_dropped: int | None = None
    tx_dropped: int | None = None
    partial: bool = False


class ConnectionTelemetry(BaseModel):
    available: bool = False
    active: int | None = None
    limit: int | None = None


class ObservedDevice(BaseModel):
    address: str
    mac: str
    hostname: str = ""
    interface: str = ""
    source: str


class DeviceTelemetry(BaseModel):
    available: bool = False
    count: int | None = None
    dhcp_leases: int | None = None
    neighbors: int | None = None
    items: list[ObservedDevice] = Field(default_factory=list)
    partial: bool = False


class SystemTelemetry(BaseModel):
    uptime_seconds: float | None = None
    cpu_percent: float | None = None
    memory_used_bytes: int | None = None
    memory_total_bytes: int | None = None


class DestinationTelemetry(BaseModel):
    address: str
    port: int | None = None
    protocol: str
    connections: int
    packets: int | None = None
    bytes: int | None = None


class TopDestinations(BaseModel):
    available: bool = False
    basis: Literal["bytes", "connections"] = "connections"
    items: list[DestinationTelemetry] = Field(default_factory=list)
    partial: bool = False


class TelemetrySnapshot(BaseModel):
    demo: bool
    timestamp: float
    details_included: bool = True
    sample_seconds: float | None = None
    traffic: TrafficTelemetry = Field(default_factory=TrafficTelemetry)
    interfaces: list[InterfaceTelemetry] = Field(default_factory=list)
    connections: ConnectionTelemetry = Field(default_factory=ConnectionTelemetry)
    devices: DeviceTelemetry = Field(default_factory=DeviceTelemetry)
    system: SystemTelemetry = Field(default_factory=SystemTelemetry)
    top_destinations: TopDestinations = Field(default_factory=TopDestinations)


@dataclass(frozen=True)
class RawInterface:
    name: str
    index: int | None
    state: str
    physical: bool
    counters: tuple[int, ...]


def read_bounded(path: Path, limit: int = READ_LIMIT) -> tuple[str | None, bool]:
    try:
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
    except OSError:
        return None, False
    truncated = len(content) > limit
    return content[:limit].decode("utf-8", errors="replace"), truncated


def read_number(path: Path) -> int | None:
    text, _ = read_bounded(path, 128)
    try:
        number = int(text.strip()) if text is not None else -1
        return number if 0 <= number <= 2**64 - 1 else None
    except ValueError:
        return None


def command_output(args: list[str]) -> tuple[str | None, bool]:
    """Fixed-argument read commands, bounded in elapsed time and captured output."""
    try:
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            assert process.stdout is not None
            output = bytearray()
            deadline = time.monotonic() + 2
            truncated = False
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        process.kill()
                        process.wait()
                        return None, True
                    if not selector.select(remaining):
                        continue
                    chunk = os.read(
                        process.stdout.fileno(), min(65536, READ_LIMIT + 1 - len(output))
                    )
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > READ_LIMIT:
                        truncated = True
                        process.kill()
                        break
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return None, True
            if process.returncode and not truncated:
                return None, False
            return output[:READ_LIMIT].decode("utf-8", errors="replace"), truncated
    except OSError:
        log.debug("Optional telemetry command unavailable: %s", args[0])
        return None, False


def parse_interfaces(text: str, sys_root: Path) -> list[RawInterface]:
    result = []
    for line in text.splitlines()[2 : INTERFACE_LIMIT + 2]:
        name, separator, content = line.rpartition(":")
        name = name.strip()
        if not separator or not IFNAME.fullmatch(name) or name in ("lo", ".", ".."):
            continue
        try:
            values = tuple(int(value) for value in content.split())
        except ValueError:
            continue
        if len(values) != 16 or any(value < 0 or value > 2**64 - 1 for value in values):
            continue
        path = sys_root / name
        state, _ = read_bounded(path / "operstate", 32)
        result.append(
            RawInterface(
                name=name,
                index=read_number(path / "ifindex"),
                state=(state or "unknown").strip().upper(),
                physical=(path / "device").exists(),
                # First four are used for rate calculations, then errors/drops.
                counters=(
                    values[0],
                    values[8],
                    values[1],
                    values[9],
                    values[2],
                    values[10],
                    values[3],
                    values[11],
                ),
            )
        )
    return result


def valid_mac(value: str) -> str | None:
    value = value.lower()
    if not MAC.fullmatch(value) or value == "00:00:00:00:00:00":
        return None
    return None if int(value[:2], 16) & 1 else value


def valid_address(value: str) -> str | None:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    return (
        None
        if address.is_unspecified or address.is_loopback or address.is_multicast
        else str(address)
    )


def observed_devices(
    neighbor_text: str | None,
    lease_text: str | None,
    now: float,
    own_macs: set[str],
    partial: bool = False,
) -> DeviceTelemetry:
    """Observed identities only; this does not discover every device on a network."""
    identities: dict[str, ObservedDevice] = {}
    neighbor_macs: set[str] = set()
    lease_macs: set[str] = set()
    neighbors_available = False
    if neighbor_text is not None:
        try:
            rows = json.loads(neighbor_text)
        except (ValueError, TypeError):
            rows = None
        if isinstance(rows, list):
            neighbors_available = True
            partial = partial or len(rows) > 16_384
            for row in rows[:16_384]:
                if not isinstance(row, dict):
                    continue
                states = row.get("state", [])
                if isinstance(states, str):
                    states = states.split(",")
                if not isinstance(states, list) or any(
                    state in ("FAILED", "INCOMPLETE", "NONE") for state in states
                ):
                    continue
                mac = valid_mac(str(row.get("lladdr", "")))
                address = valid_address(str(row.get("dst", "")))
                if not mac or not address or mac in own_macs:
                    continue
                neighbor_macs.add(mac)
                identities[mac] = ObservedDevice(
                    address=address,
                    mac=mac,
                    interface=str(row.get("dev", ""))[:15],
                    source="neighbor",
                )
    if lease_text is not None:
        lines = lease_text.splitlines()
        partial = partial or len(lines) > 16_384
        for line in lines[:16_384]:
            parts = line.split()
            if len(parts) != 5:
                continue
            try:
                expires = int(parts[0])
            except ValueError:
                continue
            if expires < 0 or (expires and expires <= now):
                continue
            mac, address = valid_mac(parts[1]), valid_address(parts[2])
            if not mac or not address or mac in own_macs:
                continue
            lease_macs.add(mac)
            previous = identities.get(mac)
            identities[mac] = ObservedDevice(
                address=previous.address if previous else address,
                mac=mac,
                hostname="" if parts[3] == "*" else parts[3][:253],
                interface=previous.interface if previous else "",
                source="neighbor+dhcp" if previous else "dhcp",
            )
    available = neighbors_available or lease_text is not None
    return DeviceTelemetry(
        available=available,
        count=len(identities) if available else None,
        dhcp_leases=len(lease_macs) if lease_text is not None else None,
        neighbors=len(neighbor_macs) if neighbors_available else None,
        items=sorted(identities.values(), key=lambda item: item.address)[:DEVICE_LIMIT],
        partial=partial or len(identities) > DEVICE_LIMIT,
    )


def parse_destinations(text: str | None, truncated: bool = False) -> TopDestinations:
    if text is None:
        return TopDestinations()
    groups: dict[tuple[str, int | None, str], DestinationTelemetry] = {}
    count = 0
    partial = truncated
    accounting = True
    for line in text.splitlines():
        if count >= FLOW_LIMIT:
            partial = True
            break
        count += 1
        # Original tuple starts at the first src=. Never use reply src/dst or accounting.
        before, separator, tuples = line.partition("src=")
        if not separator or before.split()[:1] == ["ipv6"]:
            continue
        tokens = before.split()
        protocol = next(
            (item for item in tokens if item in ("tcp", "udp", "icmp", "gre", "sctp")), "other"
        )
        original = ("src=" + tuples).split(" src=", 1)[0]
        values = dict(token.split("=", 1) for token in original.split() if "=" in token)
        address = valid_address(values.get("dst", ""))
        if not address:
            continue
        port: int | None = None
        try:
            candidate = int(values["dport"])
            port = candidate if 0 <= candidate <= 65535 else None
        except (KeyError, ValueError):
            pass
        counts: dict[str, int | None] = {}
        for key in ("packets", "bytes"):
            try:
                value = int(values[key])
                counts[key] = value if 0 <= value <= 2**64 - 1 else None
            except (KeyError, ValueError):
                counts[key] = None
        accounting = accounting and counts["bytes"] is not None
        group_key = (address, port, protocol)
        group = groups.setdefault(
            group_key,
            DestinationTelemetry(
                address=address, port=port, protocol=protocol, connections=0, packets=0, bytes=0
            ),
        )
        group.connections += 1
        for field in ("packets", "bytes"):
            previous, amount = getattr(group, field), counts[field]
            setattr(
                group,
                field,
                previous + amount if previous is not None and amount is not None else None,
            )
    basis: Literal["bytes", "connections"] = "bytes" if groups and accounting else "connections"
    items = sorted(
        groups.values(),
        key=lambda item: (
            -(item.bytes or 0) if basis == "bytes" else -item.connections,
            item.address,
            item.port or 0,
            item.protocol,
        ),
    )[:10]
    return TopDestinations(available=True, basis=basis, items=items, partial=partial)


class TelemetryCollector:
    def __init__(
        self,
        mode: str,
        data_dir: Path,
        *,
        proc_root: Path = Path("/proc"),
        sys_root: Path = Path("/sys/class/net"),
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], float] = time.time,
        command: Callable[[list[str]], tuple[str | None, bool]] = command_output,
    ) -> None:
        self.demo = mode == "demo"
        self.proc_root, self.sys_root = proc_root, sys_root
        self.lease_path = data_dir / "network" / "dhcp.leases"
        self.monotonic, self.clock, self.command = monotonic, clock, command
        self.lock = threading.Lock()
        self.details_lock = threading.Lock()
        self.details_at: float | None = None
        self.devices = DeviceTelemetry()
        self.top_destinations = TopDestinations()
        self.started = monotonic()
        self.previous_at: float | None = None
        self.previous: dict[str, RawInterface] = {}
        self.previous_cpu: tuple[int, int] | None = None
        self.cached: TelemetrySnapshot | None = None
        self.cached_at: float | None = None

    def snapshot(self, *, fast: bool = False) -> TelemetrySnapshot:
        # Slow inventory commands never hold the counter lock. A full request may
        # take seconds, while concurrent fast requests keep reading /proc counters.
        if not self.demo and not fast:
            self._refresh_details()
        with self.lock:
            now = self.monotonic()
            if not (
                self.cached and self.cached_at is not None and now - self.cached_at < CACHE_SECONDS
            ):
                self.cached = self._demo(now) if self.demo else self._linux(now)
                self.previous_at = now
                self.cached_at = now
            assert self.cached is not None
            result = self.cached.model_copy(deep=True)
            if fast:
                # Do not resend up to 512 unchanged device records at 5 Hz.
                result.details_included = False
                result.devices = DeviceTelemetry()
                result.top_destinations = TopDestinations()
            return result

    def _refresh_details(self) -> None:
        if not self.details_lock.acquire(blocking=False):
            return
        try:
            now = self.monotonic()
            if self.details_at is not None and now - self.details_at < DETAILS_CACHE_SECONDS:
                return
            devices, destinations = self._details()
            with self.lock:
                self.devices, self.top_destinations = devices, destinations
                self.details_at = self.monotonic()
                if self.cached is not None:
                    self.cached.devices = devices
                    self.cached.top_destinations = destinations
        finally:
            self.details_lock.release()

    def _linux(self, now: float) -> TelemetrySnapshot:
        elapsed = now - self.previous_at if self.previous_at is not None else None
        elapsed = elapsed if elapsed and elapsed > 0 else None
        result = TelemetrySnapshot(demo=False, timestamp=self.clock(), sample_seconds=elapsed)
        content, interfaces_partial = read_bounded(self.proc_root / "net" / "dev")
        raw = parse_interfaces(content, self.sys_root) if content is not None else []
        for item in raw:
            rates: list[float | None] = [None] * 4
            previous = self.previous.get(item.name)
            if elapsed and previous and previous.index is not None and previous.index == item.index:
                for index in range(4):
                    difference = item.counters[index] - previous.counters[index]
                    if difference >= 0:
                        rates[index] = difference / elapsed * (8 if index < 2 else 1)
            result.interfaces.append(
                InterfaceTelemetry(
                    name=item.name,
                    state=item.state,
                    physical=item.physical,
                    rx_bytes=item.counters[0],
                    tx_bytes=item.counters[1],
                    rx_packets=item.counters[2],
                    tx_packets=item.counters[3],
                    rx_bps=rates[0],
                    tx_bps=rates[1],
                    rx_pps=rates[2],
                    tx_pps=rates[3],
                )
            )
        self.previous = {item.name: item for item in raw}
        selected = [item for item in raw if item.physical]
        scope = "physical_interfaces"
        if not selected and raw:
            # VMs/containers may not expose a device symlink. A single fallback cannot
            # double-count a packet through stacked bridge/VLAN/tunnel interfaces.
            selected = [max(raw, key=lambda item: sum(item.counters[:2]))]
            scope = "primary_interface_fallback"
        if selected:
            names = {item.name for item in selected}
            rates_rows = [item for item in result.interfaces if item.name in names]
            totals: dict[str, int | float | None] = {
                key: sum(item.counters[index] for item in selected)
                for index, key in enumerate(
                    (*COUNTERS, "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
                )
            }
            for key in ("rx_bps", "tx_bps", "rx_pps", "tx_pps"):
                values = [getattr(item, key) for item in rates_rows]
                totals[key] = sum(values) if all(value is not None for value in values) else None
            result.traffic = TrafficTelemetry.model_validate(
                {
                    "available": True,
                    "scope": scope,
                    "interfaces": sorted(names),
                    "partial": interfaces_partial
                    or bool(content and len(content.splitlines()) > INTERFACE_LIMIT + 2),
                    **totals,
                }
            )
        active = read_number(self.proc_root / "sys/net/netfilter/nf_conntrack_count")
        limit = read_number(self.proc_root / "sys/net/netfilter/nf_conntrack_max")
        result.connections = ConnectionTelemetry(
            available=active is not None, active=active, limit=limit
        )
        result.system = self._system()
        result.devices = self.devices
        result.top_destinations = self.top_destinations
        return result

    def _details(self) -> tuple[DeviceTelemetry, TopDestinations]:
        content, _ = read_bounded(self.proc_root / "net" / "dev")
        raw = parse_interfaces(content, self.sys_root) if content is not None else []
        own_macs = set()
        for item in raw:
            own, _ = read_bounded(self.sys_root / item.name / "address", 64)
            if own and (mac := valid_mac(own.strip())):
                own_macs.add(mac)
        neighbor_text, neighbor_partial = (None, False)
        if ip := shutil.which("ip"):
            neighbor_text, neighbor_partial = self.command([ip, "-j", "-4", "neigh", "show"])
        lease_text, lease_partial = read_bounded(self.lease_path)
        devices = observed_devices(
            neighbor_text, lease_text, self.clock(), own_macs, neighbor_partial or lease_partial
        )
        flows, partial = read_bounded(self.proc_root / "net/nf_conntrack")
        if flows is None:
            flows, partial = read_bounded(self.proc_root / "net/ip_conntrack")
        if flows is None and (binary := shutil.which("conntrack")):
            flows, partial = self.command([binary, "-L", "-f", "ipv4", "-o", "extended"])
        return devices, parse_destinations(flows, partial)

    def _system(self) -> SystemTelemetry:
        result = SystemTelemetry()
        uptime, _ = read_bounded(self.proc_root / "uptime", 128)
        try:
            value = float((uptime or "").split()[0])
            if math.isfinite(value) and value >= 0:
                result.uptime_seconds = value
        except (ValueError, IndexError):
            pass
        memory, _ = read_bounded(self.proc_root / "meminfo", 16384)
        if memory is not None:
            values = {}
            for line in memory.splitlines():
                parts = line.split()
                if (
                    len(parts) == 3
                    and parts[0] in ("MemTotal:", "MemAvailable:")
                    and parts[2] == "kB"
                ):
                    try:
                        values[parts[0]] = max(0, int(parts[1])) * 1024
                    except ValueError:
                        continue
            total, available = values.get("MemTotal:"), values.get("MemAvailable:")
            if total is not None:
                result.memory_total_bytes = total
                if available is not None and available <= total:
                    result.memory_used_bytes = total - available
        cpu, _ = read_bounded(self.proc_root / "stat", 4096)
        try:
            fields = (cpu or "").splitlines()[0].split()
            values_cpu = [int(value) for value in fields[1:9]]
            if fields[0] == "cpu" and len(values_cpu) >= 4 and min(values_cpu) >= 0:
                # Guest values are already included in user/nice; do not add them again.
                total_cpu = sum(values_cpu)
                idle = values_cpu[3] + (values_cpu[4] if len(values_cpu) > 4 else 0)
                previous = self.previous_cpu
                if previous and total_cpu > previous[0] and idle >= previous[1]:
                    result.cpu_percent = round(
                        max(
                            0,
                            min(100, (1 - (idle - previous[1]) / (total_cpu - previous[0])) * 100),
                        ),
                        1,
                    )
                self.previous_cpu = (total_cpu, idle)
        except (ValueError, IndexError):
            self.previous_cpu = None
        return result

    def _demo(self, now: float) -> TelemetrySnapshot:
        elapsed = max(0, now - self.started)
        rates = [
            (
                "eth0",
                27_000_000 + 9_000_000 * math.sin(elapsed / 13),
                6_000_000 + 2_000_000 * math.cos(elapsed / 17),
            ),
            (
                "eth1",
                3_400_000 + 700_000 * math.sin(elapsed / 11),
                19_000_000 + 5_000_000 * math.cos(elapsed / 14),
            ),
            (
                "eth2",
                1_200_000 + 400_000 * math.cos(elapsed / 19),
                4_500_000 + 1_000_000 * math.sin(elapsed / 12),
            ),
        ]
        interfaces = []
        previous = {item.name: item for item in self.cached.interfaces} if self.cached else {}
        step = max(0, now - self.previous_at) if self.previous_at is not None else 0
        for name, rx, tx in rates:
            baseline = previous.get(name)
            interfaces.append(
                InterfaceTelemetry(
                    name=name,
                    state="UP",
                    physical=True,
                    rx_bytes=(baseline.rx_bytes if baseline else 4_000_000_000)
                    + int(step * rx / 8),
                    tx_bytes=(baseline.tx_bytes if baseline else 1_800_000_000)
                    + int(step * tx / 8),
                    rx_packets=(baseline.rx_packets if baseline else 5_000_000)
                    + int(step * rx / 6400),
                    tx_packets=(baseline.tx_packets if baseline else 2_400_000)
                    + int(step * tx / 6400),
                    rx_bps=round(rx),
                    tx_bps=round(tx),
                    rx_pps=round(rx / 6400),
                    tx_pps=round(tx / 6400),
                )
            )
        total_fields = (*COUNTERS, "rx_bps", "tx_bps", "rx_pps", "tx_pps")
        totals = {key: sum(getattr(item, key) for item in interfaces) for key in total_fields}
        devices = [
            ObservedDevice(
                address=f"192.168.10.{100 + index}",
                mac=f"02:00:00:00:00:{index + 1:02x}",
                hostname=name,
                interface="br-lan",
                source="neighbor+dhcp",
            )
            for index, name in enumerate(
                (
                    "workstation",
                    "notebook",
                    "phone",
                    "tablet",
                    "printer",
                    "camera",
                    "access-point",
                    "media-player",
                )
            )
        ]
        return TelemetrySnapshot(
            demo=True,
            timestamp=self.clock(),
            sample_seconds=now - self.previous_at if self.previous_at is not None else None,
            traffic=TrafficTelemetry(
                available=True,
                scope="physical_interfaces",
                interfaces=[item.name for item in interfaces],
                rx_errors=0,
                tx_errors=0,
                rx_dropped=3,
                tx_dropped=0,
                **totals,
            ),
            interfaces=interfaces,
            connections=ConnectionTelemetry(
                available=True, active=312 + int(35 * math.sin(elapsed / 23)), limit=65536
            ),
            devices=DeviceTelemetry(
                available=True,
                count=len(devices),
                dhcp_leases=len(devices),
                neighbors=len(devices),
                items=devices,
            ),
            system=SystemTelemetry(
                uptime_seconds=86400 + elapsed,
                cpu_percent=round(14 + 5 * math.sin(elapsed / 16), 1),
                memory_used_bytes=246_415_360,
                memory_total_bytes=1_073_741_824,
            ),
            top_destinations=TopDestinations(
                available=True,
                basis="bytes",
                items=[
                    DestinationTelemetry(
                        address="203.0.113.80",
                        port=443,
                        protocol="tcp",
                        connections=42,
                        packets=124000,
                        bytes=86_000_000,
                    ),
                    DestinationTelemetry(
                        address="203.0.113.25",
                        port=443,
                        protocol="tcp",
                        connections=11,
                        packets=5900,
                        bytes=4_300_000,
                    ),
                    DestinationTelemetry(
                        address="198.51.100.53",
                        port=53,
                        protocol="udp",
                        connections=18,
                        packets=28000,
                        bytes=2_400_000,
                    ),
                ],
            ),
        )
