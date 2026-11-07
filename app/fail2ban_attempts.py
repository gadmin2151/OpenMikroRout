"""Private, metadata-only NFLOG collector for distinct IPv4 TCP connection attempts.

The ABI is Linux's nfnetlink_log.h / nfnetlink_conntrack.h. No protocol-family
logger is bound or unbound: this process exclusively owns its one NFLOG group.
Conntrack IDs and original tuples identify connections. Unconfirmed entries may
be destroyed by a later DROP, so their tuples are conservatively deduplicated
for the entire observation window (exact tuple reuse can undercount attempts).
Missing conntrack metadata never falls back to counting packets. This does not
detect authentication failures.
"""

import errno
import ipaddress
import os
import re
import socket
import struct
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.compiler import FirewallError
from app.fail2ban_models import F2BConfiguration

NFLOG_GROUP = 5088
NETLINK_NETFILTER = 12
LOG_PACKET = 4 << 8
LOG_CONFIG = LOG_PACKET | 1
MAX_DATAGRAM = 131072
MAX_TRACKED_CONNECTIONS = 65536
MAX_EVENTS_PER_SECOND = 2000
LOG_MAX_BYTES = 2 * 1024 * 1024
LOG_BACKUPS = 3
_NL_HEADER = struct.Struct("=IHHII")
_ATTR_HEADER = struct.Struct("=HH")
_PROFILE = re.compile(r"r_[0-9a-f]{18}\Z")


def _align(length: int) -> int:
    return (length + 3) & ~3


def _attribute(kind: int, payload: bytes) -> bytes:
    length = len(payload) + 4
    return _ATTR_HEADER.pack(length, kind) + payload + bytes(_align(length) - length)


def _attributes(payload: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 4:
            raise ValueError("Truncated netlink attribute")
        length, kind = _ATTR_HEADER.unpack_from(payload, offset)
        kind &= 0x3FFF  # NLA_F_NESTED and NLA_F_NET_BYTEORDER are flags.
        if length < 4 or offset + length > len(payload) or kind in result:
            raise ValueError("Invalid or duplicate netlink attribute")
        if len(result) >= 64:
            raise ValueError("Too many netlink attributes")
        result[kind] = payload[offset + 4 : offset + length]
        offset += _align(length)
    return result


def _messages(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    offset = 0
    while offset < len(data):
        if len(data) - offset < _NL_HEADER.size:
            raise ValueError("Truncated netlink message")
        length, kind, _flags, sequence, _pid = _NL_HEADER.unpack_from(data, offset)
        if length < _NL_HEADER.size or offset + length > len(data):
            raise ValueError("Invalid netlink message length")
        yield kind, sequence, data[offset + _NL_HEADER.size : offset + length]
        offset += _align(length)


class MissingConntrack(ValueError):
    """The kernel supplied a packet without a reliable connection identity."""


@dataclass(frozen=True)
class ConnectionAttempt:
    profile: str
    source: str
    destination: str
    source_port: int
    destination_port: int
    connection_id: int
    confirmed: bool
    zone: int
    sequence: int


@dataclass(frozen=True)
class _SeenConnection:
    at: float
    connection_id: int
    confirmed: bool


def parse_attempt(payload: bytes) -> ConnectionAttempt:
    if len(payload) < 4:
        raise ValueError("Missing NFLOG header")
    family, version, group = struct.unpack_from("!BBH", payload)
    if family != socket.AF_INET or version != 0 or group != NFLOG_GROUP:
        raise ValueError("Unexpected NFLOG family or group")
    attributes = _attributes(payload[4:])
    prefix = attributes.get(10, b"")
    if not prefix.endswith(b"\0"):
        raise ValueError("Missing NFLOG prefix")
    profile = prefix[:-1].decode("ascii")
    if not _PROFILE.fullmatch(profile):
        raise ValueError("Unexpected profile identifier")
    if 18 not in attributes or attributes.get(19) != struct.pack("!I", 2):
        raise MissingConntrack("A new original-direction conntrack entry is required")
    ct = _attributes(attributes[18])
    original = _attributes(ct.get(1, b""))
    addresses = _attributes(original.get(1, b""))
    protocol = _attributes(original.get(2, b""))
    if (
        len(ct.get(12, b"")) != 4
        or len(ct.get(3, b"")) != 4
        or len(addresses.get(1, b"")) != 4
        or len(addresses.get(2, b"")) != 4
        or protocol.get(1) != b"\x06"
        or len(protocol.get(2, b"")) != 2
        or len(protocol.get(3, b"")) != 2
        or len(attributes.get(12, b"")) != 4
    ):
        raise MissingConntrack("Incomplete IPv4 TCP conntrack identity")
    source = ipaddress.IPv4Address(addresses[1])
    if source.is_loopback or source.is_unspecified or source.is_multicast:
        raise ValueError("Non-client source address")
    zone = ct.get(18, original.get(3, b"\0\0"))
    if len(zone) != 2:
        raise ValueError("Invalid conntrack zone")
    return ConnectionAttempt(
        profile=profile,
        source=str(source),
        destination=str(ipaddress.IPv4Address(addresses[2])),
        source_port=struct.unpack("!H", protocol[2])[0],
        destination_port=struct.unpack("!H", protocol[3])[0],
        connection_id=struct.unpack("!I", ct[12])[0],
        confirmed=bool(struct.unpack("!I", ct[3])[0] & 8),  # IPS_CONFIRMED
        zone=struct.unpack("!H", zone)[0],
        sequence=struct.unpack("!I", attributes[12])[0],
    )


class _PrivateJournal:
    def __init__(self, data_dir: Path) -> None:
        directory = data_dir / "fail2ban"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / "attempts.log"
        self.fd = -1
        self._open()

    def _open(self) -> None:
        self.fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.fchmod(self.fd, 0o600)
        self.size = os.fstat(self.fd).st_size

    def append(self, attempt: ConnectionAttempt) -> None:
        if self.fd < 0:
            raise OSError("Connection journal is closed")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (
            f"{timestamp} openmikrorout connection_attempt "
            f"profile={attempt.profile} src={attempt.source}\n"
        ).encode("ascii")
        if self.size + len(line) > LOG_MAX_BYTES:
            os.close(self.fd)
            self.fd = -1
            for index in range(LOG_BACKUPS - 1, 0, -1):
                old = self.path.with_suffix(f".log.{index}")
                if old.exists():
                    os.replace(old, self.path.with_suffix(f".log.{index + 1}"))
            os.replace(self.path, self.path.with_suffix(".log.1"))
            self._open()
        written = os.write(self.fd, line)
        if written != len(line):
            raise OSError("Incomplete connection journal write")
        self.size += written

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def _command(sock: socket.socket, sequence: int, attributes: bytes) -> None:
    payload = struct.pack("!BBH", socket.AF_INET, 0, NFLOG_GROUP) + attributes
    message = _NL_HEADER.pack(len(payload) + 16, LOG_CONFIG, 1 | 4, sequence, 0) + payload
    sock.sendto(message, (0, 0))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            data, _ancillary, flags, address = sock.recvmsg(MAX_DATAGRAM)
        except TimeoutError:
            continue
        if address[0] != 0 or flags & socket.MSG_TRUNC:
            raise OSError("Invalid NFLOG acknowledgement")
        for kind, reply_sequence, body in _messages(data):
            if kind != 2 or reply_sequence != sequence:
                continue
            if len(body) < 4:
                raise OSError("Incomplete NFLOG acknowledgement")
            error = struct.unpack_from("=i", body)[0]
            if error:
                raise OSError(-error, os.strerror(-error))
            return
    raise TimeoutError("NFLOG configuration acknowledgement timed out")


def _open_socket() -> socket.socket:
    if not hasattr(socket, "AF_NETLINK"):
        raise FirewallError("Connection protection requires Linux NFLOG and conntrack")
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        sock.settimeout(0.25)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * MAX_DATAGRAM)
        sock.bind((0, 0))
        # Group BIND only. PF_BIND/PF_UNBIND would interfere with other firewalls.
        _command(sock, 1, _attribute(1, b"\x01"))
        configuration = (
            _attribute(2, struct.pack("!IBB", 0, 1, 0))  # COPY_META: no packet payload
            + _attribute(5, struct.pack("!I", 1))
            + _attribute(6, struct.pack("!H", 1 | 4))  # SEQ + CONNTRACK
        )
        # First use can load nf_conntrack_netlink and return EAGAIN once.
        for sequence in (2, 3):
            try:
                _command(sock, sequence, configuration)
                break
            except OSError as exc:
                if exc.errno != errno.EAGAIN or sequence == 3:
                    raise
        return sock
    except (OSError, ValueError) as exc:
        if sock is not None:
            sock.close()  # Closing automatically releases only this socket's group.
        raise FirewallError(
            f"Cannot exclusively open private NFLOG group {NFLOG_GROUP}: {exc}. "
            "Check NET_ADMIN permission, group ownership and conntrack support"
        ) from exc


class ConnectionAttemptCollector:
    """A bounded, opt-in producer of trusted events for the private Fail2ban daemon."""

    def __init__(self, data_dir: Path, demo: bool = False) -> None:
        self.demo = demo
        self.journal = _PrivateJournal(data_dir)
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._closed = False
        self._profiles: dict[str, int] = {}
        self._seen: OrderedDict[tuple[object, ...], _SeenConnection] = OrderedDict()
        self._last_sequence: int | None = None
        self._rate_second = 0
        self._rate_count = 0
        self._counters = dict(
            events=0,
            duplicates=0,
            malformed=0,
            missing_conntrack=0,
            dropped=0,
            overflows=0,
            rate_limited=0,
            ignored=0,
        )
        self._last_error = ""

    @staticmethod
    def _selected(settings: F2BConfiguration) -> dict[str, int]:
        return {
            profile.id: max(600, profile.find_time)
            for profile in settings.profiles
            if settings.enabled and profile.enabled and profile.service == "connections"
        }

    def start(self) -> None:
        """Lifecycle compatibility: configure() starts capture only when opted in."""

    def check(self, settings: F2BConfiguration) -> None:
        if self.demo or not self._selected(settings):
            return
        with self._lifecycle:
            if self._closed:
                raise FirewallError("Connection attempt collector is closed")
            if self._socket is not None and self._thread is not None and self._thread.is_alive():
                return
            probe = _open_socket()
            probe.close()

    def configure(self, settings: F2BConfiguration) -> None:
        selected = self._selected(settings)
        with self._lifecycle:
            if self._closed:
                raise FirewallError("Connection attempt collector is closed")
            if not selected:
                self._halt()
            elif not self.demo and (self._thread is None or not self._thread.is_alive()):
                self._halt()
                self._socket = _open_socket()
                self._stop.clear()
                self._last_sequence = None
                with self._lock:
                    self._profiles = selected
                    self._last_error = ""
                self._thread = threading.Thread(
                    target=self._receive, name="omr-connection-attempts", daemon=True
                )
                self._thread.start()
            with self._lock:
                self._profiles = selected

    def _halt(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                raise FirewallError("Connection collector did not stop within its deadline")
        if self._socket is not None:
            self._socket.close()
        self._thread = None
        self._socket = None

    def close(self) -> None:
        with self._lifecycle:
            if self._closed:
                return
            self._halt()
            with self._lock:
                self._profiles = {}
                self._closed = True
                self.journal.close()

    def status(self) -> dict[str, Any]:
        with self._lock:
            active = bool(self._profiles)
            running = self._thread is not None and self._thread.is_alive()
            return {
                "enabled": active,
                "running": running,
                "demo": self.demo,
                "group": NFLOG_GROUP,
                "profiles": sorted(self._profiles),
                "tracked_connections": len(self._seen),
                **self._counters,
                "last_error": self._last_error,
                "healthy": not active or self.demo or (running and not self._last_error),
            }

    def _record(self, attempt: ConnectionAttempt, now: float) -> None:
        with self._lock:
            if self._closed or attempt.profile not in self._profiles:
                self._counters["ignored"] += 1
                return
            identity = (
                attempt.profile,
                attempt.zone,
                attempt.source,
                attempt.destination,
                attempt.source_port,
                attempt.destination_port,
            )
            previous = self._seen.get(identity)
            if (
                previous is not None
                and now - previous.at < self._profiles[attempt.profile]
                and (previous.connection_id == attempt.connection_id or not previous.confirmed)
            ):
                self._seen[identity] = _SeenConnection(
                    now, attempt.connection_id, attempt.confirmed
                )
                self._seen.move_to_end(identity)
                self._counters["duplicates"] += 1
                return
            # Expire only entries outside their own complete observation window.
            while self._seen:
                key, seen_at = next(iter(self._seen.items()))
                if now - seen_at.at < max(self._profiles.values(), default=600):
                    break
                self._seen.pop(key)
            if int(now) != self._rate_second:
                self._rate_second, self._rate_count = int(now), 0
            if self._rate_count >= MAX_EVENTS_PER_SECOND:
                self._counters["rate_limited"] += 1
                self._last_error = "Connection event rate limit reached; protection is degraded"
                return
            if len(self._seen) >= MAX_TRACKED_CONNECTIONS and identity not in self._seen:
                self._counters["overflows"] += 1
                self._last_error = "Connection identity cache is full; protection is degraded"
                return
            self.journal.append(attempt)
            self._seen[identity] = _SeenConnection(now, attempt.connection_id, attempt.confirmed)
            self._seen.move_to_end(identity)
            self._rate_count += 1
            self._counters["events"] += 1

    def _consume(self, data: bytes) -> None:
        for kind, _sequence, payload in _messages(data):
            if kind != LOG_PACKET:
                continue
            try:
                # Sequence describes the entire private group, including deliberately
                # ignored local sources, not just accepted journal events.
                sequence_bytes = _attributes(payload[4:]).get(12, b"")
                if len(sequence_bytes) == 4:
                    sequence = struct.unpack("!I", sequence_bytes)[0]
                    with self._lock:
                        if self._last_sequence is not None:
                            gap = (sequence - self._last_sequence - 1) & 0xFFFFFFFF
                            if gap:
                                self._counters["dropped"] += gap
                                self._last_error = "NFLOG events were lost; protection is degraded"
                        self._last_sequence = sequence
                attempt = parse_attempt(payload)
            except MissingConntrack:
                with self._lock:
                    self._counters["missing_conntrack"] += 1
                    self._last_error = (
                        "NFLOG lacks TCP conntrack identity; attempts were not counted"
                    )
                continue
            except (ValueError, UnicodeError):
                with self._lock:
                    self._counters["malformed"] += 1
                continue
            self._record(attempt, time.monotonic())

    def _receive(self) -> None:
        sock = self._socket
        assert sock is not None
        while not self._stop.is_set():
            try:
                data, _ancillary, flags, address = sock.recvmsg(MAX_DATAGRAM)
                if flags & socket.MSG_TRUNC:
                    raise OSError(errno.ENOBUFS, "Truncated NFLOG datagram")
                if address[0] != 0:
                    continue
                self._consume(data)
            except TimeoutError:
                continue
            except ValueError:
                with self._lock:
                    self._counters["malformed"] += 1
            except OSError as exc:
                with self._lock:
                    self._last_error = f"Connection collector failed: {exc}"
                    if exc.errno == errno.ENOBUFS:
                        self._counters["dropped"] += 1
                if exc.errno != errno.ENOBUFS:
                    return
