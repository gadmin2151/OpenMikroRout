"""Passive, opt-in neighbor inventory with bounded local persistence and provenance."""

import hashlib
import ipaddress
import json
import shutil
import socket
import sqlite3
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.discovery_io import DiscoveryError, bounded_command, connected_networks
from app.discovery_models import DiscoverySettings
from app.discovery_protocols import MAX_NEIGHBORS, clean_text, parse_arp, parse_lldp, parse_mndp
from app.display_filters import validate_display_negation
from app.link_models import interface_name
from app.telemetry import valid_address, valid_mac


class DiscoveryService:
    def __init__(
        self,
        data_dir: Path,
        demo: bool,
        settings: Callable[[], DiscoverySettings],
        lease_path: Path | None = None,
    ) -> None:
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = data_dir / "discovery.sqlite3"
        self.demo, self.settings = demo, settings
        self.lease_path = lease_path or data_dir / "network" / "dhcp.leases"
        self.lock = threading.RLock()
        self.last_collection = 0.0
        self.errors: dict[str, str] = {}
        self.socket: socket.socket | None = None
        self.closed = False
        self.vendors: dict[str, str] | None = None
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS hosts (
                    id TEXT PRIMARY KEY, interface TEXT NOT NULL, mac TEXT NOT NULL,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL, document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS hosts_seen ON hosts(last_seen DESC);
                CREATE INDEX IF NOT EXISTS hosts_segment ON hosts(interface, mac);
            """)
        self.path.chmod(0o600)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def ingest(self, observation: dict[str, Any], now: float | None = None) -> None:
        now = time.time() if now is None else now
        interface = interface_name(str(observation.get("interface", "")))
        source = str(observation.get("source", ""))
        if source not in ("arp", "dhcp", "lldp", "cdp", "mndp", "scan"):
            raise ValueError("Unknown discovery source")
        mac = valid_mac(str(observation.get("mac", ""))) or ""
        addresses = sorted(
            {
                str(ip)
                for item in observation.get("addresses", [])[:32]
                if (ip := valid_address(str(item)))
            }
        )
        identity = mac or clean_text(observation.get("chassis_id", "")) or ",".join(addresses)
        if not identity:
            return
        identifier = hashlib.sha256(f"{interface}\0{identity}".encode()).hexdigest()[:32]
        ttl = min(86400, max(1, int(observation.get("ttl", self.settings().stale_seconds))))
        allowed = (
            "hostname",
            "description",
            "platform",
            "model",
            "version",
            "chassis_id",
            "remote_port",
            "port_description",
            "vendor",
        )
        fields: dict[str, Any] = {
            key: clean_text(observation[key]) for key in allowed if observation.get(key)
        }
        fields["addresses"] = addresses
        fields["mac"] = mac
        if isinstance(observation.get("uptime_seconds"), int):
            fields["uptime_seconds"] = max(0, min(2**32 - 1, observation["uptime_seconds"]))
        fields["capabilities"] = [
            clean_text(value, 64) for value in observation.get("capabilities", [])[:32]
        ]
        if "ports" in observation:
            fields["ports"] = observation["ports"][:256]
        if observation.get("os_guesses"):
            fields["os_guesses"] = [
                clean_text(value, 100) for value in observation["os_guesses"][:16]
            ]
        if mac and not fields.get("vendor"):
            vendor = self._vendor(mac)
            if vendor:
                fields.update({"vendor": vendor, "vendor_source": "local Nmap OUI database"})
        with self.lock, self.connect() as db:
            migrated: sqlite3.Row | None = None
            if len(addresses) == 1:
                candidates = db.execute(
                    "SELECT id,mac,document,first_seen FROM hosts WHERE interface=? "
                    "AND last_seen>=? AND document LIKE ? LIMIT 3",
                    (interface, now - self.settings().stale_seconds, '%"' + addresses[0] + '"%'),
                ).fetchall()
                if not mac and len(candidates) == 1 and candidates[0]["mac"]:
                    identifier, mac = candidates[0]["id"], candidates[0]["mac"]
                elif mac and len(candidates) == 1 and not candidates[0]["mac"]:
                    migrated = candidates[0]
            row = db.execute(
                "SELECT document, first_seen FROM hosts WHERE id=?", (identifier,)
            ).fetchone()
            if migrated and not row:
                row = migrated
                db.execute("DELETE FROM hosts WHERE id=?", (migrated["id"],))
            previous = json.loads(row["document"]) if row else {"observations": []}
            observations = [
                item
                for item in previous["observations"]
                if not (item["source"] == source and item["fields"].get("addresses") == addresses)
            ]
            observations.append(
                {"source": source, "observed_at": now, "expires_at": now + ttl, "fields": fields}
            )
            observations = sorted(observations, key=lambda item: item["observed_at"])[-32:]
            document = {
                "id": identifier,
                "interface": interface,
                "mac": mac,
                "observations": observations,
            }
            db.execute(
                "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "last_seen=excluded.last_seen, document=excluded.document",
                (
                    identifier,
                    interface,
                    mac,
                    row["first_seen"] if row else now,
                    now,
                    json.dumps(document),
                ),
            )
            db.execute(
                "DELETE FROM hosts WHERE id NOT IN "
                "(SELECT id FROM hosts ORDER BY last_seen DESC LIMIT ?)",
                (MAX_NEIGHBORS,),
            )

    @staticmethod
    def _render(row: sqlite3.Row, now: float) -> dict[str, Any]:
        document: dict[str, Any] = json.loads(row["document"])
        values: dict[str, Any] = {}
        addresses: set[str] = set()
        for observation in sorted(document["observations"], key=lambda item: item["observed_at"]):
            observation["stale"] = observation["expires_at"] <= now
            for key, value in observation["fields"].items():
                if key == "addresses":
                    addresses.update(value)
                elif value != "" and value != []:
                    values[key] = value
        document.update(values)
        document.update(
            {
                "addresses": sorted(addresses),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "stale": all(item["stale"] for item in document["observations"]),
                "sources": sorted({item["source"] for item in document["observations"]}),
            }
        )
        return document

    def hosts(
        self,
        query: str = "",
        interface: str = "",
        offset: int = 0,
        limit: int = 50,
        *,
        negate: str | list[str] = "",
    ) -> dict[str, Any]:
        if not 0 <= offset <= MAX_NEIGHBORS or not 1 <= limit <= 100 or len(query) > 100:
            raise ValueError("Invalid host pagination or search")
        if interface:
            interface_name(interface)
        excluded = validate_display_negation(negate, {"query": query, "interface": interface})
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conditions = []
        parameters = []
        if interface:
            conditions.append("NOT (interface=?)" if "interface" in excluded else "interface=?")
            parameters.append(interface)
        if query:
            match = "document LIKE ? ESCAPE '\\'"
            conditions.append(f"NOT ({match})" if "query" in excluded else match)
            parameters.append(pattern)
        condition = " AND ".join(conditions) or "1"
        with self.connect() as db:
            total = db.execute(
                f"SELECT COUNT(*) FROM hosts WHERE {condition}", parameters
            ).fetchone()[0]
            rows = db.execute(
                f"SELECT * FROM hosts WHERE {condition} "
                "ORDER BY last_seen DESC, id LIMIT ? OFFSET ?",
                (*parameters, limit, offset),
            ).fetchall()
            items = [self._render(row, time.time()) for row in rows]
            conflicts = {
                (row["interface"], row["address"])
                for row in db.execute(
                    "SELECT h.interface,a.value AS address FROM hosts h, "
                    "json_each(h.document,'$.observations') o, "
                    "json_each(o.value,'$.fields.addresses') a "
                    "WHERE h.mac!='' AND json_extract(o.value,'$.expires_at')>? "
                    "GROUP BY h.interface,a.value HAVING COUNT(DISTINCT h.mac)>1",
                    (time.time(),),
                )
            }
            for item in items:
                item["conflicting_addresses"] = [
                    address
                    for address in item["addresses"]
                    if (item["interface"], address) in conflicts
                ]
        return {"items": items, "total": total, "offset": offset, "limit": limit, "demo": self.demo}

    def host(self, identifier: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM hosts WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        return self._render(row, time.time())

    def ingest_scan(self, interface: str, hosts: list[dict[str, Any]]) -> None:
        for host in hosts[:1024]:
            if host.get("state") == "up":
                self.ingest({**host, "interface": interface, "source": "scan", "ttl": 86400})

    def _vendor(self, mac: str) -> str:
        if int(mac[:2], 16) & 2:
            return ""  # Randomized/locally administered MACs do not establish a vendor.
        if self.vendors is None:
            self.vendors = {}
            path = Path("/usr/share/nmap/nmap-mac-prefixes")
            try:
                with path.open("rb") as stream:
                    content = stream.read(5 * 1024 * 1024 + 1)
                if len(content) <= 5 * 1024 * 1024:
                    for line in content.decode("utf-8", errors="replace").splitlines()[:65536]:
                        parts = line.split(" ", 1)
                        if len(parts) == 2 and len(parts[0]) == 6:
                            self.vendors[parts[0].upper()] = clean_text(parts[1])
            except FileNotFoundError:
                pass  # Optional local vendor database; never guess or perform a web lookup.
        return self.vendors.get(mac.replace(":", "")[:6].upper(), "")

    def _leases(self, settings: DiscoverySettings) -> None:
        if not self.lease_path.exists():
            return
        with self.lease_path.open("rb") as stream:
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise DiscoveryError("DHCP lease file exceeds its limit")
        networks = connected_networks()
        now = time.time()
        for line in content.decode("utf-8", errors="replace").splitlines()[:MAX_NEIGHBORS]:
            parts = line.split()
            if len(parts) != 5:
                continue
            try:
                expires = int(parts[0])
                address = ipaddress.IPv4Address(parts[2])
            except ValueError:
                continue
            if expires < 0 or (expires and expires <= now):
                continue
            matches = [
                name
                for name in settings.interfaces
                if any(
                    address in ipaddress.IPv4Network(subnet) for subnet in networks.get(name, [])
                )
            ]
            # Overlapping L3 interfaces do not provide enough evidence for a segment.
            if len(matches) != 1:
                continue
            self.ingest(
                {
                    "interface": matches[0],
                    "source": "dhcp",
                    "mac": parts[1],
                    "addresses": [parts[2]],
                    "hostname": "" if parts[3] == "*" else parts[3],
                    "ttl": min(settings.stale_seconds, expires - now)
                    if expires
                    else settings.stale_seconds,
                }
            )

    def _mndp(self, settings: DiscoverySettings) -> None:
        if self.socket is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.IPPROTO_IP, 8, 1)  # Linux IP_PKTINFO, no transmission.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                sock.bind(("0.0.0.0", 5678))
                sock.setblocking(False)
            except OSError:
                sock.close()
                raise
            self.socket = sock
        for _ in range(64):
            try:
                data, ancillary, flags, sender = self.socket.recvmsg(16384, 128)
            except BlockingIOError:
                break
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                continue
            interface = ""
            for level, kind, info in ancillary:
                if level == socket.IPPROTO_IP and kind == 8 and len(info) >= 12:
                    try:
                        interface = socket.if_indextoname(struct.unpack_from("=I", info)[0])
                    except OSError:
                        continue
            if interface not in settings.interfaces:
                continue
            observation = parse_mndp(data, interface, sender[0])
            if observation:
                self.ingest(observation)

    def maintain(self) -> None:
        if self.closed:
            return
        settings = self.settings()
        if not settings.enabled:
            self.errors.clear()
            if self.socket:
                self.socket.close()
                self.socket = None
            return
        if self.demo:
            return
        for source in list(self.errors):
            if source not in settings.protocols and not (
                source == "lldp" and "cdp" in settings.protocols
            ):
                self.errors.pop(source, None)
        if "mndp" in settings.protocols:
            try:
                self._mndp(settings)
                self.errors.pop("mndp", None)
            except (OSError, ValueError, DiscoveryError) as exc:
                self.errors["mndp"] = clean_text(exc)
        elif self.socket:
            self.socket.close()
            self.socket = None
        if time.monotonic() - self.last_collection < 15:
            return
        self.last_collection = time.monotonic()
        sources = {
            "arp": ("ip", ["-j", "-4", "neigh", "show"], parse_arp),
            "lldp": ("lldpcli", ["-f", "json0", "show", "neighbors", "details"], parse_lldp),
        }
        for source, (utility, arguments, decoder) in sources.items():
            if source not in settings.protocols and not (
                source == "lldp" and "cdp" in settings.protocols
            ):
                continue
            try:
                binary = shutil.which(utility)
                if not binary:
                    raise DiscoveryError(f"Install {utility} to collect {source.upper()}")
                rows = decoder(
                    bounded_command([binary, *arguments]).decode("utf-8", errors="replace"),
                    set(settings.interfaces),
                )
                for row in rows:
                    if row["source"] in settings.protocols:
                        self.ingest(row)
                self.errors.pop(source, None)
            except (OSError, ValueError, DiscoveryError) as exc:
                self.errors[source] = clean_text(exc)
        if "dhcp" in settings.protocols:
            try:
                self._leases(settings)
                self.errors.pop("dhcp", None)
            except (OSError, ValueError, DiscoveryError) as exc:
                self.errors["dhcp"] = clean_text(exc)

    def status(self) -> dict[str, Any]:
        settings = self.settings()
        return {
            "settings": settings.model_dump(mode="json"),
            "demo": self.demo,
            "errors": dict(self.errors),
            "lldp_available": bool(shutil.which("lldpcli")),
            "mndp_listening": self.socket is not None,
            "passive": True,
            "scope": "IPv4 / selected local segments; device-reported data is unverified",
        }

    def close(self) -> None:
        self.closed = True
        if self.socket:
            self.socket.close()
            self.socket = None
