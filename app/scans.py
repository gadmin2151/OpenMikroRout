"""Explicit, bounded Nmap jobs, restricted to approved directly connected IPv4 networks."""

import ipaddress
import json
import os
import selectors
import shutil
import sqlite3
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.discovery_io import DiscoveryError, connected_networks
from app.discovery_models import ScanRequest, ScanSettings
from app.discovery_protocols import clean_text
from app.network_models import NetworkConfiguration
from app.telemetry import valid_address, valid_mac

MAX_OUTPUT = 16 * 1024 * 1024
MAX_PORT_RESULTS = 4096
ACTIVE = ("queued", "running")
SETTINGS_CHECK_SECONDS = 1
TOPOLOGY_CHECK_SECONDS = 5


def validated_target(
    request: ScanRequest, settings: ScanSettings, networks: dict[str, list[str]]
) -> str:
    if not settings.enabled or request.interface not in settings.interfaces:
        raise DiscoveryError("Active scanning is disabled for this interface")
    allowed = [ipaddress.IPv4Network(value) for value in networks.get(request.interface, [])]
    if not allowed:
        raise DiscoveryError("The selected interface has no connected IPv4 network")
    if request.kind == "network":
        target = ipaddress.IPv4Network(request.target)
        if target.num_addresses > settings.max_hosts:
            raise DiscoveryError(f"Network scan is limited to {settings.max_hosts} addresses")
        if not any(target.subnet_of(network) for network in allowed):
            raise DiscoveryError("The target must belong to the selected connected network")
        if target.is_loopback or target.is_multicast or target.is_unspecified:
            raise DiscoveryError("Use a unicast connected network")
        return str(target)
    try:
        address = ipaddress.IPv4Address(request.target)
    except ValueError:
        # Bounded system utility avoids an unbounded getaddrinfo call in the API worker.
        from app.wireguard import resolve_ipv4

        address = ipaddress.IPv4Address(resolve_ipv4(request.target))
    if not valid_address(str(address)) or address.is_reserved:
        raise DiscoveryError("Use a unicast host in the selected connected network")
    if not any(
        address in network
        and (
            network.prefixlen >= 31
            or address not in (network.network_address, network.broadcast_address)
        )
        for network in allowed
    ):
        raise DiscoveryError("The target must be a host in the selected connected network")
    return str(address)


def scan_command(
    binary: str, request: ScanRequest, settings: ScanSettings, target: str
) -> list[str]:
    arguments = [
        binary,
        "-n",
        "-e",
        request.interface,
        "--max-rate",
        str(settings.max_rate),
        "--max-retries",
        "1",
        "--host-timeout",
        f"{settings.timeout_seconds}s",
        "--stats-every",
        "1s",
        "-oX",
        "-",
    ]
    if request.kind == "network":
        arguments += ["-sn", "-PR"]
    else:
        arguments += ["-Pn", "-sU" if request.profile == "udp" else "-sS"]
        if request.profile == "quick":
            arguments += ["--top-ports", "100"]
        elif request.profile == "full":
            arguments += ["-p", "1-65535"]
        else:
            arguments += ["-p", request.ports]
        if request.service_detection:
            arguments += ["-sV", "--version-light"]
    return [*arguments, target]


def parse_host(element: ET.Element) -> dict[str, Any]:
    addresses, mac, vendor = [], "", ""
    for row in element.findall("address")[:32]:
        if row.get("addrtype") == "ipv4" and (address := valid_address(row.get("addr", ""))):
            addresses.append(address)
        if row.get("addrtype") == "mac":
            mac = valid_mac(row.get("addr", "")) or ""
            vendor = clean_text(row.get("vendor", ""))
    status = element.find("status")
    hostname = element.find("hostnames/hostname")
    ports = []
    all_ports = element.findall("ports/port")
    for row in all_ports[:MAX_PORT_RESULTS]:
        try:
            port = int(row.get("portid", "0"))
        except ValueError:
            continue
        if not 1 <= port <= 65535 or row.get("protocol") not in ("tcp", "udp"):
            continue
        state, service = row.find("state"), row.find("service")
        ports.append(
            {
                "port": port,
                "protocol": row.get("protocol"),
                "state": clean_text(
                    state.get("state", "unknown") if state is not None else "unknown", 32
                ),
                "reason": clean_text(state.get("reason", "") if state is not None else "", 100),
                "service": clean_text(service.get("name", "") if service is not None else "", 100),
                "product": clean_text(service.get("product", "") if service is not None else ""),
                "version": clean_text(service.get("version", "") if service is not None else ""),
                "os_guess": clean_text(
                    service.get("ostype", "") if service is not None else "", 100
                ),
                "method": clean_text(service.get("method", "") if service is not None else "", 32),
                "confidence": clean_text(service.get("conf", "") if service is not None else "", 8),
            }
        )
    extra = []
    for row in element.findall("ports/extraports")[:16]:
        try:
            count = int(row.get("count", "0"))
        except ValueError:
            continue
        extra.append(
            {
                "state": clean_text(row.get("state", "unknown"), 32),
                "count": min(65535, max(0, count)),
            }
        )
    return {
        "addresses": addresses,
        "mac": mac,
        "vendor": vendor,
        "hostname": clean_text(hostname.get("name", "") if hostname is not None else ""),
        "state": clean_text(
            status.get("state", "unknown") if status is not None else "unknown", 32
        ),
        "reason": clean_text(status.get("reason", "") if status is not None else "", 100),
        "ports": ports,
        "os_guesses": sorted({port["os_guess"] for port in ports if port["os_guess"]})[:16],
        "other_ports": extra,
        "ports_truncated": len(all_ports) > MAX_PORT_RESULTS,
    }


class ScanService:
    def __init__(
        self,
        data_dir: Path,
        demo: bool,
        settings: Callable[[], ScanSettings],
        on_result: Callable[[str, list[dict[str, Any]]], None] | None = None,
        *,
        network_configuration: Callable[[], NetworkConfiguration] | None = None,
    ) -> None:
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = data_dir / "scans.sqlite3"
        self.demo, self.settings, self.on_result = demo, settings, on_result
        self.network_configuration = network_configuration
        self.lock = threading.RLock()
        self.cancelled: dict[str, threading.Event] = {}
        self.threads: dict[str, threading.Thread] = {}
        self.requests: deque[float] = deque()
        self.closed = False
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, state TEXT NOT NULL, created REAL NOT NULL,
                    updated REAL NOT NULL, request TEXT NOT NULL, target TEXT NOT NULL,
                    result TEXT NOT NULL, error TEXT NOT NULL, progress REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS scan_jobs_created ON jobs(created DESC);
            """)
        self.path.chmod(0o600)

    def recover(self) -> None:
        """Call only after acquiring the application's exclusive process lock."""
        with self.lock, self.connect() as db:
            db.execute(
                "UPDATE jobs SET state='interrupted', updated=?, "
                "error='Service restarted; scan was not resumed' "
                "WHERE state IN ('queued','running')",
                (time.time(),),
            )

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _row(row: sqlite3.Row, detail: bool = True) -> dict[str, Any]:
        result = dict(row)
        result["request"] = json.loads(result["request"])
        if detail:
            result["result"] = json.loads(result["result"])
        else:
            result.pop("result", None)
        return result

    def status(self) -> dict[str, Any]:
        try:
            networks, error = self._networks(), ""
        except DiscoveryError as exc:
            networks, error = {}, str(exc)
        settings = self.settings()
        return {
            "settings": settings.model_dump(mode="json"),
            "demo": self.demo,
            "available": self.demo or bool(shutil.which("nmap")),
            "networks": networks,
            "error": error,
            "scope": "Only directly connected IPv4 networks on allowed interfaces",
        }

    def _networks(self) -> dict[str, list[str]]:
        if self.demo:
            configuration = self.network_configuration() if self.network_configuration else None
            return connected_networks(True, configuration)
        return connected_networks()

    def jobs(self, offset: int = 0, limit: int = 20) -> dict[str, Any]:
        if not 0 <= offset <= 100 or not 1 <= limit <= 100:
            raise ValueError("Invalid scan history pagination")
        with self.connect() as db:
            total = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            rows = db.execute(
                "SELECT id,state,created,updated,request,target,error,progress "
                "FROM jobs ORDER BY created DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return {
            "items": [self._row(row, False) for row in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    def job(self, identifier: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()
        if not row:
            raise KeyError(identifier)
        return self._row(row)

    def start(self, request: ScanRequest) -> dict[str, Any]:
        with self.lock:
            if self.closed:
                raise DiscoveryError("The scan service is stopping")
            settings = self.settings()
            target = validated_target(request, settings, self._networks())
            binary = shutil.which("nmap")
            if not self.demo and not binary:
                raise DiscoveryError("Install Nmap to run network scans")
            now = time.time()
            while self.requests and self.requests[0] < now - 60:
                self.requests.popleft()
            if len(self.requests) >= 6:
                raise DiscoveryError("Scans are limited to six starts per minute")
            with self.connect() as db:
                count = db.execute(
                    "SELECT COUNT(*) FROM jobs WHERE state IN ('queued','running')"
                ).fetchone()[0]
                if count:
                    raise DiscoveryError("Another scan is active; wait or cancel it")
                identifier = uuid4().hex
                initial = {
                    "hosts": [],
                    "demo": self.demo,
                    "partial": True,
                    "note": "No response does not prove that a host is absent",
                }
                db.execute(
                    "INSERT INTO jobs VALUES (?, 'queued', ?, ?, ?, ?, ?, '', 0)",
                    (identifier, now, now, request.model_dump_json(), target, json.dumps(initial)),
                )
                db.execute(
                    "DELETE FROM jobs WHERE id NOT IN "
                    "(SELECT id FROM jobs ORDER BY created DESC LIMIT ?)",
                    (settings.history_limit,),
                )
            self.requests.append(now)
            event = threading.Event()
            self.cancelled[identifier] = event
            thread = threading.Thread(
                target=self._run,
                args=(identifier, request, settings, target, binary or "nmap", event),
                daemon=True,
                name="omr-network-scan",
            )
            self.threads[identifier] = thread
            thread.start()
            return self.job(identifier)

    def _update(
        self,
        identifier: str,
        state: str,
        result: dict[str, Any],
        error: str = "",
        progress: float = 0,
    ) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET state=?, updated=?, result=?, error=?, progress=? WHERE id=?",
                (
                    state,
                    time.time(),
                    json.dumps(result),
                    clean_text(error, 500),
                    min(100, max(0, progress)),
                    identifier,
                ),
            )

    def cancel(self, identifier: str) -> dict[str, Any]:
        with self.lock:
            job = self.job(identifier)
            event = self.cancelled.get(identifier)
            if event and job["state"] in ACTIVE:
                event.set()
            return self.job(identifier)

    def _run(
        self,
        identifier: str,
        request: ScanRequest,
        settings: ScanSettings,
        target: str,
        binary: str,
        event: threading.Event,
    ) -> None:
        result: dict[str, Any] = {
            "hosts": [],
            "demo": self.demo,
            "partial": True,
            "note": "No response does not prove that a host is absent",
        }
        try:
            self._update(identifier, "running", result)
            if self.demo:
                result.update(
                    {
                        "partial": False,
                        "note": "Деморежим: сканирование не запускалось; сеть не опрашивалась",
                    }
                )
                self._update(identifier, "completed", result, progress=100)
                return
            # Revalidate immediately before launch against the current interface topology/settings.
            pinned_request = request.model_copy(update={"target": target})
            validated_target(pinned_request, self.settings(), self._networks())
            self._execute(identifier, request, settings, target, binary, event, result)
            if self.on_result:
                self.on_result(request.interface, result["hosts"])
        except (
            OSError,
            ValueError,
            DiscoveryError,
            ET.ParseError,
            subprocess.SubprocessError,
        ) as exc:
            self._update(identifier, "cancelled" if event.is_set() else "error", result, str(exc))
        finally:
            with self.lock:
                self.cancelled.pop(identifier, None)
                self.threads.pop(identifier, None)

    def _execute(
        self,
        identifier: str,
        request: ScanRequest,
        settings: ScanSettings,
        target: str,
        binary: str,
        event: threading.Event,
        result: dict[str, Any],
    ) -> None:
        process = subprocess.Popen(
            scan_command(binary, request, settings, target),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
        assert process.stdout is not None and process.stderr is not None
        parser = ET.XMLPullParser(events=("end",))
        total, progress, tail, error_output = 0, 0.0, b"", bytearray()
        started, saved = time.monotonic(), 0.0
        settings_checked = started
        topology_checked = started
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "xml")
                selector.register(process.stderr, selectors.EVENT_READ, "error")
                while selector.get_map():
                    if event.is_set():
                        raise DiscoveryError("Scan cancelled")
                    if time.monotonic() - started > settings.timeout_seconds:
                        raise DiscoveryError("Scan timed out; available results are partial")
                    if time.monotonic() - settings_checked >= SETTINGS_CHECK_SECONDS:
                        current = self.settings()
                        if not current.enabled or request.interface not in current.interfaces:
                            event.set()
                            raise DiscoveryError("Scan cancelled by the applied scan settings")
                        settings_checked = time.monotonic()
                    if time.monotonic() - topology_checked >= TOPOLOGY_CHECK_SECONDS:
                        try:
                            validated_target(
                                request.model_copy(update={"target": target}),
                                self.settings(),
                                self._networks(),
                            )
                        except DiscoveryError as exc:
                            event.set()
                            raise DiscoveryError(
                                "Scan cancelled: the allowed network changed"
                            ) from exc
                        topology_checked = time.monotonic()
                    for key, _ in selector.select(0.2):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_OUTPUT:
                            raise DiscoveryError("Scan output limit reached; results are partial")
                        if key.data == "error":
                            error_output.extend(chunk[: max(0, 4096 - len(error_output))])
                            continue
                        checked = (tail + chunk).upper()
                        if (
                            b"\0" in checked
                            or b"<!ENTITY" in checked
                            or b"<!DOCTYPE NMAPRUN [" in checked
                        ):
                            raise DiscoveryError("Unsupported XML declaration in scan output")
                        tail = chunk[-64:]
                        parser.feed(chunk)
                        for _, element in parser.read_events():
                            if element.tag == "host":
                                host = parse_host(element)
                                if host["addresses"] and len(result["hosts"]) < settings.max_hosts:
                                    result["hosts"].append(host)
                                element.clear()
                            elif element.tag == "taskprogress":
                                progress = float(element.get("percent", "0"))
                                element.clear()
                        if time.monotonic() - saved >= 1:
                            self._update(identifier, "running", result, progress=progress)
                            saved = time.monotonic()
            process.wait(timeout=2)
            parser.close()
            if process.returncode != 0:
                raise DiscoveryError(
                    "Nmap failed: "
                    + clean_text(error_output.decode("utf-8", errors="replace"), 350)
                )
            result["partial"] = any(host["ports_truncated"] for host in result["hosts"])
            self._update(identifier, "completed", result, progress=100)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
            process.wait(timeout=2)
            process.stdout.close()
            process.stderr.close()

    def close(self) -> None:
        with self.lock:
            self.closed = True
            for event in self.cancelled.values():
                event.set()
            threads = list(self.threads.values())
        for thread in threads:
            # A topology read has a five-second deadline; allow it to finish before
            # the cancellation path terminates/reaps Nmap.
            thread.join(timeout=10)
