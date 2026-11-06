"""Compose security/discovery services without blocking the router rollback watchdog."""

import io
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from app.compiler import FirewallError
from app.discovery import DiscoveryService
from app.discovery_models import DiscoverySettings, ScanSettings
from app.fail2ban_runtime import Fail2banService
from app.firewall import Conflict, FirewallService
from app.geoip import GeoIPService
from app.ipsets import DemoIPSetDriver, LinuxIPSetDriver
from app.models import Configuration
from app.scans import ScanService
from app.system_list_runtime import SystemListRuntime
from app.updates import UpdateService

log = logging.getLogger(__name__)


class SecurityServices:
    def __init__(
        self, data_dir: Path, demo: bool, firewall: FirewallService, updates: UpdateService
    ) -> None:
        self.firewall, self.updates, self.demo = firewall, updates, demo
        data_dir = data_dir / "demo-security" if demo else data_dir
        self.geoip = GeoIPService(data_dir)
        driver = DemoIPSetDriver() if demo else LinuxIPSetDriver(data_dir)
        self.lists = SystemListRuntime(self.geoip, driver)
        self.fail2ban = Fail2banService(
            data_dir,
            demo,
            driver,
            lambda address: str(self.geoip.lookup(address).get("country") or ""),
        )
        self.discovery = DiscoveryService(
            data_dir, demo, self.discovery_settings, data_dir / "network" / "dhcp.leases"
        )
        self.scans = ScanService(
            data_dir,
            demo,
            self.scan_settings,
            self.discovery.ingest_scan,
            network_configuration=lambda: self.applied().network,
        )
        self.stop = threading.Event()
        self.worker: threading.Thread | None = None
        self.update_thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.update_error = ""
        self.last_attempt = 0.0
        self.fail2ban.settings = self.applied().fail2ban
        if demo and not self.geoip.active_version:
            # Isolated demo fixtures only. Never a substitute for the live DB-IP dataset.
            self.geoip.import_csv(
                io.BytesIO(b"1.1.1.0,1.1.1.255,AU\n8.8.8.0,8.8.8.255,US\n9.9.9.0,9.9.9.255,US\n"),
                "2026-01",
                compressed=False,
            )
            self.geoip.activate("2026-01")

    def applied(self) -> Configuration:
        return Configuration.model_validate(self.firewall.store.read("applied"))

    def discovery_settings(self) -> DiscoverySettings:
        return self.applied().discovery

    def scan_settings(self) -> ScanSettings:
        return self.applied().scanning

    def start(self) -> None:
        # The application data-directory owner lock is already held by lifespan.
        self.scans.recover()
        self.worker = threading.Thread(target=self._maintain, daemon=True, name="router-discovery")
        self.worker.start()

    def close(self) -> None:
        self.stop.set()
        self.scans.close()
        if self.worker:
            self.worker.join(timeout=20)
        self.discovery.close()
        self.fail2ban.journal.close()
        if self.update_thread:
            self.update_thread.join(timeout=20)

    def _maintain(self) -> None:
        while not self.stop.is_set():
            try:
                self.discovery.maintain()
                settings = self.applied().geoip
                if settings.auto_update and not self.demo and not self.updates.active():
                    last = max(self.last_attempt, float(self.geoip.status()["last_check"]))
                    if time.time() - last >= settings.check_hours * 3600:
                        self.queue_geoip()
            except Conflict:
                # A draft or pending application is an expected reason to defer automatic
                # updates, not a service error to log repeatedly while the user edits.
                log.debug("Automatic GeoIP update deferred until the router is idle")
            except (FirewallError, OSError, ValueError, sqlite3.Error):
                log.exception("Security/discovery maintenance failed; existing protection retained")
            self.stop.wait(5)

    def geoip_status(self) -> dict[str, Any]:
        return {
            **self.geoip.status(),
            "demo": self.demo,
            "updating": bool(self.update_thread and self.update_thread.is_alive()),
            "error": self.update_error or self.geoip.status()["last_error"],
        }

    def _require_idle(self) -> None:
        state = self.firewall.state()
        if (
            self.stop.is_set()
            or self.updates.active()
            or state["pending"]
            or state["dirty"]
            or state["runtime_error"]
        ):
            raise Conflict("Apply/discard drafts and complete recovery before updating GeoIP")

    def queue_geoip(self) -> dict[str, Any]:
        with self.lock, self.firewall.lock:
            self._require_idle()
            if self.update_thread and self.update_thread.is_alive():
                raise Conflict("A GeoIP update is already running")
            self.last_attempt = time.time()
            self.update_error = ""
            if self.demo:
                return {
                    **self.geoip_status(),
                    "notice": "Демонстрационная база; загрузка не выполняется",
                }
            self.update_thread = threading.Thread(
                target=self._update, daemon=True, name="geoip-update"
            )
            self.update_thread.start()
            return self.geoip_status()

    def _activate(self, version: str) -> None:
        with self.firewall.lock:
            self._require_idle()
            self.geoip.activate(
                version, lambda active: self.lists.activate_version(self.applied(), active)
            )

    def _update(self) -> None:
        try:
            self.geoip.update(self._activate)
            self.firewall.store.write({}, "geoip_updated", self.geoip.active_version)
        except (FirewallError, Conflict, OSError, ValueError, sqlite3.Error) as exc:
            self.update_error = (
                "GeoIP storage is unavailable; previous protection retained"
                if isinstance(exc, sqlite3.Error)
                else str(exc)[:500]
            )
            try:
                self.firewall.store.write({}, "geoip_update_failed", self.update_error)
            except (sqlite3.Error, OSError):
                log.exception("Could not persist the GeoIP update failure audit event")
            log.warning("GeoIP update failed; previous version retained: %s", self.update_error)
