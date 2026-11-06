"""Country-set lifecycle composed with the router's durable apply/rollback transaction."""

import json
import os
import threading
from contextlib import closing
from itertools import chain
from typing import Any

from app.compiler import FirewallError
from app.geoip import GeoIPService
from app.ipsets import DemoIPSetDriver, LinuxIPSetDriver
from app.models import Configuration
from app.system_lists import required_system_lists


class SystemListRuntime:
    def __init__(self, geoip: GeoIPService, driver: DemoIPSetDriver | LinuxIPSetDriver) -> None:
        self.geoip = geoip
        self.driver = driver
        self.lock = threading.RLock()
        self.journal = geoip.path.parent / "geoip-kernel-recovery.json"

    def snapshot(self, previous: Configuration) -> dict[str, Any]:
        return {
            "version": self.geoip.active_version,
            "lists": [item.model_dump() for item in required_system_lists(previous).values()],
        }

    def prepare(self, target: Configuration, *, create: bool = True) -> None:
        """Preflight creates only absent sets. Existing/active sets are never replaced here."""
        with self.lock:
            for item in required_system_lists(target).values():
                if item.kind == "temporary":
                    if create:
                        self.driver.ensure_temporary(item.name)
                    else:
                        self.driver.validate_existing(item.name, item.kind)
                else:
                    # Consume validation before the driver's exists fast path: absence of the
                    # configured country must fail even if an obsolete kernel set still exists.
                    with closing(self.geoip.networks(item.country)) as networks:
                        first = next(networks, None)
                        if first is None:
                            raise FirewallError(f"No GeoIP ranges for {item.country}")
                        if create:
                            self.driver.ensure_country(item.name, chain([first], networks))
                        else:
                            self.driver.validate_existing(item.name, item.kind)

    def preview(self, target: Configuration) -> dict[str, Any]:
        return {
            "version": self.geoip.active_version,
            "lists": [item.model_dump() for item in required_system_lists(target).values()],
        }

    def _save_journal(self, snapshot: dict[str, Any]) -> None:
        temporary = self.journal.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(snapshot, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.journal)
        fd = os.open(self.journal.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _clear_journal(self) -> None:
        self.journal.unlink(missing_ok=True)
        fd = os.open(self.journal.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def apply(self, target: Configuration) -> None:
        self._replace(target, self.geoip.active_version)

    def activate_version(self, target: Configuration, version: str) -> None:
        """Called by GeoIPService.update under the router lock, with no pending apply."""
        self._replace(target, version)

    def _replace(self, target: Configuration, version: str) -> None:
        with self.lock:
            items = required_system_lists(target)
            countries = [item for item in items.values() if item.kind == "country"]
            if countries:
                self.geoip.require_version(version)
            previous = self.snapshot(target)
            self._save_journal(previous)
            try:
                for item in items.values():
                    if item.kind == "temporary":
                        self.driver.ensure_temporary(item.name)
                    else:
                        self.driver.replace_country(
                            item.name, self.geoip.networks(item.country, version)
                        )
            except Exception as exc:
                try:
                    self.rollback(previous)
                    self._clear_journal()
                except (FirewallError, OSError) as recovery:
                    raise FirewallError(
                        f"Country-set update failed; recovery required: {recovery}"
                    ) from exc
                raise
            self._clear_journal()

    def rollback(self, snapshot: dict[str, Any]) -> None:
        from app.system_lists import SystemAddressList

        with self.lock:
            version = str(snapshot.get("version", ""))
            for raw in snapshot.get("lists", []):
                item = SystemAddressList.model_validate(raw)
                if item.kind == "temporary":
                    # Never replay expired F2B bans or extend their remaining kernel timeout.
                    self.driver.ensure_temporary(item.name)
                else:
                    self.driver.replace_country(
                        item.name, self.geoip.networks(item.country, version)
                    )

    def recover(self, applied: Configuration) -> None:
        """Run before restoring firewall references during boot or application startup."""
        with self.lock:
            pending_version = self.geoip.recover_activation()
            if self.journal.exists():
                if self.journal.stat().st_size > 128 * 1024:
                    raise FirewallError("Country-set recovery journal exceeds the size limit")
                try:
                    saved = json.loads(self.journal.read_text())
                    self.rollback(saved)
                except (ValueError, TypeError) as exc:
                    raise FirewallError("Country-set recovery journal is invalid") from exc
                self._clear_journal()
            if pending_version is not None:
                self.rollback(
                    {"version": pending_version, "lists": self.snapshot(applied)["lists"]}
                )
                self.geoip.finish_recovery()
            self.prepare(applied)
