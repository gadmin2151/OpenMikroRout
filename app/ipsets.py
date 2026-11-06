"""Narrow ipset adapter. Never flush/destroy the host's global set collection."""

import fcntl
import ipaddress
import math
import os
import shlex
import shutil
import sqlite3
import subprocess
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.compiler import FirewallError
from app.system_lists import kernel_set_name

MAX_NETWORKS = 600_000
MAX_BANS = 65_536
MAX_TIMEOUT = 2_147_483


class LinuxIPSetDriver:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.lock = threading.RLock()
        self.local = threading.local()
        self.data_dir = data_dir or Path(os.environ.get("OMR_DATA_DIR", "data"))
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.registry = self.data_dir / "ipsets.sqlite3"
        self.lock_path = self.data_dir / "ipsets.lock"
        with sqlite3.connect(self.registry) as db:
            db.execute("CREATE TABLE IF NOT EXISTS owned (name TEXT PRIMARY KEY)")
        self.registry.chmod(0o600)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self.lock:
            if getattr(self.local, "held", False):
                yield
                return
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                deadline = time.monotonic() + 65
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise FirewallError(
                                "Another system-list operation is still running"
                            ) from None
                        time.sleep(0.05)
                self.local.held = True
                yield
            finally:
                self.local.held = False
                os.close(fd)

    def _claim(self, name: str) -> None:
        with sqlite3.connect(self.registry) as db:
            db.execute("INSERT OR IGNORE INTO owned VALUES (?)", (kernel_set_name(name),))

    def _owned(self, name: str) -> bool:
        with sqlite3.connect(self.registry) as db:
            return (
                db.execute("SELECT 1 FROM owned WHERE name=?", (kernel_set_name(name),)).fetchone()
                is not None
            )

    def available(self) -> bool:
        return shutil.which("ipset") is not None

    def _run(self, args: list[str], payload: str | None = None) -> str:
        binary = shutil.which("ipset")
        if not binary:
            raise FirewallError("Install ipset to use system address lists")
        try:
            result = subprocess.run(
                [binary, *args],
                input=payload,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError("ipset operation failed or timed out") from exc
        if result.returncode:
            raise FirewallError(f"ipset {args[0]} failed: {result.stderr.strip()[:300]}")
        if len(result.stdout) > 64 * 1024 * 1024:
            raise FirewallError("ipset output exceeds the configured limit")
        return result.stdout

    def exists(self, name: str) -> bool:
        key = kernel_set_name(name)
        return key in self._run(["list", "-name"]).splitlines()

    def _verify(self, name: str, kind: str, timed: bool = False) -> None:
        if not self._owned(name):
            raise FirewallError(f"Reserved ipset {name} is not owned by OpenMikroRout")
        # Header inspection also rejects a foreign/incompatible set with a reserved name.
        header = self._run(["list", kernel_set_name(name), "-terse"])
        fields = dict(line.split(": ", 1) for line in header.splitlines() if ": " in line)
        if fields.get("Type") != kind or "family inet " not in fields.get("Header", "") + " ":
            raise FirewallError(f"Reserved ipset {name} has incompatible type/family")
        if timed and "timeout " not in fields.get("Header", ""):
            raise FirewallError(f"Reserved ipset {name} lacks kernel timeouts")

    def validate_existing(self, name: str, kind: str) -> None:
        with self._locked():
            if not self.exists(name):
                raise FirewallError("Full access required to prepare new system lists")
            self._verify(
                name, "hash:ip" if kind == "temporary" else "hash:net", timed=kind == "temporary"
            )

    def ensure_temporary(self, name: str) -> None:
        if not name.startswith("f2b_"):
            raise ValueError("Temporary sets must belong to a Fail2ban profile")
        with self._locked():
            if not self.exists(name):
                self._claim(name)
                self._run(
                    [
                        "create",
                        kernel_set_name(name),
                        "hash:ip",
                        "family",
                        "inet",
                        "timeout",
                        "900",
                        "maxelem",
                        str(MAX_BANS),
                    ]
                )
            self._verify(name, "hash:ip", timed=True)

    def add_temporary(self, name: str, address: str, timeout: int) -> None:
        address = str(ipaddress.IPv4Address(address))
        if not 1 <= timeout <= MAX_TIMEOUT:
            raise ValueError("A finite positive kernel timeout is required")
        with self._locked():
            self.ensure_temporary(name)
            self._run(["add", kernel_set_name(name), address, "timeout", str(timeout), "-exist"])

    def delete_temporary(self, name: str, address: str) -> None:
        address = str(ipaddress.IPv4Address(address))
        with self._locked():
            if self.exists(name):
                self._verify(name, "hash:ip", timed=True)
                self._run(["del", kernel_set_name(name), address, "-exist"])

    def temporary_entries(self, name: str) -> list[dict[str, Any]]:
        with self._locked():
            if not self.exists(name):
                return []
            self._verify(name, "hash:ip", timed=True)
            result = []
            key = kernel_set_name(name)
            for line in self._run(["save", key]).splitlines():
                tokens = shlex.split(line)
                if len(tokens) >= 5 and tokens[:2] == ["add", key] and "timeout" in tokens:
                    timeout = int(tokens[tokens.index("timeout") + 1])
                    if timeout > 0:
                        result.append(
                            {"address": str(ipaddress.IPv4Address(tokens[2])), "timeout": timeout}
                        )
                if len(result) > MAX_BANS:
                    raise FirewallError("Temporary set exceeds the configured entry limit")
            return result

    def ensure_country(self, name: str, networks: Iterable[str]) -> None:
        with self._locked():
            if self.exists(name):
                self._verify(name, "hash:net")
            else:
                self.replace_country(name, networks)

    def replace_country(self, name: str, networks: Iterable[str]) -> None:
        if not name.startswith("geo_"):
            raise ValueError("Country sets must use geo_<country>")
        key = kernel_set_name(name)
        stage = f"omr_stage_{uuid4().hex[:16]}"
        with self._locked():
            present = self.exists(name)
            if present:
                self._verify(name, "hash:net")
            else:
                self._claim(name)
            commands = [f"create {stage} hash:net family inet maxelem {MAX_NETWORKS}"]
            for count, value in enumerate(networks, 1):
                if count > MAX_NETWORKS:
                    raise FirewallError("Country set exceeds the configured network limit")
                network = ipaddress.IPv4Network(value, strict=True)
                if network.prefixlen == 0:
                    raise FirewallError("A country may not cover the complete IPv4 address space")
                commands.append(f"add {stage} {network}")
            created = False
            try:
                # The live set is never touched by a failed population of the staging set.
                created = True
                self._run(["restore"], "\n".join(commands) + "\n")
                if present:
                    self._run(["swap", stage, key])
                else:
                    self._run(["rename", stage, key])
                    created = False
            finally:
                if created:
                    self._run(["destroy", stage])


class DemoIPSetDriver:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.countries: dict[str, list[str]] = {}
        self.temporary: dict[str, dict[str, float]] = {}

    def available(self) -> bool:
        return True

    def exists(self, name: str) -> bool:
        kernel_set_name(name)
        return name in self.countries or name in self.temporary

    def validate_existing(self, name: str, kind: str) -> None:
        with self.lock:
            if not self.exists(name):
                raise FirewallError("Full access required to prepare new system lists")
            if (kind == "temporary") != (name in self.temporary):
                raise FirewallError("System list has incompatible type")

    def ensure_temporary(self, name: str) -> None:
        kernel_set_name(name)
        if not name.startswith("f2b_"):
            raise ValueError("Temporary set required")
        with self.lock:
            self.temporary.setdefault(name, {})

    def add_temporary(self, name: str, address: str, timeout: int) -> None:
        if not 1 <= timeout <= MAX_TIMEOUT:
            raise ValueError("A finite positive kernel timeout is required")
        address = str(ipaddress.IPv4Address(address))
        with self.lock:
            self.ensure_temporary(name)
            self.temporary[name][address] = time.time() + timeout

    def delete_temporary(self, name: str, address: str) -> None:
        with self.lock:
            self.temporary.get(name, {}).pop(address, None)

    def temporary_entries(self, name: str) -> list[dict[str, Any]]:
        with self.lock:
            return [
                {"address": address, "timeout": math.ceil(expiry - time.time())}
                for address, expiry in self.temporary.get(name, {}).items()
                if expiry > time.time()
            ]

    def ensure_country(self, name: str, networks: Iterable[str]) -> None:
        if name not in self.countries:
            self.replace_country(name, networks)

    def replace_country(self, name: str, networks: Iterable[str]) -> None:
        kernel_set_name(name)
        values = [str(ipaddress.IPv4Network(value, strict=True)) for value in networks]
        if len(values) > MAX_NETWORKS:
            raise FirewallError("Country set exceeds the configured network limit")
        with self.lock:
            self.countries[name] = values
