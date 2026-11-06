"""Dedicated Fail2ban instance, isolated from host jails and the HTTP session lifecycle."""

import argparse
import fcntl
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from app.compiler import FirewallError
from app.fail2ban_events import AuthenticationJournal, BanStore, TemporarySets
from app.fail2ban_models import F2BConfiguration, profile_id

WEB_FILTER = """[Definition]
failregex = ^\\s*openmikrorout auth_failure src=<ADDR> reason=credentials\\s*$
ignoreregex =
datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%SZ
"""

# Runs in the distribution's Fail2ban Python, which need not have application dependencies.
# It forwards ONLY typed ticket fields to our virtualenv, never regex captures/commands.
PYTHON_ACTION = """import json
import subprocess
from fail2ban.server.action import ActionBase

class Action(ActionBase):
    def __init__(self, jail, name, python, helper, data, profile):
        super().__init__(jail, name)
        self.argv = [python, helper, "--data-dir", data, "--profile", profile]

    def start(self):
        pass

    def stop(self):
        # Kernel timeouts remain effective while the engine restarts.
        pass

    def clearAllParams(self):
        # Fail2ban marks Python actions as retained on reload via this protocol.
        # Keep the current argv intact until the validated replacement is supplied.
        pass

    def reload(self, python, helper, data, profile):
        self.argv = [python, helper, "--data-dir", data, "--profile", profile]

    def flush(self):
        # Native stop/reload must not turn active tickets into manual-unban tombstones.
        # Individual unban operations still call unban(); expiry also lives in the kernel.
        return True

    def _event(self, operation, info):
        payload = json.dumps({"operation": operation, "address": str(info["ip"]),
            "started": float(info["time"]), "duration": int(info.get("bantime", 0))})
        result = subprocess.run(self.argv, input=payload, text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20, check=False)
        if result.returncode:
            raise RuntimeError("OpenMikroRout ban adapter failed")

    def ban(self, info):
        self._event("ban", info)

    def reban(self, info):
        self.ban(info)

    def unban(self, info):
        self._event("unban", info)
"""


def _safe_path(path: Path) -> str:
    value = str(path.absolute())
    if not re.fullmatch(r"[A-Za-z0-9_./ -]+", value):
        raise FirewallError("Fail2ban paths may contain only letters, digits, spaces, _, ., -, /")
    return value


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".omr-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Fail2banService:
    def __init__(
        self,
        data_dir: Path,
        demo: bool,
        driver: TemporarySets,
        country_lookup: Callable[[str], str] | None = None,
    ) -> None:
        self.data_dir = data_dir.resolve()
        self.directory = self.data_dir / "fail2ban"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.config_dir = self.directory / "config"
        self.socket = self.directory / "engine.sock"
        self.pidfile = self.directory / "engine.pid"
        self.demo = demo
        self.driver = driver
        self.lookup = country_lookup or (lambda _: "")
        self.bans = BanStore(self.data_dir, driver)
        self.journal = AuthenticationJournal(self.data_dir)
        self.lock = threading.RLock()
        self.settings = F2BConfiguration()
        self.last_error = ""

    @contextmanager
    def process_lock(self) -> Iterator[None]:
        with self.lock, (self.directory / "runtime.lock").open("a", encoding="utf-8") as stream:
            os.chmod(stream.name, 0o600)
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _client(self, arguments: list[str], config_dir: Path | None = None) -> str:
        binary = shutil.which("fail2ban-client")
        if not binary:
            raise FirewallError("Install fail2ban and the OpenMikroRout Fail2ban companion")
        try:
            result = subprocess.run(
                [
                    binary,
                    "-c",
                    str(config_dir or self.config_dir),
                    "-s",
                    str(self.socket),
                    "-p",
                    str(self.pidfile),
                    *arguments,
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                env={"PATH": os.defpath, "LC_ALL": "C", "PYTHONNOUSERSITE": "1"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError("The dedicated Fail2ban instance did not respond") from exc
        if result.returncode:
            # Do not expose Fail2ban matching lines or configured paths through an API error.
            raise FirewallError("The dedicated Fail2ban instance rejected the operation")
        return result.stdout[:32768]

    def _running_jails(self) -> set[str]:
        status = self._client(["status"])
        match = re.search(r"Jail list:\s*(.*)", status)
        return {name.strip() for name in match[1].split(",") if name.strip()} if match else set()

    def _actions_ready(self, expected: set[str]) -> bool:
        for jail in expected:
            actions = self._client(["get", jail, "actions"])
            if "omr" not in {line.strip() for line in actions.splitlines()}:
                return False
        return True

    def _render(self, settings: F2BConfiguration, destination: Path) -> None:
        root = Path(__file__).resolve().parents[1]
        helper = _safe_path(root / "app" / "fail2ban_action.py")
        python = _safe_path(Path(sys.executable))
        data = _safe_path(self.data_dir)
        auth_log = _safe_path(self.journal.path)
        engine_db = _safe_path(self.directory / "engine.sqlite3")
        _write_private(
            destination / "fail2ban.conf",
            (
                "[Definition]\nloglevel = WARNING\nlogtarget = SYSOUT\n"
                f"dbfile = {engine_db}\ndbpurgeage = 2592000\ndbmaxmatches = 0\n"
                f"socket = {_safe_path(self.socket)}\npidfile = {_safe_path(self.pidfile)}\n"
                "syslogsocket = auto\n"
                "allowipv6 = no\n"
            ),
        )
        _write_private(destination / "filter.d" / "omr-web.conf", WEB_FILTER)
        _write_private(destination / "action.d" / "omr.py", PYTHON_ACTION)
        lines = [
            "[DEFAULT]",
            "enabled = false",
            "usedns = no",
            "backend = polling",
            "maxretry = 5",
            "findtime = 600",
            "bantime = 900",
            "bantime.increment = false",
            "ignoreip = 127.0.0.0/8",
            "ignoreself = false",
            "logencoding = utf-8",
            "",
        ]
        for profile in settings.profiles:
            if not settings.enabled or not profile.enabled:
                continue
            lines += [
                f"[omr-{profile.id}]",
                "enabled = true",
                f"maxretry = {profile.max_retry}",
                f"findtime = {profile.find_time}",
                f"bantime = {profile.ban_time}",
                f"ignoreip = 127.0.0.0/8 {' '.join(profile.ignore_addresses)}",
            ]
            if profile.service == "web":
                lines += ["filter = omr-web", f"logpath = {auth_log}", "backend = polling"]
            else:
                # The distro-maintained sshd filter is read-only input, never editable via HTTP.
                for filename in ("sshd.conf", "common.conf"):
                    source = Path("/etc/fail2ban/filter.d") / filename
                    if not source.is_file():
                        raise FirewallError(
                            "SSH protection requires the distribution's sshd filter"
                        )
                    _write_private(destination / "filter.d" / filename, source.read_text())
                lines += [
                    "filter = sshd",
                    "backend = systemd",
                    "journalmatch = _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service",
                ]
            lines += [
                f'action = omr.py[python="{python}", helper="{helper}", '
                f'data="{data}", profile="{profile.id}"]',
                "",
            ]
        _write_private(destination / "jail.conf", "\n".join(lines))

    def initialize_files(self, settings: F2BConfiguration) -> None:
        """Installer/companion use only; ordinary preview does not activate configuration."""
        with self.process_lock():
            self._render(settings, self.config_dir)
            _write_private(self.directory / "settings.json", settings.model_dump_json())

    def check(self, previous: F2BConfiguration, target: F2BConfiguration) -> None:
        if self.demo or not target.enabled:
            return
        if not shutil.which("fail2ban-server"):
            raise FirewallError("Install fail2ban and start openmikrorout-fail2ban.service")
        with tempfile.TemporaryDirectory(prefix="check-", dir=self.directory) as stage:
            self._render(target, Path(stage))
            self._client(["-t"], Path(stage))
        self._client(["ping"])

    def preview(self, previous: F2BConfiguration, target: F2BConfiguration) -> dict[str, Any]:
        return {
            "enabled": target.enabled,
            "access_mode": target.access_mode,
            "profiles": [p.model_dump(mode="json") for p in target.profiles],
            "ipv4_only": True,
            "changed": previous != target,
        }

    def snapshot(self, previous: F2BConfiguration) -> dict[str, Any]:
        return {"settings": previous.model_dump(mode="json")}

    def apply(self, previous: F2BConfiguration, target: F2BConfiguration) -> None:
        with self.process_lock():
            if self.demo:
                self.settings = target.model_copy(deep=True)
                _write_private(self.directory / "settings.json", target.model_dump_json())
                return
            installed_file = self.directory / "settings.json"
            installed = (
                F2BConfiguration.model_validate_json(installed_file.read_text())
                if installed_file.exists()
                else F2BConfiguration()
            )
            needs_reload = target.enabled or previous.enabled or installed.enabled
            if needs_reload:
                self.check(previous, target)
            self._render(target, self.config_dir)
            _write_private(self.directory / "settings.json", target.model_dump_json())
            self.settings = target.model_copy(deep=True)
            if needs_reload:
                self._client(["reload"])
                expected = {f"omr-{p.id}" for p in target.profiles if target.enabled and p.enabled}
                if self._running_jails() != expected or not self._actions_ready(expected):
                    raise FirewallError(
                        "Fail2ban did not activate the requested protection profiles"
                    )
            self.bans.restore(target, self.lookup)
            self.last_error = ""

    def rollback(self, snapshot: dict[str, Any]) -> None:
        target = F2BConfiguration.model_validate(snapshot["settings"])
        self.apply(self.settings, target)

    def restore(self, settings: F2BConfiguration) -> None:
        """Call after ipsets exist and before early filter restoration / normal startup."""
        self.settings = settings.model_copy(deep=True)
        self.bans.restore(settings, self.lookup)

    def unban(self, profile: str, address: str) -> None:
        import ipaddress

        profile_id(profile)
        address = str(ipaddress.IPv4Address(address))
        if profile not in {item.id for item in self.settings.profiles}:
            raise ValueError("Unknown Fail2ban profile")
        with self.process_lock():
            # A disabled profile has no active jail. Keep a projection tombstone so
            # an old retained native ticket cannot resurrect its kernel ban later.
            if not self.demo and f"omr-{profile}" in self._running_jails():
                self._client(["set", f"omr-{profile}", "unbanip", address])
            # The action normally handles this. Also reconcile a missing/orphan engine ticket.
            self.bans.unban(profile, address)

    def _enforced(self) -> bool:
        from app.fail2ban_rules import f2b_anchor
        from app.filtering import LinuxFilterDriver, inspect

        snapshot = LinuxFilterDriver().snapshot()
        _, hooks = inspect(snapshot)
        for profile in self.settings.profiles:
            if not profile.enabled:
                continue
            hook = profile.chain.upper()
            first = next(
                (line for line in snapshot.splitlines() if line.startswith(f"-A {hook} ")), ""
            )
            if f"f2b:{hook}" not in hooks or shlex.split(first) != f2b_anchor(hook):
                return False
            if f"openmikrorout:f2b:{profile.id}" not in snapshot:
                return False
        return any(profile.enabled for profile in self.settings.profiles)

    def status(self) -> dict[str, Any]:
        available = bool(shutil.which("fail2ban-client") and shutil.which("fail2ban-server"))
        running = False
        error = ""
        if not self.demo and available and self.settings.enabled:
            try:
                running = "pong" in self._client(["ping"]).lower()
            except FirewallError as exc:
                error = str(exc)
        enforced = False
        if running:
            try:
                expected = {f"omr-{p.id}" for p in self.settings.profiles if p.enabled}
                enforced = (
                    self._enforced()
                    and expected == self._running_jails()
                    and self._actions_ready(expected)
                )
            except (FirewallError, RuntimeError) as exc:
                error = str(exc)
            if not enforced and not error:
                error = "Fail2ban работает, но системные правила не подтверждены перед ACCEPT"
        warnings = ["Защита действует только для IPv4; IPv6-путь проверяется отдельно."]
        if self.settings.access_mode == "direct":
            warnings.append("SSH-туннель и loopback не раскрывают исходный IP: он не блокируется.")
        elif self.settings.access_mode == "local_proxy":
            warnings.append("Принимается только один X-Forwarded-For от явно доверенного proxy.")
        if any(item.shared_listener and item.enabled for item in self.settings.profiles):
            warnings.append("Бан на общем порту затрагивает все сайты этого listener.")
        if self.demo:
            warnings.append("Деморежим: реальные попытки не считаются, сеть не блокируется.")
        profiles = []
        for item in self.settings.profiles:
            count = self.bans.page(profile=item.id, limit=1)["total"] if self.demo or running else 0
            profiles.append(
                {
                    "id": item.id,
                    "name": item.name,
                    "enabled": item.enabled,
                    "list_name": f"f2b_{item.id}",
                    "jail": f"omr-{item.id}",
                    "active_bans": count,
                }
            )
        return {
            "enabled": self.settings.enabled,
            "demo": self.demo,
            "available": available,
            "running": running,
            "effective": running and enforced and self.settings.enabled,
            "ipv4_only": True,
            "access_mode": self.settings.access_mode,
            "profiles": profiles,
            "warnings": warnings,
            "error": error or self.last_error,
        }


def daemon(data_dir: Path) -> int:
    """Companion service entry point. Never shares the system Fail2ban socket/jails."""
    from app.ipsets import LinuxIPSetDriver

    os.umask(0o077)
    service = Fail2banService(data_dir, False, LinuxIPSetDriver(data_dir))
    try:
        settings_file = service.directory / "settings.json"
        settings = (
            F2BConfiguration.model_validate_json(settings_file.read_text())
            if settings_file.exists()
            else F2BConfiguration()
        )
        service.initialize_files(settings)
        binary = shutil.which("fail2ban-server")
        if binary is None:
            raise FirewallError("Install fail2ban before starting its OpenMikroRout companion")
        os.execv(
            binary,
            [
                binary,
                "-c",
                str(service.config_dir),
                "-s",
                str(service.socket),
                "-p",
                str(service.pidfile),
                "-xf",
                "start",
            ],
        )
    finally:
        service.journal.close()
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["daemon", "initialize"])
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("OMR_DATA_DIR", "/var/lib/openmikrorout")),
    )
    args = parser.parse_args()
    if args.command == "daemon":
        return daemon(args.data_dir)
    from app.ipsets import LinuxIPSetDriver

    service = Fail2banService(args.data_dir, False, LinuxIPSetDriver(args.data_dir))
    service.initialize_files(F2BConfiguration())
    service.journal.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
