"""Root-owned systemd worker: verify, stage, snapshot, switch and health-check a release."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import closing
from pathlib import Path, PurePosixPath
from typing import Protocol

from app.updates import (
    ACTIVE_PHASES,
    GitHubReleaseClient,
    ReleaseManifest,
    UpdateConfig,
    UpdateError,
    UpdateJob,
    atomic_json,
    private_json,
    version_tuple,
)

MAX_EXTRACTED = 128 * 1024 * 1024
MAX_MEMBERS = 4096
PACKAGE_ROOTS = {
    "app",
    "deploy",
    "requirements.lock",
    "pyproject.toml",
    "release.json",
    "README.md",
    "BRAND.md",
    "run.sh",
}


def extract_package(archive: Path, target: Path) -> None:
    seen: set[str] = set()
    total = 0
    count = 0
    with tarfile.open(archive, mode="r|gz") as package:
        for member in package:
            count += 1
            name = PurePosixPath(member.name)
            if (
                count > MAX_MEMBERS
                or name.is_absolute()
                or not name.parts
                or ".." in name.parts
                or "\\" in member.name
                or len(member.name) > 240
                or name.parts[0] not in PACKAGE_ROOTS
                or str(name) in seen
                or not (member.isfile() or member.isdir())
            ):
                raise UpdateError("Unsafe path or entry type in the update archive")
            seen.add(str(name))
            total += member.size
            if member.size < 0 or member.size > 20 * 1024 * 1024 or total > MAX_EXTRACTED:
                raise UpdateError("Update archive exceeds extraction limits")
            path = target.joinpath(*name.parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            stream = package.extractfile(member)
            if stream is None:
                raise UpdateError("Cannot read an update archive entry")
            with stream, path.open("xb") as output:
                shutil.copyfileobj(stream, output, length=65536)
            path.chmod(0o755 if member.mode & 0o111 else 0o644)
    required = {
        "app/main.py",
        "app/version.py",
        "app/update_worker.py",
        "requirements.lock",
        "release.json",
    }
    if not required <= seen:
        raise UpdateError("The update package is incomplete")


def validate_requirements(path: Path) -> None:
    content = path.read_text()
    if len(content) > 65536:
        raise UpdateError("Dependency lock file exceeds its size limit")
    rows = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if (
        not rows
        or len(rows) > 256
        or any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*==[0-9][A-Za-z0-9.!+_-]*", line)
            for line in rows
        )
    ):
        raise UpdateError("Dependencies must be pinned packages from the configured package index")


def installed_version(path: Path) -> str:
    if (path / "release.json").exists():
        value = str(private_json(path / "release.json")["version"])
    else:
        with (path / "pyproject.toml").open("rb") as stream:
            value = str(tomllib.load(stream)["project"]["version"])
    version_tuple(value)
    return value


def router_ready(data_dir: Path) -> bool:
    path = data_dir / "linux.sqlite3"
    if not path.exists():
        return False
    try:
        with closing(
            sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        ) as db:
            rows = {
                key: json.loads(value)
                for key, value in db.execute(
                    "SELECT key,value FROM state "
                    "WHERE key IN ('config','applied','pending','runtime_error')"
                )
            }
        return (
            rows.get("pending") is None
            and rows.get("runtime_error") is None
            and rows.get("config") == rows.get("applied")
            and "config" in rows
        )
    except (sqlite3.Error, ValueError):
        return False


def sync_snapshot(path: Path) -> None:
    """Persist copied file contents and directory entries before trusting a snapshot."""

    def sync_directory(directory: Path) -> None:
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def sync_contents(directory: Path) -> None:
        for child in directory.iterdir():
            if child.is_symlink():
                # Persist the link via its parent; virtualenv links can point outside the release.
                continue
            if child.is_dir():
                sync_contents(child)
            else:
                with child.open("rb") as stream:
                    os.fsync(stream.fileno())
        sync_directory(directory)

    sync_contents(path)
    sync_directory(path.parent)


class ServiceControl(Protocol):
    def stop(self) -> None: ...
    def start(self) -> None: ...
    def healthy(self, expected: str) -> bool: ...


class ReleaseSource(Protocol):
    def release(self, version: str | None = None) -> tuple[ReleaseManifest, bytes, str]: ...
    def download(self, url: str, limit: int) -> bytes: ...


class BootRecoveryControl:
    """Boot ordering keeps the web service stopped until offline recovery completes."""

    def __init__(self, config: UpdateConfig) -> None:
        self.config = config

    def stop(self) -> None:
        return

    def start(self) -> None:
        return

    def healthy(self, expected: str) -> bool:
        return installed_version(self.config.install_dir) == expected and router_ready(
            self.config.data_dir
        )


class SystemdControl:
    def __init__(self, config: UpdateConfig) -> None:
        self.config = config
        self.systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"

    def _run(self, action: str) -> None:
        try:
            result = subprocess.run(
                [self.systemctl, action, self.config.service],
                capture_output=True,
                timeout=100,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UpdateError("Application service operation failed or timed out") from exc
        if result.returncode:
            raise UpdateError("Application service operation failed")

    def stop(self) -> None:
        self._run("stop")

    def start(self) -> None:
        self._run("start")

    def healthy(self, expected: str) -> bool:
        for _ in range(20):
            try:
                with urllib.request.urlopen(self.config.health_url, timeout=2) as response:
                    body = json.loads(response.read(4096))
                correct_version = body.get("version") == expected or (
                    expected == "0.2.0" and "version" not in body
                )
                if (
                    body.get("status") == "ok"
                    and body.get("mode") == "linux"
                    and correct_version
                    and router_ready(self.config.data_dir)
                ):
                    return True
            except (OSError, ValueError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        return False


def install_environment(target: Path, manifest: ReleaseManifest) -> None:
    validate_requirements(target / "requirements.lock")
    commands = [
        [sys.executable, "-m", "venv", str(target / ".venv")],
        [
            str(target / ".venv/bin/python"),
            "-m",
            "pip",
            "install",
            "--isolated",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--index-url",
            "https://pypi.org/simple",
            "-r",
            str(target / "requirements.lock"),
        ],
        [str(target / ".venv/bin/python"), "-m", "pip", "check"],
        [
            str(target / ".venv/bin/python"),
            "-c",
            "import app.main, app.update_worker; from app.version import VERSION; print(VERSION)",
        ],
    ]
    for command in commands:
        try:
            result = subprocess.run(
                command,
                cwd=target,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UpdateError("Release dependency installation failed or timed out") from exc
        if result.returncode:
            raise UpdateError("Release dependency installation or import validation failed")
        if command == commands[-1] and result.stdout.strip() != manifest.version:
            raise UpdateError("Installed code version does not match the signed release")


class UpdateWorker:
    def __init__(
        self,
        config: UpdateConfig,
        control: ServiceControl,
        *,
        client: ReleaseSource | None = None,
        installer: Callable[[Path, ReleaseManifest], None] = install_environment,
    ) -> None:
        self.config, self.control = config, control
        self.client = client
        self.installer = installer
        self.journal = config.state_dir / "recovery.json"

    def _job(self) -> UpdateJob:
        return UpdateJob.model_validate(private_json(self.config.state_dir / "job.json"))

    def _phase(self, job: UpdateJob, phase: str, message: str, error: str = "") -> None:
        updated = job.model_copy(
            update={"phase": phase, "message": message, "error": error, "updated_at": time.time()}
        )
        validated = UpdateJob.model_validate(updated.model_dump())
        atomic_json(self.config.state_dir / "job.json", validated.model_dump())

    def _switch(self, target: Path) -> None:
        if target.resolve().parent != self.config.releases_dir.resolve() or not target.is_dir():
            raise UpdateError("Release target is outside the application release directory")
        temporary = self.config.install_dir.parent / (".openmikrorout-link-" + os.urandom(8).hex())
        try:
            temporary.symlink_to(target, target_is_directory=True)
            os.replace(temporary, self.config.install_dir)
            descriptor = os.open(self.config.install_dir.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def _backup(self, path: Path) -> None:
        path.mkdir(parents=True, mode=0o700)
        destination = path / "data"
        shutil.copytree(
            self.config.data_dir,
            destination,
            ignore=shutil.ignore_patterns("updates", "*.sqlite3-wal", "*.sqlite3-shm", "*.lock"),
        )
        for source in self.config.data_dir.glob("*.sqlite3"):
            with (
                closing(sqlite3.connect(source)) as original,
                closing(sqlite3.connect(destination / source.name)) as target,
            ):
                original.backup(target)
            (destination / source.name).chmod(0o600)
        sync_snapshot(path)

    def _restore_data(self, backup: Path) -> None:
        if (
            backup.resolve().parent != self.config.backup_dir.resolve()
            or not (backup / "data").is_dir()
        ):
            raise UpdateError("Invalid database recovery snapshot")
        for child in self.config.data_dir.iterdir():
            if child.name == "updates":
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        for source in (backup / "data").iterdir():
            target = self.config.data_dir / source.name
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
        sync_snapshot(self.config.data_dir)

    def recover(self) -> None:
        if not self.journal.exists():
            if (self.config.state_dir / "job.json").exists():
                job = self._job()
                if job.phase in ACTIVE_PHASES:
                    self._phase(
                        job,
                        "failed",
                        "Подготовка обновления прервана; работающая версия сохранена.",
                    )
            return
        state = private_json(self.journal)
        job = self._job()
        if state.get("job_id") != job.id:
            raise UpdateError("Recovery journal does not match the update job")
        if state.get("committed"):
            self._phase(job, "succeeded", "Обновление установлено и проверено.")
            self.journal.unlink()
            return
        self._phase(job, "recovering", "Восстанавливаем предыдущую версию.")
        old = Path(state["old_release"])
        backup = Path(state["backup"])
        self.control.stop()
        self._switch(old)
        if state.get("backup_ready"):
            self._restore_data(backup)
        self.control.start()
        if not self.control.healthy(str(state["old_version"])):
            raise UpdateError(
                "Previous service version could not be restored; the recovery snapshot is retained"
            )
        self._phase(
            job,
            "failed",
            "Предыдущая версия восстановлена.",
            "Новая версия не прошла проверку запуска.",
        )
        self.journal.unlink()

    def run(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.config.state_dir / "worker.lock").open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateError("Another updater already owns this installation") from exc
            if self.journal.exists():
                self.recover()
                return
            job = self._job()
            if job.phase != "queued" or not 0 <= time.time() - job.requested_at <= 600:
                if job.phase in ACTIVE_PHASES:
                    self._phase(job, "failed", "Запрос обновления истёк или был прерван.")
                raise UpdateError("Update request expired or was already processed")
            try:
                self._perform(job)
            except Exception as exc:
                if self.journal.exists():
                    self.recover()
                else:
                    detail = (
                        str(exc)
                        if isinstance(exc, UpdateError)
                        else "Не удалось подготовить обновление."
                    )
                    self._phase(
                        job,
                        "failed",
                        "Обновление не установлено; работающая версия сохранена.",
                        detail[:300],
                    )
                raise

    def _perform(self, job: UpdateJob) -> None:
        if not self.config.install_dir.is_symlink():
            raise UpdateError("Application release layout is not configured")
        old = self.config.install_dir.resolve()
        if old.parent != self.config.releases_dir.resolve():
            raise UpdateError("The current application is outside the release directory")
        old_version = installed_version(old)
        if version_tuple(job.version) <= version_tuple(old_version):
            raise UpdateError("Downgrades and same-version replacements are not allowed")
        if not router_ready(self.config.data_dir):
            raise UpdateError("Apply or discard the router draft before updating")
        self._phase(job, "downloading", "Получаем подписанный пакет из GitHub.")
        client = self.client or GitHubReleaseClient(self.config.public_key)
        manifest, raw, url = client.release(job.version)
        if hashlib.sha256(raw).hexdigest() != job.manifest_sha256:
            raise UpdateError("The signed release changed after the update check")
        archive = client.download(url, manifest.size)
        if len(archive) != manifest.size or hashlib.sha256(archive).hexdigest() != manifest.sha256:
            raise UpdateError("Update archive checksum verification failed")
        if shutil.disk_usage(self.config.releases_dir).free < MAX_EXTRACTED * 4:
            raise UpdateError("Not enough free space to stage and recover the release")
        package = self.config.state_dir / (job.id + ".tar.gz")
        descriptor = os.open(package, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(archive)
        del archive
        target = self.config.releases_dir / (
            "v" + manifest.version + "-" + manifest.commit[:12] + "-" + job.id[:8]
        )
        target.mkdir(mode=0o755)
        self._phase(job, "validating", "Проверяем состав и целостность пакета.")
        extract_package(package, target)
        metadata = private_json(target / "release.json")
        if metadata != {"version": manifest.version, "commit": manifest.commit}:
            raise UpdateError("Build metadata does not match the signed manifest")
        self._phase(job, "installing", "Готовим отдельное окружение новой версии.")
        self.installer(target, manifest)
        sync_snapshot(target)
        if not router_ready(self.config.data_dir):
            raise UpdateError("Router configuration changed during release preparation")
        self._phase(job, "backup", "Сохраняем конфигурацию и учётные записи.")
        # A journal exists before stopping the application, so ExecStopPost and boot recovery
        # can restore it even if this process is killed during backup or cutover.
        backup = self.config.backup_dir / job.id
        backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        journal = {
            "job_id": job.id,
            "old_release": str(old),
            "old_version": old_version,
            "backup": str(backup),
            "backup_ready": False,
            "committed": False,
        }
        atomic_json(self.journal, journal)
        self.control.stop()
        self._backup(backup)
        journal["backup_ready"] = True
        atomic_json(self.journal, journal)
        self._phase(job, "restarting", "Запускаем новую версию и проверяем состояние роутера.")
        self._switch(target)
        self.control.start()
        if not self.control.healthy(manifest.version):
            raise UpdateError("New service version failed its startup health check")
        journal["committed"] = True
        atomic_json(self.journal, journal)
        self._phase(job, "succeeded", "Обновление установлено и проверено.")
        self.journal.unlink()
        package.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenMikroRout signed-release maintenance worker")
    parser.add_argument("--config", type=Path, default=Path("/etc/openmikrorout-update.json"))
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--boot-recover", action="store_true")
    arguments = parser.parse_args()
    config = UpdateConfig.load(arguments.config)
    control: ServiceControl = (
        BootRecoveryControl(config) if arguments.boot_recover else SystemdControl(config)
    )
    worker = UpdateWorker(config, control)
    if arguments.recover or arguments.boot_recover:
        worker.recover()
    else:
        worker.run()


if __name__ == "__main__":
    main()
