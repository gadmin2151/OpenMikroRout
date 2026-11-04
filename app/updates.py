"""Pinned-repository, signed-release discovery and the web-to-systemd update queue."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.totp import CredentialProof
from app.version import VERSION

REPOSITORY = "gadmin2151/OpenMikroRout"
API_ROOT = "https://api.github.com/repos/" + REPOSITORY
MANIFEST_ASSET = "openmikrorout-manifest.json"
SIGNATURE_ASSET = "openmikrorout-manifest.sig"
MAX_ARCHIVE = 32 * 1024 * 1024
ACTIVE_PHASES = {
    "queued",
    "downloading",
    "validating",
    "installing",
    "backup",
    "restarting",
    "recovering",
}
TRUSTED_DOWNLOAD_HOSTS = {
    "api.github.com",
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}


class UpdateError(Exception):
    def __init__(self, message: str, status: int = 503) -> None:
        super().__init__(message)
        self.status = status


def version_tuple(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", value):
        raise ValueError("Use a stable major.minor.patch version")
    parts = value.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


class ReleaseManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal[1] = 1
    repository: Literal["gadmin2151/OpenMikroRout"] = "gadmin2151/OpenMikroRout"
    version: str
    commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    archive: str = Field(pattern=r"^openmikrorout-[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\.tar\.gz$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(gt=0, le=MAX_ARCHIVE, strict=True)

    @field_validator("version")
    @classmethod
    def stable(cls, value: str) -> str:
        version_tuple(value)
        return value


class UpdateApply(CredentialProof):
    check_id: str = Field(pattern=r"^[a-f0-9]{32}$")


class ReleaseOffer(BaseModel):
    version: str
    commit: str
    available: bool
    check_id: str
    checked_at: float


class UpdateJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    version: str
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    requested_at: float
    updated_at: float
    phase: Literal[
        "queued",
        "downloading",
        "validating",
        "installing",
        "backup",
        "restarting",
        "recovering",
        "succeeded",
        "failed",
    ]
    message: str = ""
    error: str = ""


class UpdateStatus(BaseModel):
    enabled: bool
    repository: str = REPOSITORY
    current_version: str = VERSION
    current_commit: str = ""
    latest: ReleaseOffer | None = None
    job: UpdateJob | None = None
    error: str = ""


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
            temporary = stream.name
            os.chmod(temporary, 0o600)
            json.dump(value, stream, separators=(",", ":"), sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def private_json(path: Path, limit: int = 65536) -> dict[str, Any]:
    if path.is_symlink() or path.stat().st_size > limit:
        raise UpdateError("Invalid update state file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise UpdateError("Update state exceeds its size limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise UpdateError("Invalid update state")
    return value


@dataclass(frozen=True)
class UpdateConfig:
    public_key: Path
    state_dir: Path
    data_dir: Path
    install_dir: Path = Path("/opt/openmikrorout")
    releases_dir: Path = Path("/opt/openmikrorout-releases")
    backup_dir: Path = Path("/var/backups/openmikrorout")
    service: str = "openmikrorout.service"
    health_url: str = "http://127.0.0.1:8088/api/health"

    @classmethod
    def load(cls, path: Path) -> UpdateConfig:
        if path.is_symlink() or path.stat().st_mode & 0o022 or path.stat().st_uid != os.geteuid():
            raise UpdateError("Updater configuration must be owned by the service administrator")
        raw = private_json(path)
        allowed = {
            "public_key",
            "state_dir",
            "data_dir",
            "install_dir",
            "releases_dir",
            "backup_dir",
            "service",
            "health_url",
        }
        if set(raw) - allowed:
            raise UpdateError("Unknown updater configuration fields")
        try:
            config = cls(
                public_key=Path(str(raw["public_key"])),
                state_dir=Path(str(raw["state_dir"])),
                data_dir=Path(str(raw["data_dir"])),
                install_dir=Path(str(raw.get("install_dir", "/opt/openmikrorout"))),
                releases_dir=Path(str(raw.get("releases_dir", "/opt/openmikrorout-releases"))),
                backup_dir=Path(str(raw.get("backup_dir", "/var/backups/openmikrorout"))),
                service=str(raw.get("service", "openmikrorout.service")),
                health_url=str(raw.get("health_url", "http://127.0.0.1:8088/api/health")),
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise UpdateError("Invalid updater configuration") from exc
        if (
            config.service != "openmikrorout.service"
            or config.health_url != "http://127.0.0.1:8088/api/health"
        ):
            raise UpdateError("Only the OpenMikroRout service can be updated")
        if config.install_dir != Path("/opt/openmikrorout") or config.releases_dir != Path(
            "/opt/openmikrorout-releases"
        ):
            raise UpdateError("Unexpected application installation paths")
        if (
            config.data_dir != Path("/var/lib/openmikrorout")
            or config.state_dir != config.data_dir / "updates"
        ):
            raise UpdateError("Unexpected application data paths")
        if config.backup_dir != Path("/var/backups/openmikrorout") or config.public_key != Path(
            "/etc/openmikrorout-update.pub"
        ):
            raise UpdateError("Unexpected backup or trust-key paths")
        return config


def valid_download_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname in TRUSTED_DOWNLOAD_HOSTS
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
        )
    except ValueError:
        return False


class TrustedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        if not valid_download_url(newurl):
            raise UpdateError("GitHub download redirected to an untrusted destination")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GitHubReleaseClient:
    def __init__(self, public_key: Path) -> None:
        try:
            key = serialization.load_pem_public_key(public_key.read_bytes())
        except (OSError, ValueError) as exc:
            raise UpdateError("Update verification key is unavailable") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise UpdateError("An Ed25519 update verification key is required")
        self.key = key
        # Do not inherit proxy credentials or arbitrary proxy destinations in the root worker.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), TrustedRedirect()
        )

    def download(self, url: str, limit: int) -> bytes:
        if not valid_download_url(url):
            raise UpdateError("Untrusted update download URL")
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "OpenMikroRout-Updater/1",
                "Accept": "application/vnd.github+json"
                if url.startswith(API_ROOT)
                else "application/octet-stream",
            },
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                deadline = time.monotonic() + 45
                output = bytearray()
                while len(output) <= limit:
                    if time.monotonic() >= deadline:
                        raise UpdateError("Update download exceeded its time limit")
                    chunk = response.read1(min(65536, limit + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                content = bytes(output)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise UpdateError("GitHub is unavailable or the download timed out") from exc
        if len(content) > limit:
            raise UpdateError("Update download exceeds its size limit")
        return content

    def release(self, version: str | None = None) -> tuple[ReleaseManifest, bytes, str]:
        endpoint = API_ROOT + ("/releases/tags/v" + version if version else "/releases/latest")
        if version:
            version_tuple(version)
        try:
            metadata = json.loads(self.download(endpoint, 262144))
            if metadata.get("draft") or metadata.get("prerelease"):
                raise UpdateError("Only published stable releases are supported")
            assets = metadata["assets"]
            if not isinstance(assets, list) or len(assets) > 32:
                raise ValueError("Invalid release assets")
            urls = {str(asset["name"]): str(asset["browser_download_url"]) for asset in assets}
            for name in (MANIFEST_ASSET, SIGNATURE_ASSET):
                if name not in urls or not urls[name].startswith(
                    "https://github.com/" + REPOSITORY + "/releases/download/"
                ):
                    raise UpdateError("The release does not contain a signed update package")
            raw = self.download(urls[MANIFEST_ASSET], 8192)
            signature = base64.b64decode(
                self.download(urls[SIGNATURE_ASSET], 256).strip(), validate=True
            )
            self.key.verify(signature, raw)
            manifest = ReleaseManifest.model_validate_json(raw)
            if (
                manifest.archive != f"openmikrorout-{manifest.version}.tar.gz"
                or metadata.get("tag_name") != "v" + manifest.version
            ):
                raise UpdateError("Release tag and signed manifest disagree")
            if version and manifest.version != version:
                raise UpdateError("Unexpected update version")
            archive_url = urls[manifest.archive]
            if not archive_url.startswith(
                "https://github.com/" + REPOSITORY + "/releases/download/v" + manifest.version + "/"
            ):
                raise UpdateError("Update archive does not belong to the pinned release")
            return manifest, raw, archive_url
        except InvalidSignature as exc:
            raise UpdateError("Update signature verification failed") from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise UpdateError("Invalid signed GitHub release metadata") from exc


class UpdateService:
    def __init__(
        self,
        enabled: bool,
        config_path: Path,
        *,
        clock: Callable[[], float] = time.time,
        runner: Callable[[], None] | None = None,
    ) -> None:
        self.clock, self.runner = clock, runner or self._launch
        self.lock = threading.Lock()
        self.config: UpdateConfig | None = None
        self.error = ""
        self.latest: ReleaseOffer | None = None
        self.manifest: ReleaseManifest | None = None
        self.raw_manifest: bytes | None = None
        if enabled:
            try:
                self.config = UpdateConfig.load(config_path)
                GitHubReleaseClient(self.config.public_key)
            except (OSError, ValueError, TypeError, UpdateError):
                self.error = "Механизм обновления не настроен или ключ проверки недоступен."
        else:
            self.error = "Обновления доступны после настройки Linux-сервиса."

    @staticmethod
    def _launch() -> None:
        binary = shutil.which("systemctl")
        if not binary:
            raise UpdateError("The systemd updater is unavailable")
        try:
            result = subprocess.run(
                [binary, "start", "--no-block", "openmikrorout-update.service"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UpdateError("Could not start the updater service") from exc
        if result.returncode:
            raise UpdateError("Could not start the updater service")

    def job(self) -> UpdateJob | None:
        if not self.config or not (self.config.state_dir / "job.json").exists():
            return None
        try:
            return UpdateJob.model_validate(private_json(self.config.state_dir / "job.json"))
        except (OSError, ValueError, UpdateError) as exc:
            raise UpdateError(
                "Cannot read update status; administrator intervention is required"
            ) from exc

    def active(self) -> bool:
        if not self.config:
            return False
        try:
            job = self.job()
            return bool(job and job.phase in ACTIVE_PHASES)
        except UpdateError:
            # Fail closed when the maintenance lock cannot be read.
            return True

    def status(self) -> UpdateStatus:
        return UpdateStatus(
            enabled=self.config is not None, latest=self.latest, job=self.job(), error=self.error
        )

    def check(self) -> UpdateStatus:
        if not self.config:
            raise UpdateError(self.error)
        with self.lock:
            if self.latest and self.clock() - self.latest.checked_at < 60:
                return self.status()
            manifest, raw, _ = GitHubReleaseClient(self.config.public_key).release()
            self.manifest, self.raw_manifest = manifest, raw
            self.latest = ReleaseOffer(
                version=manifest.version,
                commit=manifest.commit,
                available=version_tuple(manifest.version) > version_tuple(VERSION),
                check_id=secrets.token_hex(16),
                checked_at=self.clock(),
            )
            return self.status()

    def queue(self, check_id: str) -> UpdateJob:
        if not self.config:
            raise UpdateError(self.error)
        with self.lock:
            if self.active():
                raise UpdateError("An update is already in progress", 409)
            if (
                not self.latest
                or not self.raw_manifest
                or not self.manifest
                or not hmac.compare_digest(self.latest.check_id, check_id)
                or self.clock() - self.latest.checked_at > 600
                or not self.latest.available
            ):
                raise UpdateError("Check for a newer signed release before updating", 409)
            job = UpdateJob(
                id=secrets.token_hex(16),
                version=self.manifest.version,
                manifest_sha256=hashlib.sha256(self.raw_manifest).hexdigest(),
                requested_at=self.clock(),
                updated_at=self.clock(),
                phase="queued",
                message="Обновление поставлено в очередь.",
            )
            atomic_json(self.config.state_dir / "job.json", job.model_dump())
            try:
                self.runner()
            except UpdateError:
                job.phase, job.message = "failed", "Не удалось запустить службу обновления."
                atomic_json(self.config.state_dir / "job.json", job.model_dump())
                raise
            return job
