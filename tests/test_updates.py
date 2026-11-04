import base64
import hashlib
import io
import json
import os
import sqlite3
import tarfile
import time
from configparser import ConfigParser
from graphlib import TopologicalSorter
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.main import Settings, create_app
from app.models import Configuration
from app.storage import Store
from app.update_worker import (
    UpdateWorker,
    extract_package,
    installed_version,
    sync_snapshot,
    validate_requirements,
)
from app.updates import (
    API_ROOT,
    MANIFEST_ASSET,
    REPOSITORY,
    SIGNATURE_ASSET,
    GitHubReleaseClient,
    ReleaseManifest,
    ReleaseOffer,
    UpdateConfig,
    UpdateError,
    UpdateJob,
    UpdateService,
    atomic_json,
    private_json,
    valid_download_url,
)

PASSWORD = "test-only-update-administrator-password"
COMMIT = "a" * 40
HEADERS = {"X-NAT-Request": "1"}


def test_early_recovery_dependency_graph_has_no_network_boot_cycle() -> None:
    deploy = Path(__file__).resolve().parents[1] / "deploy"
    recovery = "openmikrorout-update-recover.service"
    firewall = "openmikrorout-firewall.service"
    application = "openmikrorout.service"
    # PVE's cloud-init-network precedes sysinit. A normal service's implicit
    # After=basic.target would therefore make recovery-before-networking cyclic.
    graph: dict[str, set[str]] = {
        "basic.target": {"sysinit.target"},
        "sysinit.target": {"cloud-init-network.service"},
        "cloud-init-network.service": {"networking.service"},
        "networking.service": {firewall, "network-pre.target"},
        "network-online.target": {"networking.service"},
    }
    dropin = ConfigParser(interpolation=None, strict=False)
    dropin.read(deploy / "openmikrorout-update-recovery.conf")
    assert recovery in dropin["Unit"]["Requires"].split()
    for name in (recovery, firewall, application):
        unit = ConfigParser(interpolation=None, strict=False)
        unit.read(deploy / name)
        dependencies = graph.setdefault(name, set())
        dependencies.update(unit["Unit"].get("After", "").split())
        if unit["Unit"].get("DefaultDependencies", "yes") != "no":
            dependencies.update({"sysinit.target", "basic.target"})
        if name in (firewall, application):
            dependencies.update(dropin["Unit"].get("After", "").split())
        for successor in unit["Unit"].get("Before", "").split():
            graph.setdefault(successor, set()).add(name)
    order = list(TopologicalSorter(graph).static_order())
    assert (
        order.index(recovery)
        < order.index(firewall)
        < order.index("networking.service")
        < order.index(application)
    )


def archive_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


def release() -> tuple[ReleaseManifest, bytes, bytes]:
    files = {
        "app/main.py": b"# signed code\n",
        "app/version.py": b'VERSION="0.4.0"\n',
        "app/update_worker.py": b"# signed worker\n",
        "requirements.lock": b"example==1.0\n",
        "release.json": json.dumps({"version": "0.4.0", "commit": COMMIT}).encode(),
    }
    archive = archive_bytes(files)
    manifest = ReleaseManifest(
        version="0.4.0",
        commit=COMMIT,
        archive="openmikrorout-0.4.0.tar.gz",
        sha256=hashlib.sha256(archive).hexdigest(),
        size=len(archive),
    )
    return manifest, manifest.model_dump_json().encode(), archive


class Source:
    def __init__(self) -> None:
        self.manifest, self.raw, self.archive = release()

    def release(self, version: str | None = None) -> tuple[ReleaseManifest, bytes, str]:
        return (
            self.manifest,
            self.raw,
            "https://github.com/gadmin2151/OpenMikroRout/releases/download/v0.4.0/package",
        )

    def download(self, url: str, limit: int) -> bytes:
        return self.archive


class Control:
    def __init__(self, config: UpdateConfig, *, fail_new: bool = False) -> None:
        self.config, self.fail_new = config, fail_new
        self.calls: list[str] = []

    def stop(self) -> None:
        self.calls.append("stop")

    def start(self) -> None:
        version = installed_version(self.config.install_dir)
        self.calls.append("start:" + version)
        if version == "0.4.0":
            with sqlite3.connect(self.config.data_dir / "auth.sqlite3") as db:
                db.execute("INSERT INTO test VALUES ('new-migration')")
            (self.config.data_dir / "new-migration-file").write_text("new")

    def healthy(self, expected: str) -> bool:
        self.calls.append("health:" + expected)
        return not (expected == "0.4.0" and self.fail_new)


def installation(tmp_path: Path) -> tuple[UpdateConfig, Source]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    data, releases = tmp_path / "data", tmp_path / "releases"
    data.mkdir()
    releases.mkdir()
    Store(data / "linux.sqlite3", Configuration())
    with sqlite3.connect(data / "auth.sqlite3") as db:
        db.execute("CREATE TABLE test (value TEXT)")
        db.execute("INSERT INTO test VALUES ('original-user')")
    (data / "totp.key").write_bytes(b"k" * 32)
    (data / "totp.key").chmod(0o600)
    old = releases / "old"
    old.mkdir()
    (old / "release.json").write_text(json.dumps({"version": "0.3.0", "commit": "b" * 40}))
    current = tmp_path / "current"
    current.symlink_to(old, target_is_directory=True)
    config = UpdateConfig(
        public_key=tmp_path / "public",
        state_dir=data / "updates",
        data_dir=data,
        install_dir=current,
        releases_dir=releases,
        backup_dir=tmp_path / "backups",
    )
    source = Source()
    job = UpdateJob(
        id="c" * 32,
        version="0.4.0",
        manifest_sha256=hashlib.sha256(source.raw).hexdigest(),
        requested_at=time.time(),
        updated_at=time.time(),
        phase="queued",
    )
    atomic_json(config.state_dir / "job.json", job.model_dump())
    return config, source


def test_signed_release_is_required_and_metadata_is_bound(tmp_path: Path) -> None:
    signing = Ed25519PrivateKey.generate()
    public = tmp_path / "public"
    public.write_bytes(
        signing.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    source = Source()
    prefix = "https://github.com/" + REPOSITORY + "/releases/download/v0.4.0/"
    metadata = {
        "tag_name": "v0.4.0",
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": name, "browser_download_url": prefix + name}
            for name in [MANIFEST_ASSET, SIGNATURE_ASSET, source.manifest.archive]
        ],
    }
    values = {
        API_ROOT + "/releases/latest": json.dumps(metadata).encode(),
        prefix + MANIFEST_ASSET: source.raw,
        prefix + SIGNATURE_ASSET: base64.b64encode(signing.sign(source.raw)),
    }
    client = GitHubReleaseClient(public)
    with patch.object(client, "download", side_effect=lambda url, limit: values[url]):
        assert client.release()[0] == source.manifest
        values[prefix + MANIFEST_ASSET] = source.raw.replace(b"0.4.0", b"0.5.0")
        with pytest.raises(UpdateError, match="signature"):
            client.release()


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/x",
        "file:///etc/passwd",
        "https://127.0.0.1/x",
        "https://github.com.evil.test/x",
        "https://user:pass@github.com/x",
        "https://github.com:444/x",
        "https://example.com/",
        "https://[github.com/",
        "https://github.com:not-a-port/",
    ],
)
def test_download_origin_restrictions(url: str) -> None:
    assert not valid_download_url(url)


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd",
        "/tmp/outside",
        "app/../../outside",
        ".venv/bin/python",
        "app\\..\\outside",
    ],
)
def test_archive_path_traversal_is_rejected(tmp_path: Path, name: str) -> None:
    package = tmp_path / "test.tar.gz"
    package.write_bytes(archive_bytes({name: b"malicious"}))
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(UpdateError):
        extract_package(package, target)
    assert not (tmp_path / "outside").exists()


def test_archive_symlink_is_rejected(tmp_path: Path) -> None:
    package = tmp_path / "test.tar.gz"
    with tarfile.open(package, "w:gz") as archive:
        item = tarfile.TarInfo("app/link")
        item.type = tarfile.SYMTYPE
        item.linkname = "/etc"
        archive.addfile(item)
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(UpdateError, match="Unsafe"):
        extract_package(package, target)


@pytest.mark.parametrize(
    "line",
    [
        "--index-url https://evil.test",
        "package @ https://evil.test/a.whl",
        "-e .",
        "package>=1.0",
        "git+https://evil.test/repo",
        "package==1.0 --global-option=run",
    ],
)
def test_dependency_command_injection_is_rejected(tmp_path: Path, line: str) -> None:
    path = tmp_path / "requirements.lock"
    path.write_text(line)
    with pytest.raises(UpdateError):
        validate_requirements(path)


def test_successful_update_preserves_users_keys_and_configuration(tmp_path: Path) -> None:
    config, source = installation(tmp_path)
    control = Control(config)
    before = (config.data_dir / "linux.sqlite3").read_bytes()
    worker = UpdateWorker(config, control, client=source, installer=lambda path, manifest: None)
    worker.run()
    assert installed_version(config.install_dir) == "0.4.0"
    assert private_json(config.state_dir / "job.json")["phase"] == "succeeded"
    assert not worker.journal.exists()
    assert (config.data_dir / "totp.key").read_bytes() == b"k" * 32
    assert (config.data_dir / "linux.sqlite3").read_bytes() == before
    assert (config.backup_dir / ("c" * 32) / "data/auth.sqlite3").exists()
    assert control.calls == ["stop", "start:0.4.0", "health:0.4.0"]


def test_staged_release_sync_failure_keeps_running_version(tmp_path: Path) -> None:
    config, source = installation(tmp_path)
    control = Control(config)
    worker = UpdateWorker(config, control, client=source, installer=lambda path, manifest: None)
    original_sync = os.fsync

    def fail_release_sync(descriptor: int) -> None:
        for target in config.releases_dir.glob("v*/requirements.lock"):
            if os.fstat(descriptor).st_ino == target.stat().st_ino:
                raise OSError("injected staged release sync failure")
        original_sync(descriptor)

    with (
        patch("app.update_worker.os.fsync", side_effect=fail_release_sync),
        pytest.raises(OSError, match="injected staged release sync failure"),
    ):
        worker.run()
    assert not control.calls
    assert installed_version(config.install_dir) == "0.3.0"
    assert not worker.journal.exists()
    assert not config.backup_dir.exists()
    assert private_json(config.state_dir / "job.json")["phase"] == "failed"


def test_release_sync_does_not_follow_virtualenv_symlinks(tmp_path: Path) -> None:
    target, external = tmp_path / "release", tmp_path / "external"
    target.mkdir()
    external.mkdir()
    (external / "python").write_bytes(b"outside release")
    (target / "python").symlink_to(external / "python")
    (target / "lib").symlink_to(external, target_is_directory=True)
    (target / "missing").symlink_to(external / "missing")
    (target / "cycle").symlink_to(target, target_is_directory=True)
    forbidden = {external.stat().st_ino, (external / "python").stat().st_ino}
    original_sync = os.fsync

    def reject_external_sync(descriptor: int) -> None:
        assert os.fstat(descriptor).st_ino not in forbidden
        original_sync(descriptor)

    with patch("app.update_worker.os.fsync", side_effect=reject_external_sync):
        sync_snapshot(target)


def test_failed_health_rolls_back_code_and_database_migration(tmp_path: Path) -> None:
    config, source = installation(tmp_path)
    control = Control(config, fail_new=True)
    worker = UpdateWorker(config, control, client=source, installer=lambda path, manifest: None)
    with pytest.raises(UpdateError, match="health check"):
        worker.run()
    assert installed_version(config.install_dir) == "0.3.0"
    assert private_json(config.state_dir / "job.json")["phase"] == "failed"
    with sqlite3.connect(config.data_dir / "auth.sqlite3") as db:
        assert db.execute("SELECT value FROM test").fetchall() == [("original-user",)]
    assert not (config.data_dir / "new-migration-file").exists()
    assert not worker.journal.exists()
    assert "start:0.3.0" in control.calls


@pytest.mark.parametrize("failure_target", ["data/totp.key", "."])
def test_snapshot_sync_failure_keeps_old_code_and_original_data(
    tmp_path: Path, failure_target: str
) -> None:
    config, source = installation(tmp_path)
    control = Control(config)
    worker = UpdateWorker(config, control, client=source, installer=lambda path, manifest: None)
    backup = config.backup_dir / ("c" * 32)
    original_sync = os.fsync
    ready_at_failure: list[bool] = []

    def fail_snapshot_sync(descriptor: int) -> None:
        target = backup / failure_target
        if target.exists() and os.fstat(descriptor).st_ino == target.stat().st_ino:
            ready_at_failure.append(private_json(worker.journal)["backup_ready"])
            # An incomplete snapshot must never replace the authoritative data.
            (backup / "data/totp.key").write_bytes(b"incomplete snapshot")
            raise OSError("injected snapshot sync failure")
        original_sync(descriptor)

    with (
        patch("app.update_worker.os.fsync", side_effect=fail_snapshot_sync),
        patch.object(worker, "_switch", wraps=worker._switch) as switch,
        pytest.raises(OSError, match="injected snapshot sync failure"),
    ):
        worker.run()
    assert ready_at_failure == [False]
    assert switch.call_args_list == [((config.releases_dir / "old",), {})]
    assert installed_version(config.install_dir) == "0.3.0"
    assert (config.data_dir / "totp.key").read_bytes() == b"k" * 32
    with sqlite3.connect(config.data_dir / "auth.sqlite3") as db:
        assert db.execute("SELECT value FROM test").fetchall() == [("original-user",)]
    assert not (config.data_dir / "new-migration-file").exists()
    assert private_json(config.state_dir / "job.json")["phase"] == "failed"
    assert not worker.journal.exists()
    assert "start:0.4.0" not in control.calls


def test_tampered_package_never_stops_the_running_service(tmp_path: Path) -> None:
    config, source = installation(tmp_path)
    source.archive += b"tamper"
    control = Control(config)
    with pytest.raises(UpdateError, match="checksum"):
        UpdateWorker(config, control, client=source, installer=lambda path, manifest: None).run()
    assert not control.calls and installed_version(config.install_dir) == "0.3.0"


def test_restore_sync_failure_retains_recovery_journal_and_snapshot(tmp_path: Path) -> None:
    config, source = installation(tmp_path)
    control = Control(config, fail_new=True)
    worker = UpdateWorker(config, control, client=source, installer=lambda path, manifest: None)
    original_sync = os.fsync

    def fail_restored_key_sync(descriptor: int) -> None:
        target = config.data_dir / "totp.key"
        if target.exists() and os.fstat(descriptor).st_ino == target.stat().st_ino:
            raise OSError("injected restore sync failure")
        original_sync(descriptor)

    with (
        patch("app.update_worker.os.fsync", side_effect=fail_restored_key_sync),
        pytest.raises(OSError, match="injected restore sync failure"),
    ):
        worker.run()
    assert worker.journal.exists()
    assert private_json(worker.journal)["backup_ready"] is True
    assert (config.backup_dir / ("c" * 32) / "data/totp.key").read_bytes() == b"k" * 32
    assert "start:0.3.0" not in control.calls
    worker.recover()
    assert installed_version(config.install_dir) == "0.3.0"
    assert not worker.journal.exists()
    assert control.calls[-2:] == ["start:0.3.0", "health:0.3.0"]


def test_crash_before_backup_recovers_without_replacing_data(tmp_path: Path) -> None:
    config, source = installation(tmp_path)
    control = Control(config)
    journal = {
        "job_id": "c" * 32,
        "old_release": str(config.install_dir.resolve()),
        "old_version": "0.3.0",
        "backup": str(config.backup_dir / ("c" * 32)),
        "backup_ready": False,
        "committed": False,
    }
    worker = UpdateWorker(config, control, client=source)
    atomic_json(worker.journal, journal)
    worker.recover()
    assert installed_version(config.install_dir) == "0.3.0" and not worker.journal.exists()
    with sqlite3.connect(config.data_dir / "auth.sqlite3") as db:
        assert db.execute("SELECT value FROM test").fetchall() == [("original-user",)]


def test_update_queue_is_single_use_and_requires_a_fresh_verified_offer(tmp_path: Path) -> None:
    config, source = installation(tmp_path)
    (config.state_dir / "job.json").unlink()
    launched = []
    service = UpdateService(False, tmp_path / "none", runner=lambda: launched.append(True))
    service.config = config
    service.manifest, service.raw_manifest = source.manifest, source.raw
    service.latest = ReleaseOffer(
        version="0.4.0", commit=COMMIT, available=True, check_id="d" * 32, checked_at=time.time()
    )
    with pytest.raises(UpdateError):
        service.queue("e" * 32)
    job = service.queue("d" * 32)
    assert job.phase == "queued" and launched == [True]
    with pytest.raises(UpdateError):
        service.queue("d" * 32)


def test_update_api_roles_reauthentication_and_maintenance_lock(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "app", auth_enabled=True, password=PASSWORD, read_password=PASSWORD
    )
    app = create_app(settings)
    config, source = installation(tmp_path / "installation")
    (config.state_dir / "job.json").unlink()
    updates = app.state.updates
    updates.config = config
    updates.runner = lambda: None
    updates.manifest, updates.raw_manifest = source.manifest, source.raw
    updates.latest = ReleaseOffer(
        version="0.4.0", commit=COMMIT, available=True, check_id="d" * 32, checked_at=time.time()
    )
    with TestClient(app) as client:
        client.post(
            "/api/login", headers=HEADERS, json={"username": "viewer", "password": PASSWORD}
        )
        assert client.get("/api/updates").status_code == 403
        assert client.post("/api/updates/apply", headers=HEADERS, json={}).status_code == 403
        client.post("/api/login", headers=HEADERS, json={"username": "admin", "password": PASSWORD})
        assert (
            client.post(
                "/api/updates/apply",
                headers=HEADERS,
                json={"check_id": "d" * 32, "password": "wrong"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/updates/apply",
                headers=HEADERS,
                json={"check_id": "d" * 32, "password": PASSWORD, "url": "file:///etc/passwd"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/updates/apply",
                headers=HEADERS,
                json={"check_id": "d" * 32, "password": PASSWORD},
            ).status_code
            == 202
        )
        assert client.put("/api/config", headers=HEADERS, json={}).status_code == 423
        assert (
            client.post(
                "/api/me/totp/setup", headers=HEADERS, json={"password": PASSWORD}
            ).status_code
            == 423
        )
        assert client.get("/api/updates").status_code == 200
