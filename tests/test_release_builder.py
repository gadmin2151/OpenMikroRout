import base64
import hashlib
import io
import json
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_release import NDPI_COMMIT, NDPI_TERMS_SHA256, native_files

ARTIFACTS = (
    "openmikrorout-0.3.0.tar.gz",
    "openmikrorout-manifest.json",
    "openmikrorout-manifest.sig",
)


def companion_bundle(
    path: Path,
    *,
    commit: str = "a" * 40,
    corrupted: bool = False,
    engine_commit: str = NDPI_COMMIT,
) -> None:
    binary = bytearray(64)
    binary[:6] = b"\x7fELF\x02\x01"
    binary[18:20] = b"\x3e\x00"
    terms = (Path(__file__).resolve().parents[1] / "app/ndpi-license-6.0.txt").read_bytes()
    manifest = {
        "format": 1,
        "purpose": "OpenMikroRout native companion",
        "platform": "linux-amd64",
        "source_commit": commit,
        "engine": {
            "name": "ndpi",
            "version": "6.0-stable",
            "commit": engine_commit,
            "license_profile": "explicit-ndpi-6-license-profile-required",
        },
        "files": {
            "bin/omr-app-supervisor": hashlib.sha256(binary).hexdigest(),
            "licenses/ndpi-README-license-md": hashlib.sha256(terms).hexdigest(),
        },
    }
    if corrupted:
        binary[-1] = 1
    with tarfile.open(path, "w:gz") as archive:
        for name, body, mode in (
            ("bin/omr-app-supervisor", bytes(binary), 0o755),
            ("manifest.json", json.dumps(manifest).encode(), 0o644),
            ("licenses/ndpi-README-license-md", terms, 0o644),
        ):
            item = tarfile.TarInfo("app/native/" + name)
            item.size, item.mode = len(body), mode
            archive.addfile(item, io.BytesIO(body))


def test_native_bundle_binds_binary_hashes_to_exact_release_source(tmp_path: Path) -> None:
    archive = tmp_path / "native.tar.gz"
    companion_bundle(archive)
    entries = native_files(archive, "a" * 40)
    assert {name for name, _, _ in entries} == {
        "app/native/bin/omr-app-supervisor",
        "app/native/manifest.json",
        "app/native/licenses/ndpi-README-license-md",
    }
    with pytest.raises(SystemExit, match="committed release"):
        native_files(archive, "b" * 40)


def test_native_bundle_rejects_modified_binary_and_unsafe_paths(tmp_path: Path) -> None:
    archive = tmp_path / "corrupted.tar.gz"
    companion_bundle(archive, corrupted=True)
    with pytest.raises(SystemExit, match="hash mismatch"):
        native_files(archive, "a" * 40)
    for name in ("app/native/../../evil", "/app/native/bin/evil", "deploy/evil"):
        with tarfile.open(archive, "w:gz") as package:
            item = tarfile.TarInfo(name)
            item.size = 1
            package.addfile(item, io.BytesIO(b"x"))
        with pytest.raises(SystemExit, match="Unsafe"):
            native_files(archive, "a" * 40)


def test_native_bundle_rejects_symlinks(tmp_path: Path) -> None:
    archive = tmp_path / "linked.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        item = tarfile.TarInfo("app/native/bin/omr-app-supervisor")
        item.type = tarfile.SYMTYPE
        item.linkname = "/bin/sh"
        package.addfile(item)
    with pytest.raises(SystemExit, match="Unsafe"):
        native_files(archive, "a" * 40)


def test_native_bundle_rejects_unreviewed_engine_and_unexpected_payload(tmp_path: Path) -> None:
    from app.third_party_license import ENGINE_COMMIT, TERMS_SHA256

    assert NDPI_COMMIT == ENGINE_COMMIT and NDPI_TERMS_SHA256 == TERMS_SHA256
    archive = tmp_path / "native.tar.gz"
    companion_bundle(archive, engine_commit="b" * 40)
    with pytest.raises(SystemExit, match="pinned nDPI"):
        native_files(archive, "a" * 40)
    for name in ("app/native/signing.key", "app/native/extra.py", "app/native/lib//libfoo.so.1"):
        with tarfile.open(archive, "w:gz") as package:
            item = tarfile.TarInfo(name)
            item.size = 1
            package.addfile(item, io.BytesIO(b"x"))
        with pytest.raises(SystemExit, match="Unexpected|Unsafe"):
            native_files(archive, "a" * 40)


@pytest.fixture
def release_repository(tmp_path: Path) -> tuple[Path, Path, Ed25519PrivateKey]:
    repo = tmp_path / "repository"
    repo.mkdir()
    for directory in ("app", "deploy", "scripts", "output"):
        (repo / directory).mkdir()
    (repo / ".gitignore").write_text("output/\n")
    (repo / "app/version.py").write_text('VERSION = "0.3.0"\n')
    for filename in (
        "requirements.lock",
        "pyproject.toml",
        "README.md",
        "BRAND.md",
        "run.sh",
        "LICENSE",
    ):
        (repo / filename).write_text("# disposable test fixture\n")
    shutil.copyfile(
        Path(__file__).resolve().parents[1] / "scripts/build_release.py",
        repo / "scripts/build_release.py",
    )
    key = Ed25519PrivateKey.generate()
    (repo / "deploy/update-signing.pub").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    private_key = repo / "output/signing.key"
    private_key.write_bytes(key.private_bytes_raw())
    private_key.chmod(0o600)
    for arguments in (
        ("init", "--quiet"),
        ("add", "."),
        (
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Disposable release fixture",
        ),
    ):
        subprocess.run(["git", "-C", str(repo), *arguments], check=True, capture_output=True)
    return repo, private_key, key


def run_builder(
    repo: Path, private_key: Path, *extra_arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(repo / "scripts/build_release.py"),
            "--version",
            "0.3.0",
            "--private-key",
            str(private_key),
            "--output",
            str(repo / "output"),
            *extra_arguments,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_native_inventory_does_not_replace_the_release_archive_name(
    release_repository: tuple[Path, Path, Ed25519PrivateKey],
) -> None:
    repo, private_key, _ = release_repository
    commit = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    native = repo / "output/native.tar.gz"
    companion_bundle(native, commit=commit)
    result = run_builder(repo, private_key, "--native-bundle", str(native))
    assert result.returncode == 0, result.stderr
    manifest = json.loads((repo / "output/openmikrorout-manifest.json").read_text())
    assert manifest["archive"] == ARTIFACTS[0]
    with tarfile.open(repo / "output" / manifest["archive"]) as archive:
        assert "app/native/bin/omr-app-supervisor" in archive.getnames()
        assert "app/native/manifest.json" in archive.getnames()


def test_builder_rejects_accidentally_committed_signing_material(
    release_repository: tuple[Path, Path, Ed25519PrivateKey],
) -> None:
    repo, private_key, key = release_repository
    (repo / "app/accidental-secret.txt").write_bytes(b"prefix" + key.private_bytes_raw())
    subprocess.run(["git", "-C", str(repo), "add", "app/accidental-secret.txt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Accidental secret fixture",
        ],
        check=True,
        capture_output=True,
    )
    result = run_builder(repo, private_key)
    assert result.returncode != 0
    assert "Private signing material" in result.stderr
    assert not (repo / "output/openmikrorout-manifest.sig").exists()
    assert key.private_bytes_raw().hex() not in result.stdout + result.stderr


def test_builder_preserves_colocated_private_files_and_signs_valid_assets(
    release_repository: tuple[Path, Path, Ed25519PrivateKey],
) -> None:
    repo, private_key, key = release_repository
    output = repo / "output"
    sentinel = output / "unrelated.secret"
    sentinel.write_bytes(b"disposable private sentinel")
    sentinel.chmod(0o600)
    original_key = private_key.read_bytes()

    result = run_builder(repo, private_key)

    assert result.returncode == 0, result.stderr
    assert private_key.read_bytes() == original_key
    assert sentinel.read_bytes() == b"disposable private sentinel"
    assert stat.S_IMODE(private_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o600
    assert all(stat.S_IMODE((output / name).stat().st_mode) == 0o644 for name in ARTIFACTS)
    raw_manifest = (output / ARTIFACTS[1]).read_bytes()
    key.public_key().verify(base64.b64decode((output / ARTIFACTS[2]).read_bytes()), raw_manifest)
    manifest = json.loads(raw_manifest)
    archive_bytes = (output / ARTIFACTS[0]).read_bytes()
    assert manifest["sha256"] == hashlib.sha256(archive_bytes).hexdigest()
    assert manifest["size"] == len(archive_bytes)
    assert manifest["version"] == "0.3.0"
    with tarfile.open(output / ARTIFACTS[0]) as archive:
        assert "app/version.py" in archive.getnames()
        assert "deploy/LICENSE" in archive.getnames()
        assert "LICENSE" not in archive.getnames()
        assert not any(name.startswith("output/") for name in archive.getnames())


@pytest.mark.parametrize("name", ARTIFACTS)
@pytest.mark.parametrize("existing_kind", ["file", "symlink", "broken_symlink", "directory"])
def test_builder_refuses_all_existing_outputs_without_clobbering(
    release_repository: tuple[Path, Path, Ed25519PrivateKey], name: str, existing_kind: str
) -> None:
    repo, private_key, _ = release_repository
    output = repo / "output"
    collision = output / name
    if existing_kind == "file":
        collision.write_bytes(b"existing release artifact")
        collision.chmod(0o600)
    elif existing_kind == "directory":
        collision.mkdir()
    else:
        collision.symlink_to(private_key if existing_kind == "symlink" else output / "missing")
    before = {path.name for path in output.iterdir()}
    key_bytes = private_key.read_bytes()

    result = run_builder(repo, private_key)

    assert result.returncode != 0
    assert "Release output already exists" in result.stderr
    assert {path.name for path in output.iterdir()} == before
    assert private_key.read_bytes() == key_bytes
    assert stat.S_IMODE(private_key.stat().st_mode) == 0o600
    if existing_kind == "file":
        assert collision.read_bytes() == b"existing release artifact"
        assert stat.S_IMODE(collision.stat().st_mode) == 0o600
    elif existing_kind == "directory":
        assert collision.is_dir()
    else:
        assert collision.is_symlink()
