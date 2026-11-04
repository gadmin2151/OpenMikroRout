import base64
import hashlib
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

ARTIFACTS = (
    "openmikrorout-0.3.0.tar.gz",
    "openmikrorout-manifest.json",
    "openmikrorout-manifest.sig",
)


@pytest.fixture
def release_repository(tmp_path: Path) -> tuple[Path, Path, Ed25519PrivateKey]:
    repo = tmp_path / "repository"
    repo.mkdir()
    for directory in ("app", "deploy", "scripts", "output"):
        (repo / directory).mkdir()
    (repo / ".gitignore").write_text("output/\n")
    (repo / "app/version.py").write_text('VERSION = "0.3.0"\n')
    for filename in ("requirements.lock", "pyproject.toml", "README.md", "BRAND.md", "run.sh"):
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


def run_builder(repo: Path, private_key: Path) -> subprocess.CompletedProcess[str]:
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
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )


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
