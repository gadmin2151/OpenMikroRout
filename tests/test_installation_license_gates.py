"""Exercise installer license/inventory gates without touching host services."""

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


def native_fixture(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    target = tmp_path / "release"
    native = target / "app/native"
    (native / "bin").mkdir(parents=True)
    binary = native / "bin/omr-app-supervisor"
    binary.write_bytes(b"disposable native inventory fixture")
    binary.chmod(0o755)
    manifest: dict[str, object] = {
        "format": 1,
        "purpose": "OpenMikroRout native companion",
        "platform": "linux-amd64",
        "source_commit": COMMIT,
        "files": {"bin/omr-app-supervisor": hashlib.sha256(binary.read_bytes()).hexdigest()},
    }
    (target / "release.json").write_text(json.dumps({"commit": COMMIT}))
    return target, manifest


def validate_inventory(
    target: Path, manifest: dict[str, object]
) -> subprocess.CompletedProcess[str]:
    (target / "app/native/manifest.json").write_text(json.dumps(manifest))
    installer = (ROOT / "deploy/install-applications.sh").read_text()
    program = installer.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    program = program.replace("Path('/opt/openmikrorout')", f"Path({str(target)!r})")
    # -O is intentional: security checks must continue to work with asserts disabled.
    return subprocess.run(
        [sys.executable, "-O", "-c", program],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_native_inventory_accepts_exact_release_under_optimized_python(tmp_path: Path) -> None:
    target, manifest = native_fixture(tmp_path)
    result = validate_inventory(target, manifest)
    assert result.returncode == 0, result.stderr
    assert "inventory verified" in result.stdout


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("format", True),
        ("purpose", "unrelated artifact"),
        ("platform", "linux-arm64"),
        ("source_commit", "b" * 40),
        ("files", {}),
    ],
)
def test_optimized_installer_rejects_wrong_release_metadata(
    tmp_path: Path, field: str, value: object
) -> None:
    target, manifest = native_fixture(tmp_path)
    manifest[field] = value
    result = validate_inventory(target, manifest)
    assert result.returncode != 0
    assert "validation failed" in result.stderr
    assert "inventory verified" not in result.stdout


def test_optimized_installer_rejects_modified_executable(tmp_path: Path) -> None:
    target, manifest = native_fixture(tmp_path)
    (target / "app/native/bin/omr-app-supervisor").write_bytes(b"modified fixture")
    result = validate_inventory(target, manifest)
    assert result.returncode != 0 and "hash" in result.stderr


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/tmp/outside",
        "lib/../outside",
        "lib//alias.so",
        "lib/./alias.so",
        "secret.key",
    ],
)
def test_optimized_installer_rejects_unsafe_inventory_paths(tmp_path: Path, name: str) -> None:
    target, manifest = native_fixture(tmp_path)
    files = manifest["files"]
    assert isinstance(files, dict)
    files[name] = "f" * 64
    result = validate_inventory(target, manifest)
    assert result.returncode != 0 and "unsafe native inventory" in result.stderr


def test_optimized_installer_rejects_symlinked_parent_directory(tmp_path: Path) -> None:
    target, manifest = native_fixture(tmp_path)
    external = tmp_path / "outside"
    external.mkdir()
    payload = b"external native fixture"
    (external / "libfixture.so").write_bytes(payload)
    (target / "app/native/lib").symlink_to(external, target_is_directory=True)
    files = manifest["files"]
    assert isinstance(files, dict)
    files["lib/libfixture.so"] = hashlib.sha256(payload).hexdigest()
    result = validate_inventory(target, manifest)
    assert result.returncode != 0 and "symbolic links" in result.stderr


def test_bootstrap_copies_complete_standalone_license_module(tmp_path: Path) -> None:
    installer = (ROOT / "deploy/install-updater.sh").read_text()
    match = re.search(r"for module in ([^;]+); do\n", installer)
    assert match is not None
    maintenance = tmp_path / "maintenance"
    package = maintenance / "app"
    package.mkdir(parents=True)
    # Use the actual bootstrap inventory, not a manually duplicated list of modules.
    for name in shlex.split(match[1]):
        shutil.copyfile(ROOT / "app" / name, package / name)
    command = [
        sys.executable,
        "-c",
        "import hashlib; from app.third_party_license import license_terms, TERMS_SHA256; "
        "assert hashlib.sha256(license_terms().encode()).hexdigest() == TERMS_SHA256; "
        "print('standalone terms verified')",
    ]
    environment = {**os.environ, "PYTHONPATH": "", "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        command,
        cwd=maintenance,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "standalone terms verified"
    (package / "ndpi-license-6.0.txt").unlink()
    missing = subprocess.run(
        command,
        cwd=maintenance,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert missing.returncode != 0
    assert "standalone terms verified" not in missing.stdout


def test_run_script_decline_exits_before_dependencies_or_existing_service(tmp_path: Path) -> None:
    target = tmp_path / "application"
    (target / "app/native").mkdir(parents=True)
    (target / "app/native/manifest.json").write_text("{}")
    shutil.copyfile(ROOT / "run.sh", target / "run.sh")
    tools = tmp_path / "tools"
    tools.mkdir()
    fake_python = tools / "python3"
    fake_python.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$GATE_CALLS"\nexit 1\n')
    fake_python.chmod(0o755)
    (target / ".venv/bin").mkdir(parents=True)
    service_python = target / ".venv/bin/python"
    service_python.write_text('#!/bin/sh\necho unexpected > "$SERVICE_STARTED"\n')
    service_python.chmod(0o755)
    sentinel = target / "existing-service-state"
    sentinel.write_text("existing installation remains unchanged")
    calls = tmp_path / "gate-calls"
    started = tmp_path / "service-started"
    result = subprocess.run(
        ["sh", str(target / "run.sh")],
        env={
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "GATE_CALLS": str(calls),
            "SERVICE_STARTED": str(started),
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert calls.read_text().splitlines() == [
        "-m app.third_party_license --check",
        "-m app.third_party_license",
    ]
    assert not started.exists()
    assert sentinel.read_text() == "existing installation remains unchanged"
