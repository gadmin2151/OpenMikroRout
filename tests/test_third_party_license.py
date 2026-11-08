import fcntl
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from app.third_party_license import (
    ENGINE_MAJOR,
    TERMS_SHA256,
    LicenseError,
    license_terms,
    load_acceptance,
    main,
    record_acceptance,
    require_installation_acceptance,
)

REAL_FSTAT = os.fstat
REAL_STAT = os.stat


def root_info(value: os.stat_result) -> os.stat_result:
    values = list(value)
    values[4] = 0
    if stat.S_ISDIR(value.st_mode):
        values[0] = int(values[0]) & ~0o022
    return os.stat_result(values)


@pytest.fixture(autouse=True)
def root_filesystem(tmp_path: Path) -> Iterator[None]:
    """Fixtures cannot chown root; retain real file types, modes, links and lengths."""
    with (
        patch("app.third_party_license.os.fstat", side_effect=lambda fd: root_info(REAL_FSTAT(fd))),
        patch(
            "app.third_party_license.os.stat",
            side_effect=lambda *args, **kwargs: root_info(REAL_STAT(*args, **kwargs)),
        ),
    ):
        yield


def receipt(tmp_path: Path, **changes: object) -> Path:
    path = tmp_path / "ndpi-license.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "accepted": True,
                "engine_major": ENGINE_MAJOR,
                "terms_sha256": TERMS_SHA256,
                "profile": "not-for-profit",
                "accepted_at": "2026-11-08T00:00:00+00:00",
                **changes,
            }
        )
    )
    path.chmod(0o600)
    return path


def test_exact_bundled_upstream_terms() -> None:
    assert "direct" in license_terms() and "indirect" in license_terms()


@pytest.mark.parametrize("profile", ["not-for-profit", "commercial-license", "lgpl-only"])
def test_receipt_selects_only_explicit_intended_use(tmp_path: Path, profile: str) -> None:
    path = receipt(tmp_path, profile=profile)
    assert load_acceptance(path)["profile"] == profile


@pytest.mark.parametrize(
    "changes",
    [
        {"accepted": False},
        {"engine_major": 5},
        {"schema": True},
        {"terms_sha256": "0" * 64},
        {"profile": "commercial"},
        {"profile": []},
        {"accepted_at": "yesterday"},
        {"accepted_at": "2026-11-08"},
    ],
)
def test_reject_declined_stale_and_invalid_receipts(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    path = receipt(tmp_path, **changes)
    with pytest.raises(LicenseError):
        load_acceptance(path)


def test_receipt_symlink_and_insecure_mode_rejected(tmp_path: Path) -> None:
    path = receipt(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(LicenseError):
        load_acceptance(link)
    path.chmod(0o644)
    with pytest.raises(LicenseError):
        load_acceptance(path)


def test_receipt_wrong_owner_and_oversize_rejected(tmp_path: Path) -> None:
    path = receipt(tmp_path)

    def wrong_file_owner(descriptor: int) -> os.stat_result:
        info = root_info(REAL_FSTAT(descriptor))
        if stat.S_ISREG(info.st_mode):
            values = list(info)
            values[4] = 1000
            return os.stat_result(values)
        return info

    with (
        patch("app.third_party_license.os.fstat", side_effect=wrong_file_owner),
        pytest.raises(LicenseError),
    ):
        load_acceptance(path)
    path.write_bytes(b"x" * 8193)
    with pytest.raises(LicenseError):
        load_acceptance(path)


def test_old_updater_import_validation_stops_before_cutover(tmp_path: Path) -> None:
    require_installation_acceptance(tmp_path)  # Source/demo without native payload.
    (tmp_path / "app/native").mkdir(parents=True)
    (tmp_path / "app/native/manifest.json").write_text("{}")
    with (
        patch("app.third_party_license.load_acceptance", side_effect=LicenseError("declined")),
        pytest.raises(LicenseError, match="declined"),
    ):
        require_installation_acceptance(tmp_path)


def test_unattended_install_never_implies_acceptance() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "app.third_party_license"],
        input="",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "Installation cancelled" in result.stderr
    assert "direct or indirect" in result.stdout


def test_non_root_cannot_record_consent(tmp_path: Path) -> None:
    with (
        patch("app.third_party_license.os.geteuid", return_value=1000),
        pytest.raises(LicenseError, match="administrator"),
    ):
        record_acceptance("not-for-profit", tmp_path / "receipt")
    assert not list(tmp_path.iterdir())


def test_atomic_consent_has_private_mode(tmp_path: Path) -> None:
    path = tmp_path / "receipt"
    with patch("app.third_party_license.os.geteuid", return_value=0):
        record_acceptance("lgpl-only", path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["profile"] == "lgpl-only"
    archive = tmp_path / "license-acceptances" / f"ndpi-{ENGINE_MAJOR}-{TERMS_SHA256}.json"
    assert archive.read_bytes() == path.read_bytes()
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert {item.name for item in tmp_path.iterdir()} == {
        "receipt",
        "license-acceptances",
        ".ndpi-license.lock",
    }


def test_rollback_reads_exact_older_terms_archive_when_canonical_is_future(tmp_path: Path) -> None:
    path = receipt(tmp_path)
    archive_dir = tmp_path / "license-acceptances"
    archive_dir.mkdir()
    archived = archive_dir / f"ndpi-{ENGINE_MAJOR}-{TERMS_SHA256}.json"
    archived.write_bytes(path.read_bytes())
    archived.chmod(0o600)
    receipt(tmp_path, engine_major=7, terms_sha256="7" * 64, profile="lgpl-only")
    value = load_acceptance(path)
    assert value["engine_major"] == 6
    assert value["terms_sha256"] == TERMS_SHA256
    assert value["profile"] == "not-for-profit"


def test_current_matching_canonical_has_priority_over_archive(tmp_path: Path) -> None:
    path = receipt(tmp_path)
    archive_dir = tmp_path / "license-acceptances"
    archive_dir.mkdir()
    archived = archive_dir / f"ndpi-{ENGINE_MAJOR}-{TERMS_SHA256}.json"
    document = json.loads(path.read_text())
    document["profile"] = "lgpl-only"
    archived.write_text(json.dumps(document))
    archived.chmod(0o600)
    assert load_acceptance(path)["profile"] == "not-for-profit"


def test_custom_receipt_never_falls_back_to_real_server_receipts(tmp_path: Path) -> None:
    attempted: list[Path] = []

    def absent(path: Path, **kwargs: object) -> dict[str, object]:
        attempted.append(path)
        raise LicenseError("not accepted")

    path = tmp_path / "custom.json"
    with (
        patch("app.third_party_license._read_acceptance", side_effect=absent),
        pytest.raises(LicenseError),
    ):
        load_acceptance(path)
    assert attempted == [
        path,
        tmp_path / "license-acceptances" / f"ndpi-{ENGINE_MAJOR}-{TERMS_SHA256}.json",
    ]


def test_profile_change_replaces_only_current_terms_archive(tmp_path: Path) -> None:
    path = tmp_path / "receipt"
    with patch("app.third_party_license.os.geteuid", return_value=0):
        record_acceptance("not-for-profit", path)
        other = tmp_path / "license-acceptances" / f"ndpi-7-{'7' * 64}.json"
        other.write_text("retained future receipt fixture")
        other.chmod(0o600)
        before = other.read_bytes()
        record_acceptance("lgpl-only", path)
    archive = tmp_path / "license-acceptances" / f"ndpi-{ENGINE_MAJOR}-{TERMS_SHA256}.json"
    assert json.loads(path.read_text())["profile"] == "lgpl-only"
    assert archive.read_bytes() == path.read_bytes()
    assert other.read_bytes() == before
    assert path.stat().st_nlink == archive.stat().st_nlink == 1


def test_future_acceptance_archives_legacy_canonical_before_overwriting(tmp_path: Path) -> None:
    path = receipt(tmp_path)
    old_bytes = path.read_bytes()
    with (
        patch("app.third_party_license.os.geteuid", return_value=0),
        patch("app.third_party_license.ENGINE_MAJOR", 7),
        patch("app.third_party_license.ENGINE_VERSION", "7.0"),
        patch("app.third_party_license.TERMS_SHA256", "7" * 64),
        patch("app.third_party_license.license_terms", return_value="future fixture terms"),
    ):
        record_acceptance("lgpl-only", path)
    assert json.loads(path.read_text())["engine_major"] == 7
    old_archive = tmp_path / "license-acceptances" / f"ndpi-6-{TERMS_SHA256}.json"
    assert json.loads(old_archive.read_bytes()) == json.loads(old_bytes)
    # Back in the old release, archived consent permits a safe restart/rollback.
    assert load_acceptance(path)["engine_major"] == 6


def test_interactive_decline_keeps_canonical_and_archived_consent_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "receipt"
    with patch("app.third_party_license.os.geteuid", return_value=0):
        record_acceptance("not-for-profit", path)
    before = {item.relative_to(tmp_path): item.read_bytes() for item in tmp_path.rglob("*.json")}
    with (
        patch("app.third_party_license.sys.argv", ["accept-ndpi-license"]),
        patch("app.third_party_license.sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="decline"),
        patch("app.third_party_license.record_acceptance") as record,
        pytest.raises(SystemExit) as stopped,
    ):
        main()
    assert stopped.value.code == 1
    record.assert_not_called()
    after = {item.relative_to(tmp_path): item.read_bytes() for item in tmp_path.rglob("*.json")}
    assert after == before


@pytest.mark.parametrize("bad_attribute", ["owner", "permissions"])
def test_untrusted_parent_blocks_read_and_write_without_mutation(
    tmp_path: Path, bad_attribute: str
) -> None:
    path = receipt(tmp_path)
    before = path.read_bytes()
    parent_inode = tmp_path.stat().st_ino

    def untrusted_parent(descriptor: int) -> os.stat_result:
        info = root_info(REAL_FSTAT(descriptor))
        if info.st_ino == parent_inode and stat.S_ISDIR(info.st_mode):
            values = list(info)
            if bad_attribute == "owner":
                values[4] = 1000
            else:
                values[0] = int(values[0]) | 0o002
            return os.stat_result(values)
        return info

    with (
        patch("app.third_party_license.os.fstat", side_effect=untrusted_parent),
        patch("app.third_party_license.os.geteuid", return_value=0),
    ):
        with pytest.raises(LicenseError):
            load_acceptance(path)
        with pytest.raises(LicenseError):
            record_acceptance("lgpl-only", path)
    assert path.read_bytes() == before
    assert not (tmp_path / "license-acceptances").exists()


def test_symlinked_ancestor_and_archive_directory_are_never_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    path = receipt(target)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(LicenseError):
        load_acceptance(linked / path.name)
    (tmp_path / "license-acceptances").symlink_to(target, target_is_directory=True)
    with (
        patch("app.third_party_license.os.geteuid", return_value=0),
        pytest.raises(LicenseError),
    ):
        record_acceptance("lgpl-only", tmp_path / "new-receipt")
    assert not (tmp_path / "new-receipt").exists()
    assert sorted(item.name for item in target.iterdir()) == ["ndpi-license.json"]


def test_revocation_requires_removing_both_matching_receipts(tmp_path: Path) -> None:
    path = tmp_path / "receipt"
    with patch("app.third_party_license.os.geteuid", return_value=0):
        record_acceptance("lgpl-only", path)
    path.unlink()
    assert load_acceptance(path)["profile"] == "lgpl-only"
    archived = tmp_path / "license-acceptances" / f"ndpi-{ENGINE_MAJOR}-{TERMS_SHA256}.json"
    archived.unlink()
    with pytest.raises(LicenseError):
        load_acceptance(path)


def test_concurrent_acceptance_cannot_mix_archive_and_canonical_profiles(tmp_path: Path) -> None:
    path = receipt(tmp_path)
    before = path.read_bytes()
    lock_path = tmp_path / ".ndpi-license.lock"
    descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (
            patch("app.third_party_license.os.geteuid", return_value=0),
            pytest.raises(LicenseError, match="in progress"),
        ):
            record_acceptance("lgpl-only", path)
    finally:
        os.close(descriptor)
    assert path.read_bytes() == before
    assert not (tmp_path / "license-acceptances").exists()
