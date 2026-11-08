"""Explicit administrator consent for the separately licensed nDPI companion.

Only the local installer writes the root-owned receipt. Neither accepting this
notice nor selecting a profile grants a commercial license from ntop.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ENGINE_MAJOR = 6
ENGINE_VERSION = "6.0"
ENGINE_COMMIT = "cd1d03a52f0c968f1835110d70f5da652171a5d5"
TERMS_SHA256 = "1ec506620608c4707e79f5a1b254a03b6e81747f21b1bb4411417ff19fcb6bfa"
TERMS_URL = f"https://github.com/ntop/nDPI/blob/{ENGINE_COMMIT}/README.license.md"
DEFAULT_RECEIPT = Path("/etc/openmikrorout/ndpi-license.json")
PROFILES = frozenset({"not-for-profit", "commercial-license", "lgpl-only"})
NOTICE = (
    "OpenMikroRout uses the third-party nDPI 6.0 library. Its core is LGPLv3. "
    "Additional ntop components are free only where nDPI creates no direct or indirect "
    "revenue. Revenue-generating use of those components requires a commercial "
    "agreement with ntop. Selecting commercial-license confirms that you already "
    "hold that agreement; accepting this notice does not grant one. The lgpl-only "
    "profile excludes the additional components and has reduced detection coverage. "
    "Declining stops installation; an existing installation remains unchanged."
)


class LicenseError(ValueError):
    """Required administrator consent is absent, invalid, or stale."""


def license_terms() -> str:
    try:
        raw = Path(__file__).with_name("ndpi-license-6.0.txt").read_bytes()
    except OSError as exc:
        raise LicenseError("The bundled nDPI license terms are missing or unreadable") from exc
    if hashlib.sha256(raw).hexdigest() != TERMS_SHA256:
        raise LicenseError("The bundled nDPI license terms failed integrity verification")
    return raw.decode("utf-8")


def _open_directory(path: Path, *, create: bool = False) -> int:
    """Walk stable directory descriptors; every parent must be controlled by root."""
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise LicenseError("The license receipt path must not traverse parent directories")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in ("", *absolute.parts[1:]):
            if part:
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, mode=0o755, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise LicenseError("License receipt directories must be controlled by root")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _archive_path(path: Path, major: int | None = None, digest: str | None = None) -> Path:
    major = ENGINE_MAJOR if major is None else major
    digest = TERMS_SHA256 if digest is None else digest
    return path.parent / "license-acceptances" / f"ndpi-{major}-{digest}.json"


def _read_acceptance(path: Path, *, current_terms: bool = True) -> dict[str, Any]:
    descriptor: int | None = None
    directory: int | None = None
    try:
        directory = _open_directory(path.parent)
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > 8192
        ):
            raise LicenseError("The nDPI license receipt must be a root-owned 0600 regular file")
        raw = os.read(descriptor, 8193)
        if len(raw) > 8192:
            raise LicenseError("The nDPI license receipt exceeds its size limit")
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or type(value.get("schema")) is not int
            or value["schema"] != 1
            or value.get("accepted") is not True
            or type(value.get("engine_major")) is not int
            or not 1 <= value["engine_major"] <= 65535
            or not isinstance(value.get("terms_sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", value["terms_sha256"])
            or current_terms
            and (value["engine_major"] != ENGINE_MAJOR or value["terms_sha256"] != TERMS_SHA256)
            or value.get("profile") not in PROFILES
            or not isinstance(value.get("accepted_at"), str)
            or len(value["accepted_at"]) > 128
        ):
            raise LicenseError("The nDPI license receipt does not cover this engine and its terms")
        accepted_at = datetime.fromisoformat(value["accepted_at"])
        if accepted_at.tzinfo is None:
            raise LicenseError("The nDPI license receipt has an invalid acceptance time")
        return value
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, LicenseError):
            raise
        raise LicenseError(
            "nDPI license acceptance is required. Run deploy/accept-ndpi-license.sh "
            "as the server administrator; declining cancels installation."
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def load_acceptance(path: Path = DEFAULT_RECEIPT) -> dict[str, Any]:
    """Prefer the current receipt, then the exact archived terms for this release."""
    try:
        return _read_acceptance(path)
    except LicenseError as current_error:
        try:
            return _read_acceptance(_archive_path(path))
        except LicenseError:
            raise current_error from None


def acceptance_status() -> dict[str, Any]:
    result: dict[str, Any] = {
        "required": True,
        "engine": "nDPI",
        "version": ENGINE_VERSION,
        "terms_sha256": TERMS_SHA256,
        "terms_url": TERMS_URL,
        "notice": NOTICE,
        "accepted": False,
        "profile": "",
    }
    try:
        receipt = load_acceptance()
        result.update(accepted=True, profile=receipt["profile"])
    except LicenseError:
        pass  # The status describes missing consent; install/runtime gates still reject it.
    return result


def installation_requires_acceptance(root: Path) -> bool:
    native = root / "app/native"
    return (native / "manifest.json").exists() or (native / "bin/omr-app-supervisor").exists()


def require_installation_acceptance(root: Path) -> None:
    if installation_requires_acceptance(root):
        license_terms()
        load_acceptance()


def _write_receipt(path: Path, value: dict[str, Any], *, replace: bool = True) -> None:
    directory = _open_directory(path.parent, create=True)
    temporary: str | None = None
    try:
        try:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if info is not None:
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise LicenseError("Existing nDPI receipts must be private root-owned files")
            if not replace:
                return
        temporary = ".ndpi-receipt-" + secrets.token_hex(16)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "w") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        if replace:
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        else:
            # Link then unlink publishes a complete file without replacing prior consent.
            # A concurrent explicit acceptance owns an already-published version.
            with suppress(FileExistsError):
                os.link(
                    temporary,
                    path.name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            os.unlink(temporary, dir_fd=directory)
        temporary = None
        os.fsync(directory)
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def record_acceptance(profile: str, path: Path = DEFAULT_RECEIPT) -> None:
    if os.geteuid() != 0:
        raise LicenseError("Only the local server administrator can accept nDPI terms")
    if profile not in PROFILES:
        raise LicenseError("Unknown nDPI intended-use profile")
    license_terms()
    value = {
        "schema": 1,
        "accepted": True,
        "engine_major": ENGINE_MAJOR,
        "engine_version": ENGINE_VERSION,
        "terms_sha256": TERMS_SHA256,
        "profile": profile,
        "accepted_at": datetime.now(UTC).isoformat(),
    }
    directory: int | None = None
    lock: int | None = None
    try:
        directory = _open_directory(path.parent, create=True)
        lock = os.open(
            ".ndpi-license.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise LicenseError("The nDPI acceptance lock must be a private root-owned file")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LicenseError("Another local nDPI acceptance is in progress; retry later") from exc
        try:
            previous = _read_acceptance(path, current_terms=False)
        except LicenseError:
            previous = None
        if previous:
            _write_receipt(
                _archive_path(path, previous["engine_major"], previous["terms_sha256"]),
                previous,
                replace=False,
            )
        _write_receipt(_archive_path(path), value)
        _write_receipt(path, value)
    except OSError as exc:
        raise LicenseError("Could not durably record nDPI license acceptance") from exc
    finally:
        if lock is not None:
            os.close(lock)
        if directory is not None:
            os.close(directory)


def main() -> None:
    parser = argparse.ArgumentParser(description=NOTICE)
    parser.add_argument("--check", action="store_true", help="Verify existing acceptance only")
    parser.add_argument("--status", action="store_true", help="Print public acceptance status")
    parser.add_argument("--accept-profile", choices=sorted(PROFILES))
    parser.add_argument(
        "--accept-terms-sha256", help="Explicit acceptance of the exact terms digest"
    )
    args = parser.parse_args()
    try:
        if args.check:
            load_acceptance()
            print("nDPI license acceptance verified.")
            return
        if args.status:
            print(json.dumps(acceptance_status(), sort_keys=True))
            return
        print(NOTICE + "\n\n" + TERMS_URL + "\n\n" + license_terms())
        if args.accept_profile or args.accept_terms_sha256:
            if not args.accept_profile or args.accept_terms_sha256 != TERMS_SHA256:
                raise LicenseError(
                    "Both the intended-use profile and exact terms digest are required"
                )
            profile = args.accept_profile
        else:
            if not sys.stdin.isatty():
                raise LicenseError("No interactive acceptance. Installation cancelled")
            print(
                "\n1: no direct/indirect revenue; 2: commercial ntop agreement held; "
                "3: LGPL core only; anything else: decline."
            )
            choice = input("Intended use [decline]: ").strip()
            profile = {"1": "not-for-profit", "2": "commercial-license", "3": "lgpl-only"}.get(
                choice
            )
            if (
                profile is None
                or input("Type ACCEPT to accept these exact terms: ").strip() != "ACCEPT"
            ):
                raise LicenseError("nDPI terms declined. Installation cancelled")
        record_acceptance(profile)
        print(f"nDPI terms accepted for profile {profile}. No router rules were changed.")
    except LicenseError as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
