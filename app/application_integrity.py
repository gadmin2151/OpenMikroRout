"""Verify the complete native inventory before loading its executable or DSOs."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


def native_inventory(binary: Path, *, owner: int = 0) -> tuple[str, list[Path]]:
    root = binary.parent.parent.resolve()
    manifest_path = root / "manifest.json"
    root_info = root.stat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != owner
        or root_info.st_mode & 0o022
    ):
        raise ValueError("Native inventory directory is not owned and private from writes")
    descriptor = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner
            or info.st_mode & 0o022
            or info.st_size > 65536
        ):
            raise ValueError("Native inventory must be an owned bounded regular file")
        raw = os.read(descriptor, 65537)
    finally:
        os.close(descriptor)
    if len(raw) > 65536:
        raise ValueError("Native inventory exceeds its size limit")
    try:
        manifest: Any = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid native inventory") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("format") != 1
        or manifest.get("purpose") != "OpenMikroRout native companion"
        or manifest.get("platform") != "linux-amd64"
    ):
        raise ValueError("Unsupported native inventory format")
    files = manifest.get("files")
    if (
        not isinstance(files, dict)
        or not 1 <= len(files) <= 256
        or "bin/omr-app-supervisor" not in files
    ):
        raise ValueError("Invalid native inventory file list")
    verified: list[Path] = []
    total = 0
    for name, expected in files.items():
        relative = PurePosixPath(name)
        if (
            not isinstance(name, str)
            or relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or "\\" in name
            or len(name) > 240
            or not isinstance(expected, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected)
        ):
            raise ValueError("Unsafe native inventory path or digest")
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or any(
            parent.is_symlink()
            for parent in path.parents
            if parent != root and parent.is_relative_to(root)
        ):
            raise ValueError("Native inventory cannot follow symbolic links")
        for parent in path.parents:
            if parent == root:
                break
            directory = parent.stat()
            if (
                not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != owner
                or directory.st_mode & 0o022
            ):
                raise ValueError("Native inventory parent directory is writable by another user")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            total += info.st_size
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != owner
                or info.st_mode & 0o022
                or info.st_size > 20 * 1024 * 1024
                or total > 64 * 1024 * 1024
            ):
                raise ValueError("Native inventory file ownership or bounds are invalid")
            digest = hashlib.sha256()
            consumed = 0
            while True:
                part = os.read(descriptor, 65536)
                if not part:
                    break
                consumed += len(part)
                if consumed > info.st_size or consumed > 20 * 1024 * 1024:
                    raise ValueError("Native inventory file changed or exceeds its bound")
                digest.update(part)
        finally:
            os.close(descriptor)
        if digest.hexdigest() != expected:
            raise ValueError("Native inventory hash mismatch")
        verified.append(path)
    if binary.resolve() != root / "bin/omr-app-supervisor":
        raise ValueError("The configured companion is outside its native inventory")
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest(), verified
