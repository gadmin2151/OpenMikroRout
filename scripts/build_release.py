"""Build and sign only committed application sources; private keys never enter the package."""

import argparse
import ast
import base64
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "gadmin2151/OpenMikroRout"
NDPI_COMMIT = "cd1d03a52f0c968f1835110d70f5da652171a5d5"
NDPI_TERMS_SHA256 = "1ec506620608c4707e79f5a1b254a03b6e81747f21b1bb4411417ff19fcb6bfa"


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def native_files(path: Path, commit: str) -> list[tuple[str, bytes, int]]:
    """Include only a bounded, source-bound companion built for this exact release."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise SystemExit("Invalid native companion bundle")
    files: dict[str, tuple[bytes, int]] = {}
    with tarfile.open(path, mode="r|*") as archive:
        total = 0
        for index, member in enumerate(archive, start=1):
            if index > 128:
                raise SystemExit("Too many native companion entries")
            name = member.name
            parts = PurePosixPath(name).parts
            if (
                not name.startswith("app/native/")
                or name.startswith("/")
                or ".." in parts
                or "\\" in name
                or len(name) > 240
                or str(PurePosixPath(name)) != name.rstrip("/")
                or not (member.isfile() or member.isdir())
            ):
                raise SystemExit("Unsafe native companion path")
            if member.isdir():
                continue
            relative = name.removeprefix("app/native/")
            if not (
                relative in {"bin/omr-app-supervisor", "manifest.json"}
                or re.fullmatch(r"lib/lib[A-Za-z0-9_+.-]+\.so(?:\.[0-9]+)*", relative)
                or re.fullmatch(r"licenses/[A-Za-z0-9_+.-]{1,120}", relative)
            ) or relative.endswith((".key", ".pem")):
                raise SystemExit("Unexpected native companion payload")
            total += member.size
            if (
                name in files
                or not 0 <= member.size <= 20 * 1024 * 1024
                or total > 96 * 1024 * 1024
            ):
                raise SystemExit("Invalid native companion file size or duplicate")
            stream = archive.extractfile(member)
            if stream is None:
                raise SystemExit("Missing native companion content")
            with stream:
                files[name] = (stream.read(), 0o755 if member.mode & 0o111 else 0o644)
    manifest_entry = files.get("app/native/manifest.json")
    if manifest_entry is None or len(manifest_entry[0]) > 65536:
        raise SystemExit("Missing bounded native manifest")
    try:
        manifest: dict[str, Any] = json.loads(manifest_entry[0])
    except (ValueError, TypeError) as exc:
        raise SystemExit("Invalid native manifest") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("format") != 1
        or manifest.get("purpose") != "OpenMikroRout native companion"
        or manifest.get("source_commit") != commit
        or manifest.get("platform") != "linux-amd64"
    ):
        raise SystemExit("Native companion does not match the committed release")
    if manifest.get("engine") != {
        "name": "ndpi",
        "version": "6.0-stable",
        "commit": NDPI_COMMIT,
        "license_profile": "explicit-ndpi-6-license-profile-required",
    }:
        raise SystemExit("Native companion does not use the licensed, pinned nDPI engine")
    hashes = manifest.get("files")
    if not isinstance(hashes, dict):
        raise SystemExit("Native manifest file hashes are missing")
    expected = {"app/native/" + name for name in hashes}
    if set(files) - {"app/native/manifest.json"} != expected:
        raise SystemExit("Native bundle does not match its file inventory")
    for relative, digest in hashes.items():
        payload, _ = files["app/native/" + relative]
        if not isinstance(digest, str) or hashlib.sha256(payload).hexdigest() != digest:
            raise SystemExit("Native companion hash mismatch")
    terms = files.get("app/native/licenses/ndpi-README-license-md")
    if terms is None or hashlib.sha256(terms[0]).hexdigest() != NDPI_TERMS_SHA256:
        raise SystemExit("The exact nDPI third-party license notice is missing")
    binary = files.get("app/native/bin/omr-app-supervisor")
    if binary is None or binary[1] != 0o755 or not binary[0].startswith(b"\x7fELF\x02\x01"):
        raise SystemExit("The Linux amd64 companion executable is missing")
    if len(binary[0]) < 20 or binary[0][18:20] != b"\x3e\x00":
        raise SystemExit("Native companion has an unsupported machine architecture")
    return [(name, payload, mode) for name, (payload, mode) in sorted(files.items())]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--native-bundle", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", args.version):
        raise SystemExit("Use a stable major.minor.patch version")
    if git("status", "--porcelain").strip():
        raise SystemExit("Commit all source changes before signing a release")
    if (
        args.private_key.is_symlink()
        or not args.private_key.is_file()
        or args.private_key.stat().st_mode & 0o077
    ):
        raise SystemExit("The signing key must be a private regular file (0600)")
    raw_key = args.private_key.read_bytes()
    key = (
        Ed25519PrivateKey.from_private_bytes(raw_key)
        if len(raw_key) == 32
        else serialization.load_pem_private_key(raw_key, password=None)
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("An Ed25519 signing key is required")
    private_material = (raw_key, key.private_bytes_raw())
    public = serialization.load_pem_public_key((ROOT / "deploy/update-signing.pub").read_bytes())
    if (
        not isinstance(public, Ed25519PublicKey)
        or key.public_key().public_bytes_raw() != public.public_bytes_raw()
    ):
        raise SystemExit("The signing key does not match the pinned public key")
    version_tree = ast.parse(git("show", "HEAD:app/version.py").decode())
    versions = [
        ast.literal_eval(node.value)
        for node in version_tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets)
    ]
    if versions != [args.version]:
        raise SystemExit("The release version does not match committed app/version.py")
    commit = git("rev-parse", "HEAD").decode().strip()
    companion = native_files(args.native_bundle, commit) if args.native_bundle else []
    source = git(
        "archive",
        "--format=tar",
        "HEAD",
        "--",
        "app",
        "deploy",
        "requirements.lock",
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "BRAND.md",
        "run.sh",
    )
    args.output.mkdir(parents=True, exist_ok=True)
    name = f"openmikrorout-{args.version}.tar.gz"
    archive_path = args.output / name
    manifest_path = args.output / "openmikrorout-manifest.json"
    signature_path = args.output / "openmikrorout-manifest.sig"
    for path in (archive_path, manifest_path, signature_path):
        if path.exists() or path.is_symlink():
            raise SystemExit(f"Release output already exists: {path.name}")
    with (
        archive_path.open("xb") as output,
        gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed,
        tarfile.open(fileobj=cast(BinaryIO, compressed), mode="w|") as package,
    ):
        os.fchmod(output.fileno(), 0o644)
        with tarfile.open(fileobj=io.BytesIO(source), mode="r:") as original:
            for member in original:
                # Rejected design studies are available in Git, but are not runtime assets.
                # Keep signed updates small enough for the existing bounded downloader.
                if member.name == "app/static/brand-options" or member.name.startswith(
                    "app/static/brand-options/"
                ):
                    continue
                if not (member.isfile() or member.isdir()):
                    raise SystemExit("Only regular committed files may be packaged")
                if member.name == "LICENSE":
                    # 0.10's stock updater only accepts app/deploy roots. Keep the
                    # new license accessible without requiring an updater bypass.
                    member.name = "deploy/LICENSE"
                stream = original.extractfile(member) if member.isfile() else None
                try:
                    if stream:
                        payload = stream.read()
                        if any(secret in payload for secret in private_material):
                            raise SystemExit("Private signing material must not enter a release")
                        package.addfile(member, io.BytesIO(payload))
                    else:
                        package.addfile(member)
                finally:
                    if stream:
                        stream.close()
        for native_name, payload, mode in companion:
            if any(secret in payload for secret in private_material):
                raise SystemExit("Private signing material must not enter a release")
            item = tarfile.TarInfo(native_name)
            item.size, item.mode, item.mtime = len(payload), mode, 0
            package.addfile(item, io.BytesIO(payload))
        metadata = (
            json.dumps(
                {"version": args.version, "commit": commit}, separators=(",", ":"), sort_keys=True
            ).encode()
            + b"\n"
        )
        item = tarfile.TarInfo("release.json")
        item.size, item.mode, item.mtime = len(metadata), 0o644, 0
        package.addfile(item, io.BytesIO(metadata))
    manifest = {
        "format": 1,
        "repository": REPOSITORY,
        "version": args.version,
        "commit": commit,
        "archive": name,
        "size": archive_path.stat().st_size,
        "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
    }
    raw = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    with manifest_path.open("xb") as manifest_output, signature_path.open("xb") as signature_output:
        manifest_output.write(raw)
        signature_output.write(base64.b64encode(key.sign(raw)) + b"\n")
        os.fchmod(manifest_output.fileno(), 0o644)
        os.fchmod(signature_output.fileno(), 0o644)
    print(
        json.dumps(
            {
                "version": args.version,
                "commit": commit,
                "archive": str(archive_path),
                "sha256": manifest["sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
