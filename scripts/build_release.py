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
from pathlib import Path
from typing import BinaryIO, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "gadmin2151/OpenMikroRout"


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", args.version):
        raise SystemExit("Use a stable major.minor.patch version")
    if git("status", "--porcelain").strip():
        raise SystemExit("Commit all source changes before signing a release")
    if args.private_key.is_symlink() or args.private_key.stat().st_mode & 0o077:
        raise SystemExit("The signing key must be a private regular file (0600)")
    raw_key = args.private_key.read_bytes()
    key = (
        Ed25519PrivateKey.from_private_bytes(raw_key)
        if len(raw_key) == 32
        else serialization.load_pem_private_key(raw_key, password=None)
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("An Ed25519 signing key is required")
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
        "BRAND.md",
        "run.sh",
    )
    args.output.mkdir(parents=True, exist_ok=True)
    name = f"openmikrorout-{args.version}.tar.gz"
    archive_path = args.output / name
    with (
        archive_path.open("xb") as output,
        gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed,
        tarfile.open(fileobj=cast(BinaryIO, compressed), mode="w|") as package,
    ):
        with tarfile.open(fileobj=io.BytesIO(source), mode="r:") as original:
            for member in original:
                if not (member.isfile() or member.isdir()):
                    raise SystemExit("Only regular committed files may be packaged")
                stream = original.extractfile(member) if member.isfile() else None
                try:
                    package.addfile(member, stream)
                finally:
                    if stream:
                        stream.close()
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
    (args.output / "openmikrorout-manifest.json").write_bytes(raw)
    (args.output / "openmikrorout-manifest.sig").write_bytes(
        base64.b64encode(key.sign(raw)) + b"\n"
    )
    for path in args.output.iterdir():
        if path.is_file():
            os.chmod(path, 0o644)
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
