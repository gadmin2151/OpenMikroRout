"""Assemble a relocatable native companion without symlinks or undeclared payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--ndpi-source", type=Path, required=True)
parser.add_argument("--ndpi-prefix", type=Path, required=True)
parser.add_argument("--source-commit", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if not re.fullmatch(r"[a-f0-9]{40}", args.source_commit):
    raise SystemExit("An exact committed OpenMikroRout source revision is required")
if args.output.exists():
    raise SystemExit("Output must be a new directory")
args.output.mkdir(parents=True)
for name in ("bin", "lib", "licenses"):
    (args.output / name).mkdir()
shutil.copyfile(args.binary, args.output / "bin/omr-app-supervisor")
(args.output / "bin/omr-app-supervisor").chmod(0o755)
capabilities = json.loads(
    subprocess.check_output([str(args.binary.resolve()), "capabilities", "--json"], text=True)
)
if capabilities.get("engine", {}).get(
    "commit"
) != "cd1d03a52f0c968f1835110d70f5da652171a5d5" or not str(
    capabilities.get("engine", {}).get("version", "")
).startswith("6.0"):
    raise SystemExit("The actual engine does not match the pinned current stable profile")
if capabilities.get("test_instrumentation") is not False:
    raise SystemExit("Instrumented/emulation test binaries may not enter a release")
listing = subprocess.check_output(["ldd", str(args.binary)], text=True)
packages = set()
for line in listing.splitlines():
    match = re.search(r"^\s*(\S+) => (/\S+)", line)
    if not match:
        continue
    soname, filename = match.groups()
    # The platform's glibc/loader are not replaced. Other dependency SONAME aliases
    # are materialized as regular files so the stock updater needs no symlinks.
    if soname in {"libc.so.6", "libm.so.6", "libpthread.so.0", "librt.so.1", "libdl.so.2"}:
        continue
    shutil.copyfile(Path(filename).resolve(), args.output / "lib" / soname)
    if Path(filename).resolve().is_relative_to(args.ndpi_prefix.resolve()):
        continue
    try:
        owner = subprocess.check_output(
            ["dpkg-query", "-S", str(Path(filename).resolve())],
            text=True,
            stderr=subprocess.DEVNULL,
        ).split(": ", 1)[0]
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"Dependency source/notice attribution is missing: {filename}") from error
    packages.add(owner)
dependencies = []
for package in sorted(packages):
    metadata = (
        subprocess.check_output(
            [
                "dpkg-query",
                "-W",
                "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}",
                package,
            ],
            text=True,
        )
        .strip()
        .split("\t")
    )
    if len(metadata) != 4:
        raise SystemExit(f"Dependency source metadata is incomplete: {package}")
    binary_name, binary_version, source_name, source_version = metadata
    dependencies.append(
        {
            "package": binary_name,
            "version": binary_version,
            "source_package": source_name,
            "source_version": source_version,
            "source_url": (
                f"https://snapshot.debian.org/package/{quote(source_name)}/"
                f"{quote(source_version, safe='')}/"
            ),
            "license_notice": f"licenses/{binary_name}.copyright",
        }
    )
    base = package.split(":", 1)[0]
    notice = Path("/usr/share/doc") / base / "copyright"
    if notice.exists():
        shutil.copyfile(notice, args.output / "licenses" / f"{base}.copyright")
    else:
        raise SystemExit(f"Dependency attribution is missing: {package}")
for name in ("COPYING", "COPYING.LESSER", "LICENSE", "README.md", "README.license.md"):
    path = args.ndpi_source / name
    if path.is_file():
        shutil.copyfile(path, args.output / "licenses" / f"ndpi-{name.replace('.', '-')}")
patches = Path(__file__).parent / "patches"
for path in sorted(patches.glob("*.patch")):
    shutil.copyfile(path, args.output / "licenses" / path.name)
source = {
    "project": "OpenMikroRout native application companion",
    "license": "GPL-3.0-or-later",
    "source_commit": args.source_commit,
    "source_url": f"https://github.com/gadmin2151/OpenMikroRout/tree/{args.source_commit}/native",
    "engine_commit": "cd1d03a52f0c968f1835110d70f5da652171a5d5",
    "engine_source_url": "https://github.com/ntop/nDPI/tree/cd1d03a52f0c968f1835110d70f5da652171a5d5",
    "engine_license": (
        "LGPL-3.0-or-later core and additional restricted ntop components; "
        "see included README.license.md"
    ),
    "profile": "explicit-ndpi-6-license-profile-required",
    "rebuild": "See native/Dockerfile.build and native/Makefile at the exact source revision.",
    "distribution_packages": dependencies,
}
(args.output / "licenses/SOURCES.json").write_text(json.dumps(source, indent=2) + "\n")
# Strip copied binaries only; keep the build products available for diagnostics.
for path in sorted((args.output / "bin").iterdir()):
    subprocess.run(["strip", "--strip-unneeded", str(path)], check=True)
for path in sorted((args.output / "lib").iterdir()):
    subprocess.run(["strip", "--strip-unneeded", str(path)], check=True)
files = {}
for path in sorted(args.output.rglob("*")):
    if path.is_file():
        if path.is_symlink():
            raise SystemExit("No symlink may enter the companion bundle")
        path.chmod(0o755 if path.parent.name == "bin" else 0o644)
        files[path.relative_to(args.output).as_posix()] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
manifest = {
    "format": 1,
    "purpose": "OpenMikroRout native companion",
    "source_commit": args.source_commit,
    "platform": "linux-amd64",
    "engine": {
        "name": "ndpi",
        "version": "6.0-stable",
        "commit": source["engine_commit"],
        "license_profile": source["profile"],
    },
    "dependencies": dependencies,
    "files": files,
}
(args.output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
os.chmod(args.output / "manifest.json", 0o644)
print(
    json.dumps(
        {"output": str(args.output), "files": len(files), "source_commit": args.source_commit}
    )
)
