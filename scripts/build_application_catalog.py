"""Publish typed application data without installing code or granting capabilities.

Run from the checkout with ``python -m scripts.build_application_catalog --help``.
Domain hints are opt-in, fixed to the reviewed V2Fly commit, and remain weak evidence.
The private signing key never enters catalog data, provenance or command output.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import urllib.request
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from app.application_catalog import MAX_CATALOG_BYTES, CatalogBundle  # noqa: E402
from app.ipv4 import domain_name  # noqa: E402

V2FLY_COMMIT = "e8d7a10a15bf662c927a40a3aa680bae86379608"
V2FLY_BASE = f"https://raw.githubusercontent.com/v2fly/domain-list-community/{V2FLY_COMMIT}/"
V2FLY_LICENSE_SHA256 = "b9d84a22870d3f21c91a4c6e410c9cc51d00902f5233ad0c84011479244bf7d2"
INVENTORY = ROOT / "docs/research/application-source-inventory-2026-11-08.json"
MAX_FILE_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_FILES = 128
MAX_INCLUDE_DEPTH = 8
MAX_DOMAINS_PER_APP = 256
MAX_SOURCE_DOMAINS = 100_000
Fetcher = Callable[[str, int], bytes]


class CatalogBuildError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise CatalogBuildError("Domain source redirects are not allowed")


def fetch_source(url: str, limit: int) -> bytes:
    if not url.startswith(V2FLY_BASE):
        raise CatalogBuildError("Only the fixed, pinned domain source is allowed")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/plain",
            "Accept-Encoding": "identity",
            "User-Agent": "OMR-Catalog/1",
        },
    )
    with opener.open(request, timeout=10) as response:
        if (
            response.status != 200
            or response.headers.get("Content-Encoding", "identity") != "identity"
        ):
            raise CatalogBuildError("Unexpected domain source response")
        data = response.read(limit + 1)
    if not isinstance(data, bytes) or len(data) > limit:
        raise CatalogBuildError("Domain source exceeds its size limit")
    return data


def read_file(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise CatalogBuildError("Input must be a bounded regular file")
    data = path.read_bytes()
    if len(data) > limit:
        raise CatalogBuildError("Input grew beyond its size limit")
    return data


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


@dataclass(frozen=True)
class SourcePin:
    blobs: dict[str, str]
    inventory_sha256: str


def read_pin(path: Path = INVENTORY) -> SourcePin:
    raw = read_file(path, 4 * 1024 * 1024)
    inventory = json.loads(raw)
    if not isinstance(inventory, dict):
        raise CatalogBuildError("Invalid source inventory document")
    source = inventory.get("domain_list_community", {})
    if not isinstance(source, dict):
        raise CatalogBuildError("Invalid source inventory record")
    if source.get("commit") != V2FLY_COMMIT or source.get("license") != "MIT":
        raise CatalogBuildError("Domain source commit/license does not match the reviewed pin")
    if source.get("license_sha256") != V2FLY_LICENSE_SHA256:
        raise CatalogBuildError("Domain source license hash changed")
    entries = source.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 10000:
        raise CatalogBuildError("Invalid pinned domain inventory")
    blobs = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise CatalogBuildError("Invalid pinned domain record")
        identifier, path_name, blob = entry.get("id"), entry.get("path"), entry.get("git_blob_sha1")
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_.!-]{0,99}", identifier)
            or path_name != "data/" + identifier
            or not isinstance(blob, str)
            or not re.fullmatch(r"[a-f0-9]{40}", blob)
            or identifier in blobs
        ):
            raise CatalogBuildError("Unsafe or duplicate pinned domain record")
        blobs[identifier] = blob
    return SourcePin(blobs, hashlib.sha256(raw).hexdigest())


class DomainHints:
    def __init__(self, pin: SourcePin, fetcher: Fetcher = fetch_source) -> None:
        self.pin = pin
        self.fetcher = fetcher
        self.files: dict[str, dict[str, Any]] = {}
        self.cache: dict[str, set[str]] = {}
        self.total_bytes = 0
        self.skipped: Counter[str] = Counter()

    def domains(self, identifier: str, stack: tuple[str, ...] = ()) -> set[str]:
        if identifier in stack:
            raise CatalogBuildError("Domain include cycle")
        if len(stack) >= MAX_INCLUDE_DEPTH:
            raise CatalogBuildError("Domain include depth exceeds the limit")
        if identifier in self.cache:
            return self.cache[identifier]
        if identifier not in self.pin.blobs:
            raise CatalogBuildError("Domain include is not in the pinned inventory")
        if len(self.files) >= MAX_SOURCE_FILES:
            raise CatalogBuildError("Too many domain source files")
        raw = self.fetcher(V2FLY_BASE + "data/" + identifier, MAX_FILE_BYTES)
        self.total_bytes += len(raw)
        if len(raw) > MAX_FILE_BYTES or self.total_bytes > MAX_SOURCE_BYTES:
            raise CatalogBuildError("Domain sources exceed the total size limit")
        if git_blob_sha1(raw) != self.pin.blobs[identifier]:
            raise CatalogBuildError("Pinned domain source blob hash mismatch")
        self.files[identifier] = {
            "path": "data/" + identifier,
            "git_blob_sha1": self.pin.blobs[identifier],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        result = set()
        for raw_line in raw.decode("utf-8", errors="strict").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if "@" in line or len(line.split()) != 1:
                self.skipped["qualified_or_whitespace"] += 1
                continue
            if line.startswith("include:"):
                result.update(self.domains(line.removeprefix("include:"), (*stack, identifier)))
            elif line.startswith(("full:", "regexp:", "keyword:")):
                # CatalogEntry.domains contains suffixes. Converting exact/regex rules
                # to suffixes would broaden the source's meaning.
                self.skipped[line.split(":", 1)[0]] += 1
            elif ":" in line and not line.startswith("domain:"):
                self.skipped["unsupported_prefix"] += 1
            else:
                value = line.removeprefix("domain:")
                try:
                    value = domain_name(value)
                    if "." not in value or value.endswith((".local", ".localhost", ".invalid")):
                        raise ValueError("Not a public DNS suffix")
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        pass
                    else:
                        raise ValueError("A domain hint cannot be an IP literal")
                except ValueError:
                    self.skipped["invalid_domain"] += 1
                else:
                    result.add(value)
            if len(result) > MAX_SOURCE_DOMAINS:
                raise CatalogBuildError("Too many normalized domain hints")
        self.cache[identifier] = result
        return result

    def license(self) -> str:
        raw = self.fetcher(V2FLY_BASE + "LICENSE", 16384)
        if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != V2FLY_LICENSE_SHA256:
            raise CatalogBuildError("Pinned domain license hash mismatch")
        return raw.decode("utf-8", errors="strict")


def add_domain_hints(
    bundle: CatalogBundle, loader: DomainHints
) -> tuple[CatalogBundle, dict[str, Any]]:
    document = bundle.model_dump(mode="json")
    by_id = {entry["id"]: entry for entry in document["entries"]}
    refs: dict[str, set[str]] = {identifier: set() for identifier in by_id}
    for entry in document["entries"]:
        for reference in entry["domain_provider_refs"]:
            if not reference.startswith("v2fly:"):
                raise CatalogBuildError("Only the fixed domain provider can supply hints")
            identifier = reference.removeprefix("v2fly:")
            targets = entry["children"] if entry["kind"] == "family" else [entry["id"]]
            for target in targets:
                refs[target].add(identifier)
            refs[entry["id"]].add(identifier)
    app_report: dict[str, dict[str, Any]] = {}
    for identifier, entry in by_id.items():
        hints = set(entry["domains"])
        for source in sorted(refs[identifier]):
            hints.update(loader.domains(source))
        kept = sorted(hints)[:MAX_DOMAINS_PER_APP]
        entry["domains"] = kept
        app_report[identifier] = {
            "provider_refs": sorted(refs[identifier]),
            "retained_domains": len(kept),
            "omitted_above_limit": max(0, len(hints) - len(kept)),
        }
        # No provider-derived capability promotion: imported names/domains do not
        # establish reliable packet classification or port-override safety.
    notice = loader.license()
    provider_metadata = {
        "id": "v2fly-domain-hints",
        "commit": V2FLY_COMMIT,
        "license": "MIT",
        "license_sha256": V2FLY_LICENSE_SHA256,
        "source_url": V2FLY_BASE,
        "interpretation": "weak suffix hints only; not application identity or permission",
        "license_notice_format": "framed-text-v1; concatenate contents between BEGIN/END-NOTICE",
    }
    for index, offset in enumerate(range(0, len(notice), 450), 1):
        # The surrounding frame preserves boundary whitespace in the strict
        # catalog model while keeping every metadata value below 500 characters.
        provider_metadata[f"license_notice_{index:03}"] = (
            "BEGIN-NOTICE\n" + notice[offset : offset + 450] + "\nEND-NOTICE"
        )
    document["sources"].append(provider_metadata)
    result = CatalogBundle.model_validate(document)
    for before, after in zip(bundle.entries, result.entries, strict=True):
        if (before.block_validated, before.allow_over_port_deny, before.observable) != (
            after.block_validated,
            after.allow_over_port_deny,
            after.observable,
        ):
            raise CatalogBuildError("Domain import changed a classification capability")
    return result, {
        "repository": "https://github.com/v2fly/domain-list-community",
        "commit": V2FLY_COMMIT,
        "inventory_sha256": loader.pin.inventory_sha256,
        "license": "MIT",
        "license_notice": notice,
        "files": loader.files,
        "skipped_rows": dict(sorted(loader.skipped.items())),
        "applications": app_report,
    }


def load_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise CatalogBuildError("Signing key must be a private regular file (0600)")
    raw = read_file(path, 16384)
    key = (
        Ed25519PrivateKey.from_private_bytes(raw)
        if len(raw) == 32
        else serialization.load_pem_private_key(raw, password=None)
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise CatalogBuildError("An Ed25519 signing key is required")
    return key


def build_catalog(
    input_path: Path,
    version: str,
    serial: int,
    private_key: Path,
    output: Path,
    *,
    with_domain_hints: bool = False,
    fetcher: Fetcher = fetch_source,
) -> dict[str, Any]:
    if serial <= 0:
        raise CatalogBuildError(
            "Published catalog serial must be positive; zero is the bundled seed"
        )
    source = read_file(input_path, MAX_CATALOG_BYTES)
    seed = json.loads(source)
    if not isinstance(seed, dict):
        raise CatalogBuildError("Input must be a catalog seed object")
    bundle = CatalogBundle.model_validate(
        {
            "version": version,
            "serial": serial,
            "entries": seed.get("entries"),
            "sources": seed.get("sources", []),
        }
    )
    domain_report = None
    if with_domain_hints:
        bundle, domain_report = add_domain_hints(bundle, DomainHints(read_pin(), fetcher))
    raw = (
        json.dumps(
            bundle.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    if len(raw) > MAX_CATALOG_BYTES:
        raise CatalogBuildError("Published catalog exceeds the router size limit")
    key = load_key(private_key)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    provenance = {
        "format": 1,
        "purpose": "OpenMikroRout application catalog provenance",
        "version": bundle.version,
        "serial": bundle.serial,
        "entries": len(bundle.entries),
        "catalog_sha256": hashlib.sha256(raw).hexdigest(),
        "input_sha256": hashlib.sha256(source).hexdigest(),
        "signing_public_key_pem": public.decode(),
        "signing_public_key_sha256": hashlib.sha256(public).hexdigest(),
        "domain_hints": domain_report,
        "capabilities_promoted_by_import": False,
    }
    artifacts = {
        "catalog.json": raw,
        "catalog.sig": base64.b64encode(key.sign(raw)) + b"\n",
        "catalog.provenance.json": (
            json.dumps(provenance, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode(),
    }
    if output.is_symlink():
        raise CatalogBuildError("Output directory must not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() or (output / name).is_symlink() for name in artifacts):
        raise CatalogBuildError("Output artifacts already exist; use a new build directory")
    created = []
    try:
        for name, payload in artifacts.items():
            path = output / name
            with path.open("xb") as target:
                created.append(path)
                os.fchmod(target.fileno(), 0o644)
                target.write(payload)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return {
        key: provenance[key]
        for key in ("version", "serial", "entries", "catalog_sha256", "signing_public_key_sha256")
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "app/application_catalog_seed.json")
    parser.add_argument("--version", required=True)
    parser.add_argument("--serial", type=int, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--with-domain-hints", action="store_true")
    args = parser.parse_args()
    try:
        result = build_catalog(
            args.input,
            args.version,
            args.serial,
            args.private_key,
            args.output,
            with_domain_hints=args.with_domain_hints,
        )
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
