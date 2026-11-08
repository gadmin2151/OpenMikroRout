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
MAX_FULL_SOURCE_FILES = 4096
MAX_FULL_SOURCE_BYTES = 32 * 1024 * 1024
FULL_DOMAINS_PER_APP = 64
NDPI_COMMIT = "cd1d03a52f0c968f1835110d70f5da652171a5d5"
PROVIDER_LISTS = frozenset(
    {
        "akamai",
        "alibabacloud",
        "aliyun",
        "anexia",
        "aws",
        "aws-cn",
        "azure",
        "baishancloud",
        "bandwagonhost",
        "beget",
        "bootcdn",
        "capitalonline",
        "cdn77",
        "cloudcone",
        "cloudflare",
        "cloudflare-cn",
        "cloudinary",
        "cloudns",
        "ctyun",
        "digitalocean",
        "dmit",
        "fastly",
        "flyio",
        "gandi",
        "godaddy",
        "heroku",
        "hetzner",
        "huaweicloud",
        "hurricaneelectric",
        "imgix",
        "jsdelivr",
        "limelight",
        "maocloud",
        "netcup",
        "netlify",
        "ovh",
        "pagecdn",
        "qcloud",
        "qingcloud",
        "qiniu",
        "quantil",
        "scaleflex",
        "selectel",
        "stackpath",
        "staticfile",
        "timeweb",
        "ucloud",
        "upai",
        "vercel",
        "volcengine",
        "vultr",
        "wangsu",
        "xtom",
    }
)
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
    ndpi: dict[str, Any] | None = None


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
    ndpi = inventory.get("ndpi")
    return SourcePin(
        blobs, hashlib.sha256(raw).hexdigest(), ndpi if isinstance(ndpi, dict) else None
    )


def local_source_fetcher(directory: Path) -> Fetcher:
    """Read a checkout/archive cache; every source blob is still hash-verified."""
    if directory.is_symlink() or not directory.is_dir():
        raise CatalogBuildError("Domain source cache must be a real directory")
    root = directory.resolve(strict=True)

    def fetch(url: str, limit: int) -> bytes:
        if not url.startswith(V2FLY_BASE):
            raise CatalogBuildError("Only the pinned source can use the local cache")
        relative = url.removeprefix(V2FLY_BASE)
        if relative != "LICENSE" and not re.fullmatch(r"data/[a-z0-9][a-z0-9_.!-]{0,99}", relative):
            raise CatalogBuildError("Unsafe domain cache path")
        candidate = root / relative
        if candidate.is_symlink() or not candidate.resolve(strict=True).is_relative_to(root):
            raise CatalogBuildError("Domain cache links cannot escape the source root")
        return read_file(candidate, limit)

    return fetch


class DomainHints:
    def __init__(
        self, pin: SourcePin, fetcher: Fetcher = fetch_source, *, full_catalog: bool = False
    ) -> None:
        self.pin = pin
        self.fetcher = fetcher
        self.files: dict[str, dict[str, Any]] = {}
        self.cache: dict[str, set[str]] = {}
        self.direct: dict[str, set[str]] = {}
        self.includes: dict[str, set[str]] = {}
        self.full_catalog = full_catalog
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
        if len(self.files) >= (MAX_FULL_SOURCE_FILES if self.full_catalog else MAX_SOURCE_FILES):
            raise CatalogBuildError("Too many domain source files")
        raw = self.fetcher(V2FLY_BASE + "data/" + identifier, MAX_FILE_BYTES)
        self.total_bytes += len(raw)
        if len(raw) > MAX_FILE_BYTES or self.total_bytes > (
            MAX_FULL_SOURCE_BYTES if self.full_catalog else MAX_SOURCE_BYTES
        ):
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
        direct: set[str] = set()
        includes: set[str] = set()
        for raw_line in raw.decode("utf-8", errors="strict").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if "@" in line or len(line.split()) != 1:
                self.skipped["qualified_or_whitespace"] += 1
                continue
            if line.startswith("include:"):
                child = line.removeprefix("include:")
                includes.add(child)
                result.update(self.domains(child, (*stack, identifier)))
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
                    direct.add(value)
            if len(result) > MAX_SOURCE_DOMAINS:
                raise CatalogBuildError("Too many normalized domain hints")
        self.cache[identifier] = result
        self.direct[identifier] = direct
        self.includes[identifier] = includes
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


def source_id(provider: str, identifier: str) -> str:
    slug = re.sub(r"[^a-z0-9_.-]", "-", identifier.lower().replace("!", "not-"))
    value = f"app.{provider}.{slug}"
    if len(value) > 80:
        value = value[:63].rstrip(".-") + "." + hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return value


def name_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower().removeprefix("ndpi_protocol_"))


def source_kind(identifier: str, direct: set[str], includes: set[str]) -> str:
    if (
        identifier.startswith(("category-", "geolocation-", "tld-"))
        or identifier in {"cn", "test", "test-ipv6", "connectivity-check"}
        or (not direct and bool(includes))
    ):
        return "category"
    return "provider" if identifier in PROVIDER_LISTS else "application"


def full_catalog(
    bundle: CatalogBundle, loader: DomainHints, capabilities: dict[str, Any]
) -> tuple[CatalogBundle, dict[str, Any]]:
    """Expand source identities, never domain rows or detection capabilities.

    Concrete services get their own literal suffixes only. Includes describe
    umbrella membership; copying them into each app would create misleading
    Google/YouTube and Microsoft/GitHub ownership overlaps.
    """
    if not loader.full_catalog:
        raise CatalogBuildError("Full source import requires explicit bounded full-catalog mode")
    ndpi = loader.pin.ndpi
    engine = capabilities.get("engine", {})
    protocols = capabilities.get("protocols")
    if (
        not ndpi
        or not isinstance(engine, dict)
        or engine.get("name") != "ndpi"
        or engine.get("commit") != NDPI_COMMIT
        or not isinstance(protocols, list)
        or not 1 <= len(protocols) <= 2048
    ):
        raise CatalogBuildError("Actual capabilities from the pinned nDPI6 engine are required")
    declared = ndpi.get("entries")
    if not isinstance(declared, list):
        raise CatalogBuildError("Pinned nDPI source declarations are missing")
    symbols: dict[int, str] = {}
    for item in declared:
        if (
            not isinstance(item, dict)
            or type(item.get("engine_id")) is not int
            or not isinstance(item.get("symbol"), str)
            or not re.fullmatch(r"NDPI_PROTOCOL_[A-Z0-9_]+", item["symbol"])
            or not 1 <= item["engine_id"] <= 65535
            or item["engine_id"] in symbols
        ):
            raise CatalogBuildError("Invalid pinned nDPI source declaration")
        symbols[item["engine_id"]] = item["symbol"]
    actual: dict[int, str] = {}
    for item in protocols:
        if (
            not isinstance(item, dict)
            or type(item.get("id")) is not int
            or item["id"] not in symbols
            or item["id"] in actual
            or not isinstance(item.get("name"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.+() /-]{1,100}", item["name"])
        ):
            raise CatalogBuildError("Actual nDPI protocol identities do not match the source pin")
        actual[item["id"]] = item["name"]
    if set(actual) != set(symbols):
        raise CatalogBuildError("Full catalog requires every pinned protocol's actual engine name")
    for identifier in sorted(loader.pin.blobs):
        loader.domains(identifier)
    document = bundle.model_dump(mode="json")
    entries: list[dict[str, Any]] = document["entries"]
    by_id = {row["id"]: row for row in entries}
    owners: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    row: dict[str, Any] | None
    native_owners = {
        row["engine_mapping"]["native_id"]: row for row in entries if row.get("engine_mapping")
    }
    for row in entries:
        for reference in row["domain_provider_refs"]:
            if reference.startswith("v2fly:"):
                owners[reference.removeprefix("v2fly:")] = row
    added_ndpi = 0
    for native_id, display in sorted(actual.items()):
        row = native_owners.get(native_id)
        if row is None:
            symbol = symbols[native_id]
            identifier = source_id("ndpi", symbol.removeprefix("NDPI_PROTOCOL_"))
            if identifier in by_id:
                raise CatalogBuildError("Generated nDPI ID collides with a seed entry")
            row = {
                "id": identifier,
                "kind": "protocol",
                "name": {"ru": display, "en": display},
                "category": "network-protocols",
                "engine_mapping": {
                    "engine": "ndpi",
                    "version": "6.0",
                    "symbol": symbol,
                    "native_id": native_id,
                    "protocol_name": display,
                },
                "domain_provider_refs": [],
                "domains": [],
                "observable": not symbol.startswith("NDPI_PROTOCOL_IP_"),
                "block_validated": False,
                "allow_over_port_deny": False,
                "coverage": (
                    "Engine-declared protocol; observation only; no imported enforcement guarantee"
                ),
                "license_profile": "ndpi-6-explicit-acceptance-required",
            }
            entries.append(row)
            by_id[identifier] = row
            added_ndpi += 1
            if not row["observable"]:
                row["coverage"] = "Declared protocol outside the IPv4 TCP/UDP packet-path scope"
        by_name[name_key(display)] = row
        by_name[name_key(symbols[native_id])] = row
    aliases: dict[str, str] = {}
    for identifier in sorted(loader.pin.blobs):
        if (
            not loader.direct[identifier]
            and len(loader.includes[identifier]) == 1
            and not identifier.startswith(("category-", "geolocation-", "tld-"))
            and identifier not in {"cn", "test", "test-ipv6", "connectivity-check"}
        ):
            aliases[identifier] = next(iter(loader.includes[identifier]))
    report: dict[str, Any] = {"entries": {}, "aliases": {}, "added_ndpi_declarations": added_ndpi}
    report["engine_capabilities_sha256"] = hashlib.sha256(
        json.dumps(capabilities, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for identifier in sorted(loader.pin.blobs):
        if identifier in aliases and identifier not in owners:
            continue
        direct = loader.direct[identifier]
        kind = source_kind(identifier, direct, loader.includes[identifier])
        row = owners.get(identifier)
        if row is None and kind == "application":
            candidate = by_name.get(name_key(identifier))
            if candidate and candidate["kind"] == "protocol":
                row = candidate
                row["kind"] = "application"
        if row is None:
            canonical_id = source_id("v2fly", identifier)
            if canonical_id in by_id:
                raise CatalogBuildError("Generated V2Fly ID collides with another catalog identity")
            display = identifier.replace("!", "not-").replace("-", " ").title()
            row = {
                "id": canonical_id,
                "kind": kind,
                "name": {"ru": display, "en": display},
                "category": "web-services" if kind == "application" else f"source-{kind}s",
                "domain_provider_refs": [],
                "domains": [],
                "observable": kind == "application" and bool(direct),
                "block_validated": False,
                "allow_over_port_deny": False,
                "coverage": (
                    "Literal hostname suffix hints only; no process identity; "
                    "encrypted/unknown traffic may not match"
                ),
                "license_profile": "MIT domain data; hostname engine availability required",
            }
            entries.append(row)
            by_id[canonical_id] = row
        owners[identifier] = row
        reference = "v2fly:" + identifier
        if reference not in row["domain_provider_refs"]:
            row["domain_provider_refs"].append(reference)
        # Category/provider rows remain explicit inventory groups, never fake apps.
        if row["kind"] not in {"category", "provider", "family"}:
            anchors = {
                identifier.replace("-", "") + "." + tld for tld in ("com", "net", "org", "io")
            }
            ranked = sorted(
                direct, key=lambda host: (host not in anchors, host.count("."), len(host), host)
            )
            selected = ranked[:FULL_DOMAINS_PER_APP]
            row["domains"] = sorted(set(row["domains"]) | set(selected))[:MAX_DOMAINS_PER_APP]
        else:
            selected = []
        report["entries"][identifier] = {
            "id": row["id"],
            "kind": row["kind"],
            "direct_suffixes": len(direct),
            "retained_suffixes": len(selected),
            "omitted_above_limit": max(0, len(direct) - FULL_DOMAINS_PER_APP) if selected else 0,
            "includes": sorted(loader.includes[identifier]),
        }
    for alias, target in sorted(aliases.items()):
        seen = {alias}
        while target in aliases and target not in owners:
            if target in seen:
                raise CatalogBuildError("Catalog alias cycle")
            seen.add(target)
            target = aliases[target]
        row = owners.get(target)
        if row is None:
            raise CatalogBuildError("Catalog alias has no concrete source identity")
        reference = "v2fly:" + alias
        if reference not in row["domain_provider_refs"]:
            row["domain_provider_refs"].append(reference)
        report["aliases"][alias] = row["id"]
    document["sources"].append(
        {
            "id": "ndpi-full-protocol-identities",
            "engine_commit": NDPI_COMMIT,
            "source_commit": str(ndpi.get("commit", "")),
            "source_url": str(ndpi.get("source_url", "")),
            "source_sha256": str(ndpi.get("source_sha256", "")),
            "license": "LGPL-3.0-or-later identifiers; detector licenses remain separate",
            "interpretation": (
                "Engine declarations are not validated app-block or port-override capabilities"
            ),
        }
    )
    result = CatalogBundle.model_validate(document)
    counts = Counter(row.kind for row in result.entries)
    domains: dict[str, set[str]] = {}
    for catalog_row in result.entries:
        if catalog_row.kind == "application":
            for domain in catalog_row.domains:
                domains.setdefault(domain, set()).add(catalog_row.id)
    for catalog_row in result.entries:
        if (
            catalog_row.kind == "application"
            and catalog_row.engine_mapping is None
            and catalog_row.domains
            and all(len(domains[domain]) > 1 for domain in catalog_row.domains)
        ):
            catalog_row.observable = False
            catalog_row.coverage = (
                "All retained suffixes are shared; no unique hostname attribution"
            )
    report.update(
        {
            "source_lists": len(loader.pin.blobs),
            "entries_total": len(result.entries),
            "kinds": dict(sorted(counts.items())),
            "literal_suffixes_unique": len(domains),
            "ambiguous_literal_suffixes": sum(len(owners) > 1 for owners in domains.values()),
            "domain_only_applications": sum(
                row.kind == "application" and row.engine_mapping is None for row in result.entries
            ),
            "domain_only_applications_with_suffixes": sum(
                row.kind == "application" and row.engine_mapping is None and bool(row.domains)
                for row in result.entries
            ),
            "domain_applications_with_unique_suffix": sum(
                row.kind == "application"
                and bool(row.domains)
                and any(len(domains[domain]) == 1 for domain in row.domains)
                for row in result.entries
            ),
            "applications_with_only_ambiguous_suffixes": [
                row.id
                for row in result.entries
                if row.kind == "application"
                and row.domains
                and all(len(domains[domain]) > 1 for domain in row.domains)
            ],
            "truncated_source_lists": sum(
                item["omitted_above_limit"] > 0 for item in report["entries"].values()
            ),
            "capabilities_promoted_by_import": False,
        }
    )
    for before in bundle.entries:
        after = next(row for row in result.entries if row.id == before.id)
        if (before.block_validated, before.allow_over_port_deny) != (
            after.block_validated,
            after.allow_over_port_deny,
        ):
            raise CatalogBuildError("Full import changed a seed enforcement capability")
    return result, report


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
    expand_sources: bool = False,
    ndpi_capabilities: Path | None = None,
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
    full_report = None
    if with_domain_hints or expand_sources:
        loader = DomainHints(read_pin(), fetcher, full_catalog=expand_sources)
        bundle, domain_report = add_domain_hints(bundle, loader)
        if expand_sources:
            if ndpi_capabilities is None:
                raise CatalogBuildError("Full import requires --ndpi-capabilities")
            capabilities = json.loads(read_file(ndpi_capabilities, 512 * 1024))
            if not isinstance(capabilities, dict):
                raise CatalogBuildError("Engine capabilities must be a bounded object")
            bundle, full_report = full_catalog(bundle, loader, capabilities)
            domain_report["skipped_rows"] = dict(sorted(loader.skipped.items()))
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
        "full_sources": full_report,
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
    parser.add_argument("--expand-sources", action="store_true")
    parser.add_argument("--ndpi-capabilities", type=Path)
    parser.add_argument("--domain-source-dir", type=Path)
    args = parser.parse_args()
    try:
        result = build_catalog(
            args.input,
            args.version,
            args.serial,
            args.private_key,
            args.output,
            with_domain_hints=args.with_domain_hints,
            expand_sources=args.expand_sources,
            ndpi_capabilities=args.ndpi_capabilities,
            fetcher=local_source_fetcher(args.domain_source_dir)
            if args.domain_source_dir
            else fetch_source,
        )
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
