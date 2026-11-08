"""Bounded, versioned application data; signed downloads never activate policy."""

import base64
import hashlib
import json
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Annotated, Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import Field, model_validator

from app.application_models import CATALOG_VERSION, AppId
from app.link_models import LinkModel
from app.list_filters import FieldSpec, compile_expression, parse_expression

MAX_CATALOG_BYTES = 8 * 1024 * 1024
CATALOG_URL = "https://raw.githubusercontent.com/gadmin2151/OpenMikroRout/catalog-data/catalog.json"
CATALOG_SIGNATURE_URL = CATALOG_URL.removesuffix(".json") + ".sig"
CATALOG_SCHEMA = {
    "id": FieldSpec("text"),
    "name": FieldSpec("text"),
    "kind": FieldSpec(
        "enum", options=("application", "family", "provider", "category", "protocol")
    ),
    "category": FieldSpec("text"),
    **{
        key: FieldSpec("enum", options=("true", "false"))
        for key in ("observable", "block_validated", "allow_over_port_deny")
    },
}


class EngineMapping(LinkModel):
    engine: Literal["ndpi"] = "ndpi"
    version: str = Field(max_length=40)
    symbol: str = Field(max_length=100, pattern=r"^NDPI_PROTOCOL_[A-Z0-9_]+$")
    native_id: int = Field(ge=1, le=65535)


class CatalogNames(LinkModel):
    ru: str = Field(min_length=1, max_length=128)
    en: str = Field(min_length=1, max_length=128)


class CatalogEntry(LinkModel):
    id: AppId
    kind: Literal["application", "family", "provider", "category", "protocol"] = "application"
    name: CatalogNames
    category: str = Field(default="", max_length=64)
    parent: str = Field(default="", max_length=80)
    children: list[AppId] = Field(default_factory=list, max_length=128)
    engine_mapping: EngineMapping | None = None
    domain_provider_refs: list[Annotated[str, Field(max_length=128)]] = Field(
        default_factory=list, max_length=16
    )
    domains: list[Annotated[str, Field(max_length=253, pattern=r"^[a-z0-9.-]+$")]] = Field(
        default_factory=list, max_length=256
    )
    coverage: str = Field(default="unverified", max_length=200)
    license_profile: str = Field(default="", max_length=128)
    children_selection: str = Field(default="", max_length=100)
    observable: bool = True
    block_validated: bool = False
    allow_over_port_deny: bool = False


class CatalogBundle(LinkModel):
    format: Literal[1] = 1
    purpose: Literal["OpenMikroRout application catalog"] = "OpenMikroRout application catalog"
    serial: int = Field(ge=0, le=2**53 - 1, strict=True)
    version: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    entries: list[CatalogEntry] = Field(min_length=1, max_length=10000)
    sources: list[dict[str, Annotated[str, Field(max_length=500)]]] = Field(
        default_factory=list, max_length=32
    )

    @model_validator(mode="after")
    def valid_references(self) -> "CatalogBundle":
        entries = {entry.id: entry for entry in self.entries}
        if len(entries) != len(self.entries):
            raise ValueError("Application catalog IDs must be unique")
        for entry in self.entries:
            if any(
                child not in entries or entries[child].kind != "application"
                for child in entry.children
            ):
                raise ValueError("Catalog family children must reference concrete applications")
            if entry.parent and entry.parent not in entries:
                raise ValueError("Unknown catalog parent")
            if entry.allow_over_port_deny and entry.kind != "application":
                raise ValueError("Only concrete applications can grant a port exception")
        return self


def protocol_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.removeprefix("NDPI_PROTOCOL_").casefold())


class ApplicationCatalog:
    def __init__(self, directory: Path, public_key: Path | None = None) -> None:
        self.directory = directory / "applications"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "catalog.sqlite3"
        self.public_key = public_key
        self.lock = threading.RLock()
        self.job: dict[str, Any] | None = None
        self.worker: threading.Thread | None = None
        self.last_check = 0.0
        seed = json.loads(Path(__file__).with_name("application_catalog_seed.json").read_text())
        bundle = CatalogBundle(
            serial=0, version=CATALOG_VERSION, entries=seed["entries"], sources=seed["sources"]
        )
        with closing(self.connect()) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS catalogs(version TEXT PRIMARY KEY,"
                "serial INTEGER UNIQUE NOT NULL,payload TEXT NOT NULL,sha256 TEXT NOT NULL,"
                "verified INTEGER NOT NULL,added_at REAL NOT NULL)"
            )
            db.execute(
                "INSERT OR IGNORE INTO catalogs VALUES(?,?,?,?,?,?)",
                (
                    bundle.version,
                    0,
                    bundle.model_dump_json(),
                    hashlib.sha256(bundle.model_dump_json().encode()).hexdigest(),
                    0,
                    time.time(),
                ),
            )

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def bundle(self, version: str) -> CatalogBundle:
        with closing(self.connect()) as db:
            row = db.execute("SELECT payload FROM catalogs WHERE version=?", (version,)).fetchone()
        if row is None:
            raise ValueError("The selected application catalog has not been downloaded")
        return CatalogBundle.model_validate_json(row[0])

    def versions(self) -> list[dict[str, Any]]:
        with closing(self.connect()) as db:
            rows = db.execute(
                "SELECT version,serial,verified,added_at FROM catalogs "
                "ORDER BY serial DESC LIMIT 32"
            ).fetchall()
        return [
            {"version": row[0], "serial": row[1], "verified": bool(row[2]), "added_at": row[3]}
            for row in rows
        ]

    def entries(
        self, version: str, capabilities: dict[str, Any], *, language: str = "ru"
    ) -> list[dict[str, Any]]:
        protocols = {
            protocol_key(str(item.get("name", ""))): str(item.get("name", ""))
            for item in capabilities.get("protocols", [])
            if isinstance(item, dict)
        }
        result = []
        for entry in self.bundle(version).entries:
            mapped = (
                protocols.get(protocol_key(entry.engine_mapping.symbol))
                if entry.engine_mapping
                else None
            )
            observable = bool(entry.observable and mapped and capabilities.get("available"))
            block = bool(entry.block_validated and observable and capabilities.get("enforce"))
            allow = bool(
                entry.allow_over_port_deny and block and capabilities.get("allow_over_port_deny")
            )
            result.append(
                {
                    **entry.model_dump(mode="json"),
                    "name": entry.name.en if language == "en" else entry.name.ru,
                    "name_ru": entry.name.ru,
                    "name_en": entry.name.en,
                    "protocol_names": [mapped] if mapped else [],
                    "observable": observable,
                    "block_validated": block,
                    "allow_over_port_deny": allow,
                    "capabilities": {
                        "observable": observable,
                        "block_validated": block,
                        "allow_over_port_deny": allow,
                    },
                }
            )
        by_id = {entry["id"]: entry for entry in result}
        for public_entry in result:
            public_entry["concrete_ids"] = (
                public_entry["children"]
                if public_entry["kind"] == "family"
                else [public_entry["id"]]
            )
            if public_entry["kind"] == "family":
                public_entry["observable"] = any(
                    by_id[child]["observable"] for child in public_entry["children"]
                )
                public_entry["capabilities"]["observable"] = public_entry["observable"]
        return result

    def page(
        self,
        version: str,
        capabilities: dict[str, Any],
        expression: str = "",
        offset: int = 0,
        limit: int = 50,
        language: str = "ru",
    ) -> dict[str, Any]:
        if not 0 <= offset <= 10000 or not 1 <= limit <= 200:
            raise ValueError("Invalid catalog pagination")
        predicate = compile_expression(parse_expression(expression, CATALOG_SCHEMA), CATALOG_SCHEMA)
        entries = self.entries(version, capabilities, language=language)
        matched = [
            entry
            for entry in entries
            if predicate({**entry, "name": [entry["name_ru"], entry["name_en"]]})
        ]
        return {
            "items": matched[offset : offset + limit],
            "total": len(matched),
            "offset": offset,
            "limit": limit,
            "version": version,
        }

    def import_signed(
        self, raw: bytes, signature: bytes, verify: Callable[[bytes, bytes], None]
    ) -> CatalogBundle:
        if len(raw) > MAX_CATALOG_BYTES or len(signature) != 64:
            raise ValueError("Application catalog exceeds its data limits")
        verify(signature, raw)
        document = json.loads(raw)
        if (
            not isinstance(document, dict)
            or document.get("purpose") != "OpenMikroRout application catalog"
        ):
            raise ValueError("Invalid application catalog signature purpose")
        bundle = CatalogBundle.model_validate(document)
        with self.lock, closing(self.connect()) as db, db:
            existing = db.execute(
                "SELECT sha256 FROM catalogs WHERE version=?", (bundle.version,)
            ).fetchone()
            digest = hashlib.sha256(raw).hexdigest()
            if existing:
                if existing[0] != digest:
                    raise ValueError("An immutable catalog version cannot change its contents")
                return bundle
            maximum = db.execute("SELECT MAX(serial) FROM catalogs").fetchone()[0]
            if bundle.serial <= maximum:
                raise ValueError("Application catalog replay/downgrade rejected")
            db.execute(
                "INSERT INTO catalogs VALUES(?,?,?,?,?,?)",
                (bundle.version, bundle.serial, raw.decode("utf-8"), digest, 1, time.time()),
            )
        return bundle

    def sync(self, download: bool) -> dict[str, Any]:
        with self.lock:
            if self.worker and self.worker.is_alive():
                return dict(self.job or {})
            if time.time() - self.last_check < 10:
                raise ValueError("Wait before checking the application catalog again")
            if self.public_key is None or not self.public_key.is_file():
                raise ValueError("Application catalog verification key is not configured")
            self.last_check = time.time()
            self.job = {
                "phase": "queued",
                "operation": "download" if download else "check",
                "started_at": self.last_check,
            }
            self.worker = threading.Thread(
                target=self._sync, args=(download,), name="application-catalog", daemon=True
            )
            self.worker.start()
            return dict(self.job)

    @staticmethod
    def download(url: str, limit: int) -> bytes:
        if url not in (CATALOG_URL, CATALOG_SIGNATURE_URL):
            raise ValueError("Untrusted application catalog URL")

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                raise ValueError("Application catalog redirects are not accepted")

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(url, headers={"User-Agent": "OpenMikroRout-Catalog/1"})
        with opener.open(request, timeout=15) as response:
            raw: bytes = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("Application catalog download exceeds its size limit")
        return raw

    def _sync(self, download: bool) -> None:
        try:
            assert self.public_key is not None
            key = load_pem_public_key(self.public_key.read_bytes())
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("Application catalogs require an Ed25519 verification key")
            raw = self.download(CATALOG_URL, MAX_CATALOG_BYTES)
            signature = base64.b64decode(
                self.download(CATALOG_SIGNATURE_URL, 256).strip(), validate=True
            )
            if len(signature) != 64:
                raise ValueError("Invalid application catalog signature length")
            key.verify(signature, raw)
            document = json.loads(raw)
            if (
                not isinstance(document, dict)
                or document.get("purpose") != "OpenMikroRout application catalog"
            ):
                raise ValueError("Invalid application catalog signature purpose")
            bundle = CatalogBundle.model_validate(document)
            if download:
                self.import_signed(raw, signature, key.verify)
            result = {
                "phase": "completed",
                "version": bundle.version,
                "serial": bundle.serial,
                "staged": download,
                "finished_at": time.time(),
            }
        except (ValueError, OSError, InvalidSignature, sqlite3.Error, urllib.error.URLError) as exc:
            result = {"phase": "failed", "error": str(exc)[:300], "finished_at": time.time()}
        with self.lock:
            self.job = {**(self.job or {}), **result}

    def status(self, active: str) -> dict[str, Any]:
        return {
            "active_version": active,
            "versions": self.versions(),
            "entries": len(self.bundle(active).entries),
            "job": dict(self.job) if self.job else None,
            "sync_configured": bool(self.public_key and self.public_key.is_file()),
        }

    def close(self) -> None:
        if self.worker:
            self.worker.join(timeout=1)
