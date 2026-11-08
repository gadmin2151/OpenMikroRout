import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.application_catalog import CatalogBundle
from scripts import build_application_catalog as builder


def entry(identifier: str, **extra: object) -> dict[str, object]:
    return {
        "id": identifier,
        "name": {"ru": "Тестовый сервис", "en": "Test service"},
        "kind": "application",
        "block_validated": False,
        "allow_over_port_deny": False,
        **extra,
    }


def seed_file(tmp_path: Path) -> Path:
    path = tmp_path / "seed.json"
    path.write_text(json.dumps({"entries": [entry("app.test")], "sources": []}))
    return path


def private_file(tmp_path: Path, *, pem: bool = False) -> Path:
    path = tmp_path / "DO-NOT-PUBLISH-private-key"
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        if pem
        else key.private_bytes_raw()
    )
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("pem", [False, True])
def test_offline_publication_signs_exact_canonical_data_without_exposing_key(
    tmp_path: Path, pem: bool
) -> None:
    source, key = seed_file(tmp_path), private_file(tmp_path, pem=pem)
    output = tmp_path / "published"

    def forbidden_fetch(url: str, limit: int) -> bytes:
        pytest.fail("An offline build must not request upstream data")

    result = builder.build_catalog(
        source, "apps-2026-11-08", 1, key, output, fetcher=forbidden_fetch
    )
    raw = (output / "catalog.json").read_bytes()
    bundle = CatalogBundle.model_validate_json(raw)
    provenance = json.loads((output / "catalog.provenance.json").read_bytes())
    public = serialization.load_pem_public_key(provenance["signing_public_key_pem"].encode())
    assert isinstance(public, Ed25519PublicKey)
    public.verify(base64.b64decode((output / "catalog.sig").read_bytes()), raw)
    assert result["catalog_sha256"] == hashlib.sha256(raw).hexdigest()
    assert bundle.entries[0].allow_over_port_deny is False
    assert bundle.entries[0].block_validated is False
    assert provenance["domain_hints"] is None
    assert provenance["capabilities_promoted_by_import"] is False
    assert "DO-NOT-PUBLISH" not in json.dumps(provenance)
    assert "PRIVATE KEY" not in json.dumps(provenance)
    assert source.read_text().startswith('{"entries"')


def test_publication_is_deterministic_and_never_overwrites_a_build(tmp_path: Path) -> None:
    source, key = seed_file(tmp_path), private_file(tmp_path)
    first, second = tmp_path / "first", tmp_path / "second"
    builder.build_catalog(source, "apps-v1", 1, key, first)
    builder.build_catalog(source, "apps-v1", 1, key, second)
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }
    (first / "catalog.json").write_text("PRESERVE-EXISTING")
    with pytest.raises(builder.CatalogBuildError, match="already exist"):
        builder.build_catalog(source, "apps-v2", 2, key, first)
    assert (first / "catalog.json").read_text() == "PRESERVE-EXISTING"


@pytest.mark.parametrize("serial", [0, -1, 2**53])
def test_serial_is_positive_and_bounded(tmp_path: Path, serial: int) -> None:
    with pytest.raises(ValueError):
        builder.build_catalog(
            seed_file(tmp_path), "apps-v1", serial, private_file(tmp_path), tmp_path / "out"
        )


@pytest.mark.parametrize(
    "attack", ["key-permissions", "key-symlink", "input-symlink", "output-symlink"]
)
def test_build_paths_and_signing_key_are_safe(tmp_path: Path, attack: str) -> None:
    source, key, output = seed_file(tmp_path), private_file(tmp_path), tmp_path / "out"
    if attack == "key-permissions":
        key.chmod(0o644)
    elif attack == "key-symlink":
        target = tmp_path / "key-link"
        target.symlink_to(key)
        key = target
    elif attack == "input-symlink":
        target = tmp_path / "input-link"
        target.symlink_to(source)
        source = target
    else:
        directory = tmp_path / "target"
        directory.mkdir()
        output.symlink_to(directory)
    with pytest.raises(builder.CatalogBuildError):
        builder.build_catalog(source, "apps-v1", 1, key, output)


def loader(
    files: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> tuple[builder.DomainHints, list[str]]:
    notice = b"MIT License\nCopyright test-only fixture\nPermission granted\n"
    monkeypatch.setattr(builder, "V2FLY_LICENSE_SHA256", hashlib.sha256(notice).hexdigest())
    pin = builder.SourcePin(
        {name: builder.git_blob_sha1(raw) for name, raw in files.items()}, "inventory-fixture"
    )
    calls = []

    def fetch(url: str, limit: int) -> bytes:
        assert url.startswith(builder.V2FLY_BASE)
        assert limit in (builder.MAX_FILE_BYTES, 16384)
        calls.append(url)
        return (
            notice
            if url.endswith("/LICENSE")
            else files[url.removeprefix(builder.V2FLY_BASE + "data/")]
        )

    return builder.DomainHints(pin, fetch), calls


def test_suffix_import_does_not_broaden_exact_regex_or_qualified_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = b"""# fixture
example.com
domain:service.example.com
full:exact.example.com
regexp:.*evil
keyword:tracking
domain:qualified.example.com @ads
include:qualified @cn
include:child
https://example.com
127.0.0.1
invalid.local
"""
    hints, calls = loader({"root": source, "child": b"child.example.com\n"}, monkeypatch)
    assert hints.domains("root") == {"example.com", "service.example.com", "child.example.com"}
    assert hints.skipped["full"] == 1
    assert hints.skipped["qualified_or_whitespace"] == 2
    assert hints.skipped["regexp"] == hints.skipped["keyword"] == 1
    assert hints.skipped["invalid_domain"] == 2
    assert len(calls) == 2
    hints.domains("root")
    assert len(calls) == 2, "Cached source must not be fetched repeatedly"
    assert hints.files["root"]["sha256"] == hashlib.sha256(source).hexdigest()


def test_family_hints_are_weak_and_capabilities_cannot_be_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hints, _ = loader({"chat": b"chat.example.com\n"}, monkeypatch)
    bundle = CatalogBundle.model_validate(
        {
            "serial": 1,
            "version": "apps-v1",
            "entries": [
                entry(
                    "app.chat",
                    kind="family",
                    children=["app.chat.calls"],
                    domain_provider_refs=["v2fly:chat"],
                ),
                entry("app.chat.calls", parent="app.chat"),
            ],
        }
    )
    result, provenance = builder.add_domain_hints(bundle, hints)
    assert all(row.domains == ["chat.example.com"] for row in result.entries)
    assert all(not row.allow_over_port_deny and not row.block_validated for row in result.entries)
    assert provenance["applications"]["app.chat.calls"]["provider_refs"] == ["chat"]
    notice = "".join(
        value.removeprefix("BEGIN-NOTICE\n").removesuffix("\nEND-NOTICE")
        for key, value in result.sources[-1].items()
        if key.startswith("license_notice_") and key != "license_notice_format"
    )
    assert notice == provenance["license_notice"]
    assert result.sources[-1]["commit"] == builder.V2FLY_COMMIT


def test_hint_limit_is_deterministic_and_omissions_are_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = "\n".join(f"host{index:03}.example.com" for index in range(300)).encode()
    hints, _ = loader({"many": data}, monkeypatch)
    bundle = CatalogBundle.model_validate(
        {
            "serial": 1,
            "version": "v1",
            "entries": [entry("app.test", domain_provider_refs=["v2fly:many"])],
        }
    )
    result, provenance = builder.add_domain_hints(bundle, hints)
    assert len(result.entries[0].domains) == 256
    assert result.entries[0].domains == sorted(result.entries[0].domains)
    assert provenance["applications"]["app.test"]["omitted_above_limit"] == 44


@pytest.mark.parametrize("problem", ["hash", "cycle", "depth", "unknown", "bytes", "file-count"])
def test_invalid_or_unbounded_domain_graphs_are_rejected(
    monkeypatch: pytest.MonkeyPatch, problem: str
) -> None:
    files = {"root": b"include:child\n", "child": b"child.example.com\n"}
    if problem == "cycle":
        files["child"] = b"include:root\n"
    if problem == "unknown":
        files["child"] = b"include:../../passwd\n"
    hints, _ = loader(files, monkeypatch)
    if problem == "hash":
        hints.pin.blobs["root"] = "0" * 40
    if problem == "depth":
        monkeypatch.setattr(builder, "MAX_INCLUDE_DEPTH", 1)
    if problem == "bytes":
        monkeypatch.setattr(builder, "MAX_SOURCE_BYTES", 1)
    if problem == "file-count":
        monkeypatch.setattr(builder, "MAX_SOURCE_FILES", 1)
    with pytest.raises(builder.CatalogBuildError):
        hints.domains("root")


def test_license_mismatch_prevents_publication(monkeypatch: pytest.MonkeyPatch) -> None:
    hints, _ = loader({"root": b"example.com"}, monkeypatch)
    monkeypatch.setattr(builder, "V2FLY_LICENSE_SHA256", "0" * 64)
    with pytest.raises(builder.CatalogBuildError, match="license"):
        hints.license()


def test_only_reviewed_inventory_commit_and_literal_paths_are_allowed(tmp_path: Path) -> None:
    record = {"id": "test-!cn", "path": "data/test-!cn", "git_blob_sha1": "a" * 40}
    source: dict[str, object] = {
        "commit": builder.V2FLY_COMMIT,
        "license": "MIT",
        "license_sha256": builder.V2FLY_LICENSE_SHA256,
        "entries": [record],
    }
    document = {"domain_list_community": source}
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(document))
    assert builder.read_pin(path).blobs == {"test-!cn": "a" * 40}
    source["commit"] = "b" * 40
    path.write_text(json.dumps(document))
    with pytest.raises(builder.CatalogBuildError, match="commit"):
        builder.read_pin(path)
    source["commit"] = builder.V2FLY_COMMIT
    record["path"] = "../../secret"
    path.write_text(json.dumps(document))
    with pytest.raises(builder.CatalogBuildError, match="Unsafe"):
        builder.read_pin(path)


def test_arbitrary_urls_and_redirects_cannot_replace_source_pins() -> None:
    with pytest.raises(builder.CatalogBuildError, match="fixed"):
        builder.fetch_source("http://127.0.0.1/private", 10)
    with pytest.raises(builder.CatalogBuildError, match="redirects"):
        builder.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.org")  # type: ignore[arg-type]
