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


def full_loader(
    files: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> tuple[builder.DomainHints, dict[str, object]]:
    hints, _ = loader(files, monkeypatch)
    hints.full_catalog = True
    declarations = [
        {"engine_id": 2, "symbol": "NDPI_PROTOCOL_MAIL_POP"},
        {"engine_id": 7, "symbol": "NDPI_PROTOCOL_HTTP"},
        {"engine_id": 99, "symbol": "NDPI_PROTOCOL_ALPHA"},
    ]
    object.__setattr__(hints.pin, "ndpi", {"entries": declarations, "commit": "a" * 40})
    capabilities: dict[str, object] = {
        "engine": {"name": "ndpi", "commit": builder.NDPI_COMMIT},
        "protocols": [
            {"id": 2, "name": "POP3"},
            {"id": 7, "name": "HTTP"},
            {"id": 99, "name": "Alpha"},
        ],
    }
    return hints, capabilities


def test_full_source_import_deduplicates_identities_without_promoting_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hints, capabilities = full_loader(
        {
            "alpha": b"alpha.example.com\ninclude:beta\n",
            "beta": b"beta.example.com\n",
            "category-social": b"include:alpha\n",
            "legacy": b"include:beta\n",
            "cloudflare": b"cloudflare.example.com\n",
        },
        monkeypatch,
    )
    initial = CatalogBundle.model_validate(
        {"serial": 1, "version": "full-v1", "entries": [entry("app.keep")]}
    )
    result, report = builder.full_catalog(initial, hints, capabilities)
    by_id = {row.id: row for row in result.entries}
    alpha = by_id["app.ndpi.alpha"]
    assert alpha.kind == "application"
    assert alpha.domains == ["alpha.example.com"], (
        "Umbrella includes must not become owned suffixes"
    )
    assert alpha.engine_mapping and alpha.engine_mapping.protocol_name == "Alpha"
    assert by_id["app.ndpi.mail_pop"].engine_mapping.protocol_name == "POP3"  # type: ignore[union-attr]
    assert by_id["app.v2fly.category-social"].kind == "category"
    assert by_id["app.v2fly.cloudflare"].kind == "provider"
    assert by_id["app.v2fly.beta"].domain_provider_refs == ["v2fly:beta", "v2fly:legacy"]
    assert "app.v2fly.legacy" not in by_id and report["aliases"]["legacy"] == "app.v2fly.beta"
    assert "app.keep" in by_id
    assert all(not row.allow_over_port_deny and not row.block_validated for row in result.entries)
    assert report["source_lists"] == 5 and report["added_ndpi_declarations"] == 3
    assert report["capabilities_promoted_by_import"] is False


def test_full_import_requires_reviewed_engine_and_explicit_source_limit_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hints, capabilities = full_loader({"alpha": b"alpha.example.com\n"}, monkeypatch)
    initial = CatalogBundle.model_validate(
        {"serial": 1, "version": "full-v1", "entries": [entry("app.keep")]}
    )
    hints.full_catalog = False
    with pytest.raises(builder.CatalogBuildError, match="explicit"):
        builder.full_catalog(initial, hints, capabilities)
    hints.full_catalog = True
    capabilities["engine"] = {"name": "ndpi", "commit": "0" * 40}
    with pytest.raises(builder.CatalogBuildError, match="pinned"):
        builder.full_catalog(initial, hints, capabilities)
    capabilities["engine"] = {"name": "ndpi", "commit": builder.NDPI_COMMIT}
    capabilities["protocols"] = [{"id": 2, "name": "POP3"}]
    with pytest.raises(builder.CatalogBuildError, match="every pinned"):
        builder.full_catalog(initial, hints, capabilities)


def test_full_source_limit_preserves_primary_suffix_and_reports_omissions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b"google.com\n" + b"\n".join(f"host{i}.example.com".encode() for i in range(100))
    hints, capabilities = full_loader({"google": raw}, monkeypatch)
    initial = CatalogBundle.model_validate(
        {"serial": 1, "version": "full-v1", "entries": [entry("app.keep")]}
    )
    result, report = builder.full_catalog(initial, hints, capabilities)
    google = next(row for row in result.entries if row.id == "app.v2fly.google")
    assert len(google.domains) == 64 and "google.com" in google.domains
    assert report["entries"]["google"]["omitted_above_limit"] == 37
    assert report["truncated_source_lists"] == 1


def test_source_ids_are_stable_bounded_and_distinguish_negated_region_tags() -> None:
    for value in ("category-ai-!cn", "a" * 100, "long-" * 20):
        identifier = builder.source_id("v2fly", value)
        assert len(identifier) <= 80 and identifier == builder.source_id("v2fly", value)
    assert builder.source_id("v2fly", "category-ai-!cn") != builder.source_id(
        "v2fly", "category-ai-cn"
    )


def test_local_source_cache_is_pinned_and_cannot_follow_links(tmp_path: Path) -> None:
    root = tmp_path / "source"
    (root / "data").mkdir(parents=True)
    (root / "data/test").write_bytes(b"example.com\n")
    fetch = builder.local_source_fetcher(root)
    assert fetch(builder.V2FLY_BASE + "data/test", 100) == b"example.com\n"
    with pytest.raises(builder.CatalogBuildError, match="Unsafe"):
        fetch(builder.V2FLY_BASE + "data/../../secret", 100)
    (root / "data/link").symlink_to(root / "data/test")
    with pytest.raises(builder.CatalogBuildError, match="links"):
        fetch(builder.V2FLY_BASE + "data/link", 100)


def kagi_data(
    rows: list[dict[str, object]], monkeypatch: pytest.MonkeyPatch
) -> tuple[bytes, bytes]:
    raw = json.dumps(rows).encode()
    notice = b"MIT License\nCopyright fixture\nPermission granted\n"
    monkeypatch.setattr(builder, "KAGI_DATA_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(builder, "KAGI_LICENSE_SHA256", hashlib.sha256(notice).hexdigest())
    return raw, notice


def kagi_row(host: str, name: str = "Named Service", **extra: object) -> dict[str, object]:
    return {"d": host, "s": name, "u": f"https://{host}/search?q={{{{s}}}}", "c": "Tech", **extra}


def test_kagi_named_websites_preserve_base_and_merge_host_aliases_without_apex_guessing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = CatalogBundle.model_validate(
        {
            "version": "v1",
            "serial": 1,
            "entries": [
                entry(
                    "app.base",
                    domains=["already.example.com"],
                    block_validated=True,
                    allow_over_port_deny=True,
                )
            ],
        }
    )
    raw, notice = kagi_data(
        [
            kagi_row("www.alpha.example.com", "Alpha    Tools"),
            kagi_row("alpha.example.com", "Alpha", c="Online Services"),
            kagi_row("www.beta.example.com", "Beta", ad="example.com"),
            kagi_row("child.already.example.com", "Covered"),
            kagi_row("notalready.example.com", "Different DNS label"),
            kagi_row("tenant.github.io", "Tenant docs"),
            kagi_row("ignored.example.com", "News", c="News"),
        ],
        monkeypatch,
    )
    result, report = builder.add_kagi_web_services(base, raw, notice)
    assert result.entries[:1] == base.entries
    by_id = {row.id: row for row in result.entries}
    alpha = by_id["app.kagi.alpha.example.com"]
    assert alpha.domains == ["alpha.example.com", "www.alpha.example.com"]
    assert alpha.name.en == "Alpha"
    assert by_id["app.kagi.beta.example.com"].domains == ["www.beta.example.com"]
    assert by_id["app.kagi.tenant.github.io"].domains == ["tenant.github.io"]
    assert "app.kagi.notalready.example.com" in by_id
    assert report["added_named_web_services"] == 4
    assert report["skipped_rows"]["covered_by_existing_suffix"] == 1
    assert report["merged_display_aliases"] == 1
    assert all(
        not row.block_validated and not row.allow_over_port_deny for row in result.entries[1:]
    )
    assert all("not installed-app or DPI" in row.coverage for row in result.entries[1:])
    assert all(row.category == "web-services" for row in result.entries[1:])
    rebuilt, _ = builder.add_kagi_web_services(base, raw, notice)
    assert rebuilt == result


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "host.local",
        "host.invalid",
        "127.0.0.1",
        "127.1",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "co.uk",
        "github.io",
        "readthedocs.io",
    ],
)
def test_kagi_rejects_local_ip_and_known_namespace_roots(host: str) -> None:
    with pytest.raises(ValueError):
        builder.public_hostname(host)


@pytest.mark.parametrize(
    "name",
    ["bad\nname", "bad\x85name", "bad\u202ename", "bad\u200bname", "bad\u034fname", "x" * 129],
)
def test_kagi_rejects_control_bidi_invisible_or_overlong_names(name: str) -> None:
    with pytest.raises(ValueError):
        builder.website_name(name)


def test_kagi_collapses_unicode_whitespace_and_validates_url_hostname_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert builder.website_name("  Named\u00a0\u2002Service   ") == "Named Service"
    base = CatalogBundle.model_validate(
        {"version": "v1", "serial": 1, "entries": [entry("app.base")]}
    )
    raw, notice = kagi_data(
        [
            kagi_row("one.example.com", u="https://one.example.com.evil.test/search"),
            kagi_row("two.example.com", u="javascript:alert(1)"),
            kagi_row("three.example.com", u="https://user:pass@three.example.com/search"),
            kagi_row("four.example.com", "Nice\u202eName"),
            kagi_row("valid.example.com", u="https://search.valid.example.com/search"),
        ],
        monkeypatch,
    )
    result, report = builder.add_kagi_web_services(base, raw, notice)
    assert len(result.entries) == 2 and result.entries[-1].domains == ["valid.example.com"]
    assert report["skipped_rows"]["invalid_or_conflicting_hostname"] == 4


def test_kagi_hash_license_collision_and_policy_bounds_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = CatalogBundle.model_validate(
        {"version": "v1", "serial": 1, "entries": [entry("app.base")]}
    )
    raw, notice = kagi_data([kagi_row("new.example.com")], monkeypatch)
    with pytest.raises(builder.CatalogBuildError, match="data hash"):
        builder.add_kagi_web_services(base, raw + b" ", notice)
    with pytest.raises(builder.CatalogBuildError, match="license hash"):
        builder.add_kagi_web_services(base, raw, notice + b" ")
    monkeypatch.setattr(builder, "MAX_PRIVATE_IDENTITIES", 1)
    with pytest.raises(builder.CatalogBuildError, match="4096"):
        builder.add_kagi_web_services(base, raw, notice)
    monkeypatch.setattr(builder, "MAX_PRIVATE_IDENTITIES", 4096)
    collision = CatalogBundle.model_validate(
        {"version": "v1", "serial": 1, "entries": [entry("app.kagi.new.example.com")]}
    )
    with pytest.raises(builder.CatalogBuildError, match="collides"):
        builder.add_kagi_web_services(collision, raw, notice)
