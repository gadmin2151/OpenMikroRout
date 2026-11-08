"""Application policy is opt-in, bounded, source-scoped and never globally accepts."""

import base64
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.application_catalog import CATALOG_URL, ApplicationCatalog, CatalogBundle
from app.application_guard import main as guard_main
from app.application_guard import quarantine_patch
from app.application_integrity import native_inventory
from app.application_models import ApplicationConfiguration, ApplicationRule
from app.application_policy import (
    APP_CHAIN,
    CT_MASK,
    CT_PENDING,
    CT_VALID,
    EPOCH_SHIFT,
    denial_chain,
    denial_rules,
    guard_rules,
    queue_patch,
    resolve_policy,
)
from app.application_runtime import ApplicationRuntime, atomic_json
from app.filtering import EMPTY_FILTER, DemoFilterDriver, compiled_filters, filter_patch
from app.firewall import DemoDriver, FirewallService
from app.links import DemoLinkDriver
from app.main import Settings, create_app
from app.models import Configuration, FilterRule
from app.networking import DemoNetworkDriver
from app.rsc import export_rsc, import_rsc
from app.runtime import RouterRuntime
from app.storage import Store

HEADERS = {"X-NAT-Request": "1"}


def enabled(mode: str = "enforce") -> Configuration:
    return Configuration.model_validate(
        {
            "applications": {
                "enabled": True,
                "mode": mode,
                "interfaces": ["lan0"],
                "source_networks": ["192.0.2.0/24"],
            }
        }
    )


def catalog(directory: Path) -> ApplicationCatalog:
    return ApplicationCatalog(directory)


def test_defaults_legacy_and_rsc_roundtrip() -> None:
    old = Configuration.model_validate({"rules": []})
    assert not old.applications.enabled
    cfg = enabled("observe")
    cfg.applications.rules = [
        ApplicationRule(name="Observe BT", application_ids=["app.bittorrent"])
    ]
    assert import_rsc(export_rsc(cfg)).model_dump() == cfg.model_dump()


@pytest.mark.parametrize(
    "changes",
    [
        {"enabled": True},
        {"source_networks": ["0.0.0.0/0"]},
        {"interfaces": ["lan0;reboot"]},
        {"max_pending": 2049},
        {"max_pending": 2, "max_pending_per_client": 3},
        {"source_networks": ["::/0"]},
    ],
)
def test_settings_reject_unsafe_or_unbounded_scope(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ApplicationConfiguration.model_validate(changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"action": "allow", "connection_states": ["NEW"]},
        {"connection_states": ["INVALID"]},
        {"src_address": "192.0.2.1", "src_list": "clients"},
        {"application_ids": ["--exec"]},
    ],
)
def test_rule_is_typed(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ApplicationRule.model_validate(
            {"name": "Rule", "application_ids": ["app.bittorrent"], **changes}
        )


def test_skip_only_eligible_port_denial_preserves_later_guard_and_no_global_accept() -> None:
    cfg = enabled()
    eligible = FilterRule(
        name="Port deny",
        chain="forward",
        action="drop",
        protocol="tcp",
        dst_ports="443",
        application_override_eligible=True,
    )
    later = FilterRule(name="Address deny", chain="forward", action="drop", src_address="192.0.2.3")
    cfg.filter_rules = [eligible, later]
    ordinary = compiled_filters(cfg, 12)
    assert ordinary[0].endswith("-j " + denial_chain(eligible))
    assert "-s 192.0.2.3" in ordinary[1] and ordinary[1].endswith("-j DROP")
    exceptions = denial_rules(cfg, 12)
    assert len(exceptions) == 13 and all("-j ACCEPT" not in line for line in exceptions)
    assert sum(line.endswith("-j RETURN") for line in exceptions) == 12
    assert exceptions[-1].endswith("-j DROP")
    assert compiled_filters(cfg)[0].endswith("-j DROP")
    payload = filter_patch(EMPTY_FILTER, cfg, application_epoch=12)
    assert "--ctdir REPLY --ctorigsrc 192.0.2.0/24" in payload
    assert "-I FORWARD 1" in payload


@pytest.mark.parametrize(
    "changes",
    [
        {"chain": "input"},
        {"action": "accept"},
        {"protocol": "any"},
        {"dst_ports": ""},
        {"negate": ["dst_ports"]},
        {"src_country": ["US"]},
    ],
)
def test_port_exception_rejects_non_eligible_security_rules(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        FilterRule.model_validate(
            {
                "name": "deny",
                "chain": "forward",
                "protocol": "tcp",
                "dst_ports": "443",
                "action": "drop",
                "application_override_eligible": True,
                **changes,
            }
        )


def test_quarantine_only_owned_chain_and_queue_no_fail_open() -> None:
    cfg = enabled()
    assert quarantine_patch(EMPTY_FILTER, Configuration()) is None
    patch_script = quarantine_patch(EMPTY_FILTER, cfg)
    assert patch_script is not None
    assert ":OMR_APP_FORWARD " in patch_script and ":OMR_FORWARD " not in patch_script
    assert "-j DROP" in patch_script and "-j ACCEPT" not in patch_script
    mangle = "*mangle\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
    queue = queue_patch(mangle, cfg, 5)
    assert "--queue-num 5089" in queue and "queue-bypass" not in queue
    assert "--mark 0x540/0xffffc0" in queue
    assert "-j MARK" not in queue and "-j CONNMARK" not in queue
    assert "NFQUEUE" not in queue_patch(mangle, cfg, None)
    with pytest.raises(ValueError, match="incompatible"):
        queue_patch(mangle.replace("COMMIT", "-A FORWARD -j ACCEPT\nCOMMIT"), cfg, 1)
    with pytest.raises(ValueError, match="connmark"):
        queue_patch(
            mangle.replace("COMMIT", "-A POSTROUTING -j CONNMARK --save-mark\nCOMMIT"), cfg, 1
        )


def test_guard_profile_state_and_stale_marks_are_fail_closed() -> None:
    rows = guard_rules(enabled(), 8)
    assert all("-j ACCEPT" not in row for row in rows)
    assert any("! --mark 0x840/0xffff40" in row for row in rows)
    for state in ("NEW", "ESTABLISHED", "RELATED"):
        assert any("--ctstate " + state in row and row.endswith("-j DROP") for row in rows)
    assert any("INVALID,UNTRACKED" in row for row in rows)


def signed_bundle(directory: Path) -> tuple[ApplicationCatalog, Ed25519PrivateKey, bytes]:
    store = catalog(directory)
    bundle = store.bundle("seed-2026-11-08").model_copy(update={"serial": 1, "version": "data-1"})
    key = Ed25519PrivateKey.generate()
    return store, key, bundle.model_dump_json().encode()


def test_signed_catalog_bound_purpose_forward_serial_and_immutable_version(tmp_path: Path) -> None:
    store, key, raw = signed_bundle(tmp_path)
    with pytest.raises(InvalidSignature):
        store.import_signed(raw + b" ", key.sign(raw), key.public_key().verify)
    assert store.import_signed(raw, key.sign(raw), key.public_key().verify).version == "data-1"
    assert store.import_signed(raw, key.sign(raw), key.public_key().verify).serial == 1
    changed = CatalogBundle.model_validate_json(raw).model_copy(update={"serial": 2})
    altered = changed.model_dump_json().encode()
    with pytest.raises(ValueError, match="immutable"):
        store.import_signed(altered, key.sign(altered), key.public_key().verify)
    changed = changed.model_copy(update={"version": "stale", "serial": 1})
    altered = changed.model_dump_json().encode()
    with pytest.raises(ValueError, match="replay"):
        store.import_signed(altered, key.sign(altered), key.public_key().verify)
    document = json.loads(raw)
    document.pop("purpose")
    altered = json.dumps(document).encode()
    with pytest.raises(ValueError, match="purpose"):
        store.import_signed(altered, key.sign(altered), key.public_key().verify)


def test_catalog_sync_fixed_channel_stage_only(tmp_path: Path) -> None:
    store, key, raw = signed_bundle(tmp_path)
    public = tmp_path / "catalog.pem"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    store.public_key = public
    with patch.object(
        store, "download", side_effect=[raw, base64.b64encode(key.sign(raw))]
    ) as request:
        store.sync(True)
        assert store.worker
        store.worker.join(3)
    assert store.status("seed-2026-11-08")["active_version"] == "seed-2026-11-08"
    assert store.job and store.job["phase"] == "completed"
    assert request.call_args_list[0].args[0] == CATALOG_URL
    assert store.bundle("data-1").serial == 1
    with pytest.raises(ValueError, match="Untrusted"):
        store.download("https://127.0.0.1/catalog", 200)


def test_catalog_does_not_promote_native_port_guess_or_unproved_allow(tmp_path: Path) -> None:
    store = catalog(tmp_path)
    caps = {
        "available": True,
        "enforce": False,
        "engine": {"name": "ndpi", "version": "6.0.0"},
        "protocols": [{"name": "BitTorrent", "id": 999}],
    }
    entries = store.entries("seed-2026-11-08", caps)
    bt = next(row for row in entries if row["id"] == "app.bittorrent")
    assert bt["observable"] and not bt["block_validated"] and not bt["allow_over_port_deny"]
    assert bt["protocol_names"] == ["BitTorrent"]
    cfg = enabled()
    cfg.applications.rules = [
        ApplicationRule(name="Allow BT", action="allow", application_ids=["app.bittorrent"])
    ]
    with pytest.raises(ValueError, match="validated"):
        resolve_policy(cfg, entries, 1)


def test_disabled_runtime_no_process_no_mangle_and_stop_guard_noop(tmp_path: Path) -> None:
    cfg = Configuration()
    runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), demo=True)
    runtime.apply(cfg)
    assert runtime.process is None and not runtime.status()["healthy"]
    Store(tmp_path / "linux.sqlite3", cfg)
    with patch(
        "app.application_guard.LinuxFilterDriver", side_effect=AssertionError("host touched")
    ):
        assert guard_main(["--data-dir", str(tmp_path)]) == 0
    router = RouterRuntime(
        DemoNetworkDriver(cfg.network),
        DemoLinkDriver(cfg.network),
        DemoFilterDriver(cfg),
        applications=runtime,
    )
    with patch.object(runtime, "mangle_snapshot", side_effect=AssertionError("host touched")):
        router.check(cfg, cfg)
        router.apply(cfg, cfg)
        router.shutdown_applications()


def test_service_security_dirty_requires_application_mfa_review(tmp_path: Path) -> None:
    cfg = Configuration()
    service = FirewallService(Store(tmp_path / "router.sqlite3", cfg), DemoDriver(cfg))
    target = enabled("observe")
    service.save(target, 0)
    assert service.state()["security_dirty"]


def test_runtime_epoch_durable_and_kernel_proof_cannot_be_reused(tmp_path: Path) -> None:
    store = catalog(tmp_path)
    executable = tmp_path / "native/bin/omr-app-supervisor"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 1\n")
    executable.chmod(0o700)
    files = {"bin/omr-app-supervisor": hashlib.sha256(executable.read_bytes()).hexdigest()}
    (executable.parent.parent / "manifest.json").write_text(
        json.dumps(
            {
                "format": 1,
                "purpose": "OpenMikroRout native companion",
                "platform": "linux-amd64",
                "files": files,
            }
        )
    )
    inventory = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    runtime = ApplicationRuntime(tmp_path, store, binary=executable)
    caps = {
        "schema": 1,
        "available": True,
        "observe": True,
        "enforce": True,
        "ct_mask": CT_MASK,
        "ct_valid_bit": CT_VALID,
        "ct_pending_bit": CT_PENDING,
        "ct_epoch_shift": EPOCH_SHIFT,
        "ct_metadata": "NFQA_CT/CTA_MARK_MASK",
        "engine": {"name": "ndpi"},
        "protocols": [{"name": "BitTorrent"}],
    }
    with (
        patch.object(runtime, "_command", return_value=caps),
        patch(
            "app.application_runtime.native_inventory",
            side_effect=lambda binary: native_inventory(binary, owner=os.getuid()),
        ),
        patch("app.third_party_license.load_acceptance", return_value={"profile": "lgpl-only"}),
    ):
        assert not runtime.capabilities()["enforce"]
        atomic_json(
            store.directory / "kernel-proof.json",
            {
                "schema": 1,
                "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "native_inventory_sha256": inventory,
                "engine_license_profile": "lgpl-only",
                "kernel_release": os.uname().release,
                "first_syn": True,
                "mask_preservation": True,
                "failure_recovery": True,
                "application_block": True,
                "application_allow": True,
            },
        )
        runtime.capabilities_at = 0
        assert runtime.capabilities()["enforce"]
        first = runtime.epoch_for(enabled())
        assert first is not None
        second_runtime = ApplicationRuntime(tmp_path, store, binary=executable)
        with patch.object(second_runtime, "capabilities", return_value=runtime.capabilities()):
            assert second_runtime.epoch_for(enabled()) == first + 1
        executable.write_text("#!/bin/sh\nexit 2\n")
        runtime.capabilities_at = 0
        assert not runtime.capabilities()["enforce"]


def test_api_auth_readonly_and_no_simulated_detection(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            data_dir=tmp_path,
            auth_enabled=True,
            password="test-admin-password-123",
            read_password="test-reader-password-123",
        )
    )
    with TestClient(app) as client:
        assert client.get("/api/applications/status").status_code == 401
        assert (
            client.post(
                "/api/login",
                headers=HEADERS,
                json={"username": "viewer", "password": "test-reader-password-123"},
            ).status_code
            == 200
        )
        assert client.get("/api/applications/status").json()["demo"]
        assert client.get("/api/applications/catalog").json()["total"] > 10
        result = client.get("/api/applications/connections").json()
        assert result["items"] == [] and result["counters_scope"] == "analyzed"
        assert client.post("/api/applications/catalog/download", headers=HEADERS).status_code == 403
        assert (
            client.get(
                "/api/applications/connections",
                params={"expression": '{"kind":"condition","field":"shell","op":"eq","value":"x"}'},
            ).status_code
            == 422
        )


def test_observe_apply_rollback_preserves_every_existing_router_rule(tmp_path: Path) -> None:
    initial = Configuration(
        filter_rules=[FilterRule(name="Protect host", chain="input", action="drop")]
    )
    app_runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), demo=True)
    router = RouterRuntime(
        DemoNetworkDriver(initial.network),
        DemoLinkDriver(initial.network),
        DemoFilterDriver(initial),
        applications=app_runtime,
    )
    service = FirewallService(
        Store(tmp_path / "router.sqlite3", initial), DemoDriver(initial), runtime=router
    )
    before = router.filters.snapshot()
    target = initial.model_copy(deep=True)
    target.applications = enabled("observe").applications
    service.save(target, 0)
    with patch.object(app_runtime, "mangle_snapshot", side_effect=AssertionError("host touched")):
        service.apply(1)
        assert app_runtime.config.applications.enabled
        assert not app_runtime.status()["healthy"]
        service.rollback()
    assert not app_runtime.config.applications.enabled
    assert sorted(router.filters.snapshot().splitlines()) == sorted(before.splitlines())
    assert (
        service.store.read("applied")["filter_rules"]
        == initial.model_dump(mode="json")["filter_rules"]
    )


def test_engine_failure_quarantines_before_stopping_worker(tmp_path: Path) -> None:
    cfg = enabled()
    app_runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), demo=True)
    app_runtime.config = cfg
    filters = DemoFilterDriver(cfg)
    filters.restore(filter_patch(filters.snapshot(), cfg, application_epoch=7))
    router = RouterRuntime(
        DemoNetworkDriver(cfg.network),
        DemoLinkDriver(cfg.network),
        filters,
        applications=app_runtime,
    )

    def stop_after_guard() -> None:
        rows = filters.snapshot().splitlines()
        guard = [row for row in rows if row.startswith("-A " + APP_CHAIN + " ")]
        assert any("--ctdir ORIGINAL" in row and row.endswith("-j DROP") for row in guard)
        assert not any("--mark" in row for row in guard)

    with patch.object(app_runtime, "stop", side_effect=stop_after_guard) as stop:
        router.maintain()
        router.maintain()
    stop.assert_called_once()
    assert router.applications_failed
    assert "quarantined" in app_runtime.error


def test_no_kernel_commands_are_run_without_enforcement_license(tmp_path: Path) -> None:
    executable = tmp_path / "companion"
    executable.write_text("#!/bin/sh\nexit 1\n")
    executable.chmod(0o700)
    app_runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), binary=executable)
    from app.third_party_license import LicenseError

    with (
        patch("app.third_party_license.load_acceptance", side_effect=LicenseError("not accepted")),
        patch.object(
            app_runtime, "_command", side_effect=AssertionError("unaccepted native launch")
        ),
    ):
        assert not app_runtime.capabilities()["available"]
        app_runtime.apply(enabled("observe"))
        assert app_runtime.process is None
        assert not app_runtime.status()["healthy"]


def test_native_profiles_cannot_claim_first_packet_new_only_blocking(tmp_path: Path) -> None:
    caps = {
        "available": True,
        "enforce": True,
        "allow_over_port_deny": True,
        "protocols": [{"name": "BitTorrent"}],
    }
    entries = catalog(tmp_path).entries("seed-2026-11-08", caps)
    cfg = enabled()
    cfg.applications.rules = [
        ApplicationRule(
            name="NEW only", application_ids=["app.bittorrent"], connection_states=["NEW"]
        )
    ]
    with pytest.raises(ValueError, match="first-packet"):
        resolve_policy(cfg, entries, 8)


@pytest.mark.parametrize("change", ["port", "source", "order"])
def test_eligible_rule_contents_and_position_require_security_review(
    tmp_path: Path, change: str
) -> None:
    eligible = FilterRule(
        name="Port deny",
        chain="forward",
        action="drop",
        protocol="tcp",
        dst_ports="443",
        application_override_eligible=True,
    )
    guard = FilterRule(name="IP guard", chain="forward", action="drop", src_address="192.0.2.3")
    initial = Configuration(filter_rules=[eligible, guard])
    service = FirewallService(Store(tmp_path / "router.sqlite3", initial), DemoDriver(initial))
    target = initial.model_copy(deep=True)
    if change == "port":
        target.filter_rules[0].dst_ports = "8443"
    elif change == "source":
        target.filter_rules[0].src_address = "198.51.100.0/24"
    else:
        target.filter_rules.reverse()
    service.save(target, 0)
    assert service.state()["security_dirty"]


@pytest.mark.parametrize("reference", ["address", "interface"])
def test_application_scope_list_membership_cannot_bypass_mfa(
    tmp_path: Path, reference: str
) -> None:
    from app.models import AddressList
    from app.network_models import InterfaceList, NetworkConfiguration

    initial = Configuration(
        address_lists=[AddressList(name="clients", addresses=["192.0.2.1"])],
        network=NetworkConfiguration(interface_lists=[InterfaceList(name="LAN", members=["lan0"])]),
    )
    initial.applications.rules = [
        ApplicationRule(
            name="Allow BT",
            action="allow",
            application_ids=["app.bittorrent"],
            src_list="clients",
            in_interface_list="LAN",
        )
    ]
    service = FirewallService(Store(tmp_path / "router.sqlite3", initial), DemoDriver(initial))
    target = initial.model_copy(deep=True)
    if reference == "address":
        target.address_lists[0].addresses = ["192.0.2.0/24"]
    else:
        target.network.interface_lists[0].members = ["lan0", "lan1"]
    service.save(target, 0)
    assert service.state()["security_dirty"]


def test_unsupported_protocols_never_enter_application_queue_or_guard() -> None:
    config = enabled()
    mangle = "*mangle\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
    payload = queue_patch(mangle, config, 7)
    for line in payload.splitlines():
        if line.startswith("-A OMR_APP_QUEUE "):
            assert "-p tcp " in line or "-p udp " in line
    for epoch in (None, 7):
        for line in guard_rules(config, epoch):
            if line.endswith("-j DROP"):
                assert "-p tcp " in line or "-p udp " in line
    assert "-p icmp" not in payload


@pytest.mark.parametrize("dependency", ["nat", "routes", "engine", "license"])
def test_nat_routing_and_engine_dependencies_invalidate_flow_epoch(
    tmp_path: Path, dependency: str
) -> None:
    from app.models import NatRule
    from app.network_models import StaticRoute

    runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), demo=True)
    caps = {
        "available": False,
        "engine": {"version": "6.0"},
        "protocols": [],
        "license_profile": "lgpl-only",
        "binary_sha256": "a" * 64,
    }
    first_config = enabled("observe")
    with patch.object(runtime, "capabilities", return_value=caps):
        first = runtime.policy_for(first_config)
        target = first_config.model_copy(deep=True)
        if dependency == "nat":
            target.rules = [
                NatRule(
                    name="DNAT",
                    chain="dstnat",
                    action="dst-nat",
                    protocol="tcp",
                    dst_ports="443",
                    to_address="198.51.100.5",
                )
            ]
        elif dependency == "routes":
            target.network.routes = [StaticRoute(destination="203.0.113.0/24", gateway="192.0.2.2")]
        elif dependency == "engine":
            caps["binary_sha256"] = "b" * 64
        else:
            caps["license_profile"] = "not-for-profit"
        second = runtime.policy_for(target)
    assert second["epoch"] != first["epoch"]
    assert second["generation"] != first["generation"]


def test_interface_scoped_rules_queue_every_packet_for_current_route_recheck() -> None:
    from app.application_policy import reevaluate_interfaces

    config = enabled()
    mangle = "*mangle\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
    assert not reevaluate_interfaces(config)
    assert "application-final" in queue_patch(mangle, config, 7)
    config.applications.rules = [
        ApplicationRule(name="Only WAN0", application_ids=["app.bittorrent"], out_interface="wan0")
    ]
    assert reevaluate_interfaces(config)
    queued = queue_patch(mangle, config, 7)
    assert "application-final" not in queued and "NFQUEUE" in queued
    config.applications.rules[0].enabled = False
    assert "application-final" in queue_patch(mangle, config, 7)


def test_port_override_returns_cannot_escape_original_global_client_scope() -> None:
    config = enabled()
    config.filter_rules = [
        FilterRule(
            name="HTTPS",
            action="drop",
            protocol="tcp",
            dst_ports="443",
            application_override_eligible=True,
        )
    ]
    rows = denial_rules(config, 7)
    for row in rows:
        if row.endswith("-j RETURN"):
            assert "-p tcp" in row and "--ctorigsrc 192.0.2.0/24" in row
            assert "-i lan0" in row or "-o lan0" in row
            assert "--ctdir ORIGINAL" in row or "--ctdir REPLY" in row


def test_expected_child_cannot_fastpath_inherited_parent_allow_mark() -> None:
    mangle = "*mangle\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
    rows = queue_patch(mangle, enabled(), 7).splitlines()
    fastpaths = [row for row in rows if "application-final" in row]
    assert fastpaths
    for row in fastpaths:
        assert "--ctstate NEW,ESTABLISHED" in row
        assert "! --ctstatus EXPECTED" in row
    assert any("-j NFQUEUE" in row and "--ctstatus" not in row for row in rows)


def test_expanded_scope_exceptions_obey_global_compiled_rule_budget() -> None:
    config = enabled().model_dump(mode="json")
    config["applications"]["interfaces"] = [f"lan{index}" for index in range(16)]
    config["applications"]["source_networks"] = [
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.0.0.0/24",
    ]
    config["filter_rules"] = [
        FilterRule(
            name=f"Port{index}",
            action="drop",
            protocol="tcp",
            dst_ports="443",
            application_override_eligible=True,
        ).model_dump(mode="json")
        for index in range(4)
    ]
    with pytest.raises(ValueError, match="4096"):
        Configuration.model_validate(config)


@pytest.mark.parametrize(
    "mode,counter_source,interface_basis",
    [
        ("observe", "capture", "capture"),
        ("enforce", "classification", "netfilter"),
    ],
)
def test_monitor_accepts_actual_native_counter_and_interface_contract(
    tmp_path: Path,
    mode: str,
    counter_source: str,
    interface_basis: str,
) -> None:
    runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), demo=True)
    generation = "a" * 64
    atomic_json(
        runtime.directory / "flows.json",
        {
            "schema": 1,
            "generation": generation,
            "items": [
                {
                    "id": "flow-1",
                    "application_id": "app.bittorrent",
                    "source": "192.0.2.2",
                    "destination": "198.51.100.4",
                    "source_port": 50000,
                    "destination_port": 443,
                    "protocol": "tcp",
                    "in_interface": "lan0",
                    "out_interface": "wan0",
                    "connection_state": "UNKNOWN" if mode == "observe" else "ESTABLISHED",
                    "classification_state": "detected",
                    "decision": "fallback",
                    "counters_complete": False,
                    "counter_source": counter_source,
                    "interface_basis": interface_basis,
                    "first_seen": 1794160000.0,
                    "last_seen": 1794160001.0,
                }
            ],
        },
    )
    with patch.object(
        runtime, "status", return_value={"healthy": True, "generation": generation, "error": ""}
    ):
        result = runtime.connections()
    assert result["available"] and result["total"] == 1
    assert result["items"][0]["counter_source"] == counter_source
    assert result["items"][0]["interface_basis"] == interface_basis
    assert result["counters_scope"] == "analyzed"


def test_epoch_registry_survives_stock_data_restore_namespace(tmp_path: Path) -> None:
    runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), demo=True)
    first = runtime.policy_for(enabled("observe"))["epoch"]
    assert runtime.epoch_registry == tmp_path / "updates/application-epoch.json"
    # An older application directory snapshot must never move the independent
    # monotonic high-water mark backwards during update rollback.
    atomic_json(runtime.directory / "epoch.json", {"last": 0})
    restarted = ApplicationRuntime(tmp_path, runtime.catalog, demo=True)
    second = restarted.policy_for(enabled("observe"))["epoch"]
    assert second > first


def test_complete_native_inventory_binds_dso_and_rejects_path_or_mode_changes(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "native/bin/omr-app-supervisor"
    library = tmp_path / "native/lib/libndpi.so.6"
    binary.parent.mkdir(parents=True)
    library.parent.mkdir()
    binary.write_bytes(b"isolated executable fixture")
    library.write_bytes(b"isolated library fixture")
    files = {
        "bin/omr-app-supervisor": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "lib/libndpi.so.6": hashlib.sha256(library.read_bytes()).hexdigest(),
    }
    manifest = {
        "format": 1,
        "purpose": "OpenMikroRout native companion",
        "platform": "linux-amd64",
        "files": files,
    }
    path = binary.parent.parent / "manifest.json"
    path.write_text(json.dumps(manifest))
    inventory, actual = native_inventory(binary, owner=os.getuid())
    assert (
        inventory
        == hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert set(actual) == {binary, library}
    library.write_bytes(b"altered library but identical manifest")
    with pytest.raises(ValueError, match="hash mismatch"):
        native_inventory(binary, owner=os.getuid())
    library.unlink()
    library.symlink_to(binary)
    with pytest.raises(ValueError, match="symbolic"):
        native_inventory(binary, owner=os.getuid())
    library.unlink()
    library.write_bytes(b"isolated library fixture")
    library.chmod(0o666)
    with pytest.raises(ValueError, match="ownership"):
        native_inventory(binary, owner=os.getuid())


def test_license_revocation_invalidates_capability_cache_immediately(tmp_path: Path) -> None:
    from app.third_party_license import LicenseError

    binary = tmp_path / "companion"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o700)
    runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), binary=binary)
    with (
        patch(
            "app.third_party_license.load_acceptance",
            side_effect=[
                {"profile": "not-for-profit"},
                LicenseError("explicitly revoked"),
            ],
        ),
        patch.object(
            runtime,
            "_command",
            return_value={
                "schema": 1,
                "available": True,
                "observe": True,
                "enforce": False,
                "engine": {"name": "ndpi"},
                "protocols": [],
            },
        ) as command,
    ):
        assert runtime.capabilities()["available"]
        revoked = runtime.capabilities()
        assert not revoked["available"] and "revoked" in revoked["error"]
    command.assert_called_once_with("capabilities", "--json", "--license-profile", "not-for-profit")


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_active_profile_downgrade_stops_observer_or_quarantines_enforcement(
    tmp_path: Path,
    mode: str,
) -> None:
    import subprocess
    import time
    from unittest.mock import Mock

    config = enabled(mode)
    runtime = ApplicationRuntime(tmp_path, catalog(tmp_path), demo=True)
    runtime.config = config
    runtime.policy = {"generation": "a" * 64, "engine_license_profile": "not-for-profit"}
    process = Mock(spec=subprocess.Popen)
    process.poll.return_value = None
    runtime.process = process
    caps = {
        "available": True,
        "observe": True,
        "enforce": True,
        "allow_over_port_deny": True,
        "kernel_verified": True,
        "engine": {"name": "ndpi"},
        "license_profile": "not-for-profit",
        "error": "",
    }
    atomic_json(
        runtime.directory / "status.json",
        {"schema": 1, "generation": "a" * 64, "healthy": True, "updated_at": time.time()},
    )
    filters = DemoFilterDriver(config)
    router = RouterRuntime(
        DemoNetworkDriver(config.network),
        DemoLinkDriver(config.network),
        filters,
        applications=runtime,
    )
    before = filters.snapshot()
    with patch.object(runtime, "capabilities", return_value=caps):
        assert runtime.status()["healthy"]
        caps["license_profile"] = "lgpl-only"
        assert not runtime.status()["healthy"]
        router.guard_application_health()
    process.terminate.assert_called_once()
    assert runtime.process is None and router.applications_failed
    if mode == "observe":
        assert filters.snapshot() == before
        assert "observer stopped" in runtime.error
    else:
        assert "quarantined" in runtime.error
        assert any(
            line.startswith("-A OMR_APP_FORWARD -p tcp") and line.endswith("-j DROP")
            for line in filters.snapshot().splitlines()
        )
