"""Exercise the real Python health guard inside the disposable router namespace.

The caller supplies an already established, application-allowed connection and a
callback which sends on that SAME connection. No production interface is used.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from app.application_catalog import ApplicationCatalog
from app.application_integrity import native_inventory
from app.application_runtime import ApplicationRuntime, atomic_json
from app.models import Configuration
from app.runtime import LinkComponent, NetworkComponent, RouterRuntime


class NamespaceFilterDriver:
    def __init__(self, namespace: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", namespace):
            raise ValueError("Invalid isolated test namespace")
        self.namespace = namespace

    def snapshot(self, with_counters: bool = False) -> str:
        args = ["iptables-save", "-t", "filter"]
        if with_counters:
            args.append("-c")
        result = subprocess.run(
            ["ip", "netns", "exec", self.namespace, *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return (
            "\n".join(
                line for line in result.stdout.splitlines() if line and not line.startswith("#")
            )
            + "\n"
        )

    def restore(self, payload: str, test: bool = False) -> None:
        args = ["iptables-restore", "--noflush", "--wait", "5"]
        if test:
            args.append("--test")
        subprocess.run(
            ["ip", "netns", "exec", self.namespace, *args],
            input=payload,
            text=True,
            capture_output=True,
            check=True,
            timeout=5,
        )


def verify_quarantine(
    router_ns: str,
    native_process: subprocess.Popen[bytes] | subprocess.Popen[str],
    configpolicy: dict[str, Any],
    test_connection: Callable[[], bool],
    worker_pid: int | None = None,
) -> dict[str, Any]:
    """Kill only the owned classifier, then test its existing fast-path flow."""
    if not isinstance(native_process.args, list):
        raise ValueError("The native fixture must use an explicit argument vector")
    arguments = [str(value) for value in native_process.args]
    state = Path(arguments[arguments.index("--state-dir") + 1])
    binary = Path(arguments[arguments.index("run") - 1])
    status = json.loads((state / "status.json").read_text())
    pid = worker_pid if worker_pid is not None else status["worker_pid"]
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError("Invalid classifier PID")
    # Verify kernel parentage rather than trusting the JSON PID alone.
    process_stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if int(process_stat[1]) != native_process.pid:
        raise ValueError("The classifier is not owned by this isolated native consumer")
    if not test_connection():
        raise AssertionError("The existing flow was not application-allowed before failure")
    config = Configuration.model_validate(
        {
            "applications": {
                "enabled": True,
                "mode": "enforce",
                "interfaces": configpolicy["interfaces"],
                "source_networks": configpolicy["source_networks"],
            }
        }
    )
    with tempfile.TemporaryDirectory(prefix="omr-backend-quarantine-", dir="/run") as directory:
        catalog = ApplicationCatalog(Path(directory))
        applications = ApplicationRuntime(Path(directory), catalog, binary=binary)
        applications.directory = state
        applications.config = config
        applications.policy = configpolicy
        # Runtime uses only process ownership/lifecycle, never its typed streams.
        applications.process = cast(subprocess.Popen[bytes], native_process)
        filters = NamespaceFilterDriver(router_ns)
        # This probe invokes only health protection. Link/network mutations are
        # deliberately inaccessible to the test runtime.
        router = RouterRuntime(
            cast(NetworkComponent, object()),
            cast(LinkComponent, object()),
            filters,
            applications=applications,
        )
        from app.third_party_license import load_acceptance, record_acceptance

        receipt = Path(directory) / "fixture-license.json"
        profile = configpolicy.get("engine_license_profile", "lgpl-only")
        # Fixture receipts stay inside this owned temporary directory; they never
        # accept terms for the installed service or modify /etc.
        record_acceptance(profile, receipt)
        inventory, _ = native_inventory(binary)
        proof = state / "kernel-proof.json"
        if proof.exists():
            raise AssertionError("The disposable namespace state unexpectedly contains a proof")
        # The ordinary production gate needs a proof to start health supervision.
        # This PRIVATE bootstrap fixture is never installed or returned as proof:
        # the caller may emit a real proof only after the following same-flow
        # failure assertion succeeds, along with the earlier datapath assertions.
        atomic_json(
            proof,
            {
                "schema": 1,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "native_inventory_sha256": inventory,
                "engine_license_profile": profile,
                "kernel_release": os.uname().release,
                "first_syn": True,
                "mask_preservation": True,
                "failure_recovery": True,
                "application_block": True,
                "application_allow": True,
                "private_bootstrap_fixture": True,
            },
        )
        try:
            with patch(
                "app.third_party_license.load_acceptance",
                side_effect=lambda: load_acceptance(receipt),
            ):
                if not applications.status()["healthy"]:
                    raise AssertionError(
                        "The live isolated consumer was not healthy before failure"
                    )
                started = time.monotonic()
                os.kill(pid, signal.SIGKILL)
                deadline = started + 3
                while time.monotonic() < deadline and not router.applications_failed:
                    router.guard_application_health()
                    if not router.applications_failed:
                        time.sleep(0.02)
                elapsed = time.monotonic() - started
                if not router.applications_failed:
                    raise AssertionError(
                        "The real Python health guard did not quarantine the scope"
                    )
                if test_connection():
                    raise AssertionError("Previously allowed fast-path traffic survived quarantine")
                return {
                    "verified": True,
                    "same_connection": True,
                    "worker_failure_to_quarantine_seconds": elapsed,
                    "production_tick_seconds": 1,
                    "method": "RouterRuntime.guard_application_health + scoped filter DROP",
                }
        finally:
            proof.unlink(missing_ok=True)
            applications.stop()
            catalog.close()


def verify_compiler(router_ns: str, epoch: int = 7) -> dict[str, Any]:
    """Ask the actual target kernel to parse production compiler scripts only."""
    from app.application_models import ApplicationRule
    from app.application_policy import queue_patch
    from app.filtering import EMPTY_FILTER, filter_patch
    from app.models import FilterRule

    config = Configuration.model_validate(
        {
            "applications": {
                "enabled": True,
                "mode": "enforce",
                "interfaces": ["lan"],
                "source_networks": ["192.0.2.0/24"],
            }
        }
    )
    config.filter_rules = [
        FilterRule(
            name="Eligible port deny",
            action="drop",
            protocol="tcp",
            dst_ports="443",
            application_override_eligible=True,
        ),
        FilterRule(name="Later IP guard", action="drop", src_address="192.0.2.99"),
    ]
    filters = NamespaceFilterDriver(router_ns)
    before = filters.snapshot()
    empty_mangle = "*mangle\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
    for interface_constrained in (False, True):
        config.applications.rules = [
            ApplicationRule(
                name="BitTorrent",
                action="allow",
                application_ids=["app.bittorrent"],
                out_interface="wan" if interface_constrained else "",
            )
        ]
        filters.restore(filter_patch(EMPTY_FILTER, config, application_epoch=epoch), test=True)
        queue = queue_patch(empty_mangle, config, epoch)
        filters.restore(queue, test=True)
        if interface_constrained and "application-final" in queue:
            raise AssertionError("Interface constraints incorrectly use a final metadata fast path")
        if not interface_constrained and "! --ctstatus EXPECTED" not in queue:
            raise AssertionError("Expected child connections lack inherited-mark protection")
    if filters.snapshot() != before:
        raise AssertionError("Compiler --test unexpectedly changed the isolated filter rules")
    return {
        "verified": True,
        "filter_script": True,
        "queue_script": True,
        "expected_child_guard": True,
        "interface_reevaluation_variant": True,
        "test_only": True,
    }
