"""Real country/Fail2ban rule predicates; all packets stay in a fresh net namespace."""

import os
import platform
import select
import shutil
import socket
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

import pytest

from app.compiler import patch, rollback_patch
from app.filtering import LinuxFilterDriver, filter_patch, filter_rollback
from app.firewall import LinuxDriver
from app.ipsets import LinuxIPSetDriver
from app.models import AddressList, Configuration, FilterRule, NatRule


def command(*args: str) -> None:
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, (args, result.stdout, result.stderr)


def scenario(directory: Path) -> None:
    command("ip", "link", "set", "lo", "up")
    for address in ("1.1.1.1", "1.1.1.2", "1.1.1.3", "2.2.2.2", "8.8.8.8", "9.9.9.9"):
        command("ip", "address", "add", f"{address}/32", "dev", "lo")
    sets = LinuxIPSetDriver(directory)
    sets.ensure_country("geo_AU", ["1.1.1.0/24"])
    sets.ensure_country("geo_US", ["8.8.8.0/24"])
    sets.ensure_temporary("f2b_web")
    for address in ("1.1.1.1", "1.1.1.3", "2.2.2.2"):
        sets.add_temporary("f2b_web", address, 60)

    with ExitStack() as stack:
        listeners: dict[str, socket.socket] = {}

        def listen(label: str, address: str, port: int) -> None:
            server = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            server.bind((address, port))
            listeners[label] = server

        def expect(source: str, destination: str, port: int, receiver: str | None) -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind((source, 0))
                # Each probe has a unique tuple: existing conntrack NAT decisions must not
                # mask a new rule or set membership after changing the configuration.
                command("conntrack", "-F")
                client.sendto(b"omr-rule-predicate", (destination, port))
                ready, _, _ = select.select(list(listeners.values()), [], [], 0.3)
                if receiver is None:
                    assert not ready, f"A blocked packet arrived from {source}"
                    return
                assert ready == [listeners[receiver]], (source, destination, port, receiver, ready)
                assert listeners[receiver].recvfrom(128)[0] == b"omr-rule-predicate"

        listen("filter", "8.8.8.8", 55200)
        listen("other-country", "9.9.9.9", 55200)
        listen("other-port", "8.8.8.8", 55201)
        filters = LinuxFilterDriver()
        before_filter = filters.snapshot()
        target = Configuration(
            address_lists=[
                AddressList(name="selected_sources", addresses=["1.1.1.1", "1.1.1.2", "2.2.2.2"])
            ],
            filter_rules=[
                FilterRule(
                    name="Country and ban predicate",
                    chain="input",
                    action="drop",
                    protocol="udp",
                    src_list="selected_sources",
                    src_country="AU",
                    dst_country="US",
                    f2b_profile="web",
                    f2b_match="banned",
                    dst_ports="55200",
                )
            ],
        )
        # Global collection remains off: the selected predicate still uses existing set data.
        assert not target.fail2ban.enabled
        filters.restore(filter_patch(filters.snapshot(), target), test=True)
        expect("1.1.1.1", "8.8.8.8", 55200, "filter")
        filters.restore(filter_patch(filters.snapshot(), target))
        expect("1.1.1.1", "8.8.8.8", 55200, None)
        expect("1.1.1.2", "8.8.8.8", 55200, "filter")
        expect("1.1.1.3", "8.8.8.8", 55200, "filter")
        expect("2.2.2.2", "8.8.8.8", 55200, "filter")
        expect("1.1.1.1", "9.9.9.9", 55200, "other-country")
        expect("1.1.1.1", "8.8.8.8", 55201, "other-port")

        target.filter_rules[0].f2b_match = "not_banned"
        filters.restore(filter_patch(filters.snapshot(), target), test=True)
        filters.restore(filter_patch(filters.snapshot(), target))
        expect("1.1.1.1", "8.8.8.8", 55200, "filter")
        expect("1.1.1.2", "8.8.8.8", 55200, None)
        filters.restore(filter_rollback(filters.snapshot(), before_filter))
        expect("1.1.1.2", "8.8.8.8", 55200, "filter")

        listen("preferred", "127.0.0.1", 55310)
        listen("fallback", "127.0.0.1", 55311)
        listen("nat-other-port", "8.8.8.8", 55313)
        nat = LinuxDriver()
        before_nat = nat.snapshot()
        target = Configuration(
            rules=[
                NatRule(
                    name="Country and not-banned NAT",
                    chain="output",
                    protocol="udp",
                    src_country="AU",
                    dst_country="US",
                    f2b_profile="web",
                    f2b_match="not_banned",
                    dst_ports="55312",
                    to_address="127.0.0.1",
                    to_ports="55310",
                ),
                NatRule(
                    name="Later NAT fallback",
                    chain="output",
                    protocol="udp",
                    dst_ports="55312",
                    to_address="127.0.0.1",
                    to_ports="55311",
                ),
            ]
        )
        nat.restore(patch(nat.snapshot(), target), test=True)
        nat.restore(patch(nat.snapshot(), target))
        # US refers to the ORIGINAL destination (8.8.8.8), not 127.0.0.1 after DNAT.
        expect("1.1.1.2", "8.8.8.8", 55312, "preferred")
        # A banned source skips this NAT rule, but is not dropped. Later rules still apply.
        expect("1.1.1.1", "8.8.8.8", 55312, "fallback")
        expect("2.2.2.2", "8.8.8.8", 55312, "fallback")
        expect("1.1.1.2", "9.9.9.9", 55312, "fallback")
        expect("1.1.1.2", "8.8.8.8", 55313, "nat-other-port")
        target.rules[0].f2b_match = "banned"
        nat.restore(patch(nat.snapshot(), target), test=True)
        nat.restore(patch(nat.snapshot(), target))
        expect("1.1.1.1", "8.8.8.8", 55312, "preferred")
        expect("1.1.1.2", "8.8.8.8", 55312, "fallback")
        nat.restore(rollback_patch(nat.snapshot(), before_nat))
        expect("1.1.1.2", "8.8.8.8", 55312, None)
        expect("1.1.1.2", "8.8.8.8", 55313, "nat-other-port")


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Requires opt-in Linux root; every mutation is in a fresh network namespace",
)
def test_rule_country_and_fail2ban_predicates_real_kernel() -> None:
    for binary in ("unshare", "ip", "ipset", "iptables-save", "iptables-restore", "conntrack"):
        assert shutil.which(binary), f"Install {binary}"
    with tempfile.TemporaryDirectory() as directory:
        code = (
            "import runpy; from pathlib import Path; "
            f"runpy.run_path('tests/test_rule_security_kernel.py')['scenario'](Path({directory!r}))"
        )
        result = subprocess.run(
            ["unshare", "--net", sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    assert result.returncode == 0, result.stdout + result.stderr
