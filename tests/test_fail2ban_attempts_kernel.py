"""Opt-in NFLOG checks; all rules and sockets live in a disposable network namespace."""

import os
import platform
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from uuid import UUID

import pytest

from app.compiler import FirewallError
from app.fail2ban_attempts import ConnectionAttemptCollector
from app.fail2ban_models import F2BConfiguration, F2BProfile, F2BServiceScope, RuleProtection
from app.fail2ban_rules import observation_rules, reply_match_tokens
from app.fail2ban_runtime import Fail2banService
from app.filtering import LinuxFilterDriver, filter_patch
from app.ipsets import LinuxIPSetDriver
from app.models import Configuration, FilterRule
from app.rule_protection import effective_fail2ban

PROFILE = "r_1234567890abcdef12"


def command(*arguments: str) -> None:
    result = subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, (arguments, result.stdout, result.stderr)


def wait_events(collector: ConnectionAttemptCollector, count: int) -> None:
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if collector.status()["events"] >= count:
            return
        time.sleep(0.05)
    raise AssertionError(collector.status())


def install_observation(profile: F2BProfile) -> None:
    match = ["-p", "tcp", "-m", "multiport", "--dports", "55123"]
    rules = observation_rules(profile, "INPUT", match)
    rules += observation_rules(profile, "OUTPUT", reply_match_tokens(match), reply=True)
    for rule in rules:
        command("iptables", *shlex.split(rule))


def scenario(directory: Path) -> None:
    command("ip", "link", "set", "lo", "up")
    for address in ("1.1.1.1", "2.2.2.2"):
        command("ip", "address", "add", f"{address}/32", "dev", "lo")
    settings = F2BConfiguration(
        enabled=True,
        profiles=[
            F2BProfile(
                id=PROFILE,
                name="Connections",
                service="connections",
                enabled=True,
                ports=[55123],
                rule_id=UUID("12345678-90ab-cdef-1234-567890abcdef"),
                rule_table="filter",
                scope=F2BServiceScope(destinations=["2.2.2.2/32"]),
            )
        ],
    )
    collector = ConnectionAttemptCollector(directory)
    contender = ConnectionAttemptCollector(directory / "contender")
    try:
        collector.check(settings)
        assert not collector.status()["running"]
        collector.configure(settings)
        with pytest.raises(FirewallError, match="exclusively"):
            contender.check(settings)
        install_observation(settings.profiles[0])
        with socket.socket() as server:
            server.bind(("2.2.2.2", 55123))
            server.listen(4)
            server.settimeout(2)
            for count in (1, 2):
                with socket.socket() as client:
                    client.bind(("1.1.1.1", 0))
                    client.settimeout(2)
                    client.connect(("2.2.2.2", 55123))
                    connection, _peer = server.accept()
                    connection.close()
                wait_events(collector, count)
        # A dropped SYN and all its retries prove no return-path participation.
        command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "55123", "-j", "DROP")
        with socket.socket() as client:
            client.bind(("1.1.1.1", 0))
            client.settimeout(2.5)
            with pytest.raises(TimeoutError):
                client.connect(("2.2.2.2", 55123))
        assert collector.status()["events"] == 2, collector.status()
        assert collector.status()["healthy"], collector.status()
        lines = collector.journal.path.read_text().splitlines()
        assert len(lines) == 2
        assert all(line.endswith(f"profile={PROFILE} src=1.1.1.1") for line in lines)
        collector.configure(F2BConfiguration())
        assert not collector.status()["running"]
        contender.check(settings)  # Closing releases only our group's binding.
    finally:
        collector.close()
        contender.close()


def ban_scenario(directory: Path) -> None:
    command("ip", "link", "set", "lo", "up")
    for address in ("1.1.1.1", "2.2.2.2"):
        command("ip", "address", "add", f"{address}/32", "dev", "lo")
    config = Configuration(
        filter_rules=[
            FilterRule(
                name="Protected listener",
                chain="input",
                action="accept",
                protocol="tcp",
                dst_address="2.2.2.2",
                dst_ports="55123",
                protection=RuleProtection(
                    enabled=True,
                    event_source="connections",
                    max_retry=3,
                    find_time=60,
                    ban_time=20,
                ),
            )
        ]
    )
    settings = effective_fail2ban(config)
    profile = next(profile for profile in settings.profiles if profile.service == "connections")
    sets = LinuxIPSetDriver(directory)
    sets.ensure_temporary(f"f2b_{profile.id}")
    collector = ConnectionAttemptCollector(directory)
    service = Fail2banService(directory, False, sets)
    service.initialize_files(settings)
    service.settings = settings
    stop = threading.Event()
    listeners: list[socket.socket] = []
    threads: list[threading.Thread] = []

    def listen(port: int) -> None:
        listener = socket.socket()
        listener.bind(("2.2.2.2", port))
        listener.listen(16)
        listener.settimeout(0.1)
        listeners.append(listener)

        def receive() -> None:
            while not stop.is_set():
                try:
                    connection, _peer = listener.accept()
                    connection.close()
                except TimeoutError:
                    continue

        thread = threading.Thread(target=receive, daemon=True)
        threads.append(thread)
        thread.start()

    def connects(port: int) -> bool:
        with socket.socket() as client:
            client.bind(("1.1.1.1", 0))
            client.settimeout(0.3)
            return client.connect_ex(("2.2.2.2", port)) == 0

    listen(55123)
    listen(55124)
    process = subprocess.Popen(
        [sys.executable, "-m", "app.fail2ban_runtime", "daemon", "--data-dir", str(directory)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                if "pong" in service._client(["ping"]).lower():
                    break
            except FirewallError:
                time.sleep(0.1)
        service.apply(settings, settings)
        service._client(["set", "loglevel", "INFO"])
        collector.configure(settings)
        filters = LinuxFilterDriver()
        filters.restore(filter_patch(filters.snapshot(), config), test=True)
        filters.restore(filter_patch(filters.snapshot(), config))
        for _ in range(3):
            assert connects(55123)
        wait_events(collector, 3)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if sets.temporary_entries(f"f2b_{profile.id}"):
                break
            time.sleep(0.1)
        assert sets.temporary_entries(f"f2b_{profile.id}"), service.status()
        assert not connects(55123), "Ban did not stop the protected service"
        assert connects(55124), "A service-scoped ban blocked an unrelated port"
        assert service.bans.page()["items"][0]["kernel_present"]
        service.unban(profile.id, "1.1.1.1")
        assert connects(55123), "Manual unban did not restore service access"
        assert collector.status()["healthy"], collector.status()
    finally:
        collector.close()
        service.journal.close()
        stop.set()
        for thread in threads:
            thread.join(timeout=1)
        for listener in listeners:
            listener.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        if sys.exc_info()[0] is not None and process.stdout is not None:
            print(process.stdout.read().decode(), file=sys.stderr)


def bulk_scenario(directory: Path) -> None:
    """Ordinary application data must not hide simultaneous new handshakes."""
    command("ip", "link", "set", "lo", "up")
    for address in ("1.1.1.1", "2.2.2.2"):
        command("ip", "address", "add", f"{address}/32", "dev", "lo")
    profile = F2BProfile(
        id=PROFILE,
        name="Busy service",
        service="connections",
        enabled=True,
        ports=[55123],
        rule_id=UUID("12345678-90ab-cdef-1234-567890abcdef"),
        rule_table="filter",
        scope=F2BServiceScope(destinations=["2.2.2.2/32"]),
    )
    collector = ConnectionAttemptCollector(directory)
    stop = threading.Event()
    errors: list[BaseException] = []
    received = 0
    threads: list[threading.Thread] = []
    with socket.socket() as listener, socket.socket() as bulk_client:
        listener.bind(("2.2.2.2", 55123))
        listener.listen(16)
        listener.settimeout(2)
        bulk_client.bind(("1.1.1.1", 0))
        bulk_client.settimeout(1)
        bulk_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        collector.configure(F2BConfiguration(enabled=True, profiles=[profile]))
        install_observation(profile)
        bulk_client.connect(("2.2.2.2", 55123))
        bulk_server, _ = listener.accept()
        bulk_server.settimeout(0.2)

        def send() -> None:
            try:
                while not stop.is_set():
                    bulk_client.sendall(b"x" * 1024)
                    time.sleep(0.0002)
            except OSError as exc:
                if not stop.is_set():
                    errors.append(exc)

        def receive() -> None:
            nonlocal received
            try:
                while not stop.is_set():
                    try:
                        data = bulk_server.recv(65536)
                    except TimeoutError:
                        continue
                    if not data:
                        break
                    received += len(data)
            except OSError as exc:
                if not stop.is_set():
                    errors.append(exc)

        try:
            wait_events(collector, 1)
            for target in (send, receive):
                thread = threading.Thread(target=target, daemon=True)
                threads.append(thread)
                thread.start()
            time.sleep(0.75)
            for _ in range(12):
                with socket.socket() as client:
                    client.bind(("1.1.1.1", 0))
                    client.settimeout(1)
                    client.connect(("2.2.2.2", 55123))
                    connection, _ = listener.accept()
                    connection.close()
                time.sleep(0.1)
            wait_events(collector, 13)
            assert received >= 512 * 1024, received
            assert not errors, errors
            assert collector.status()["events"] == 13, collector.status()
            assert collector.status()["observation_saturated"] == 0, collector.status()
            assert collector.status()["healthy"], collector.status()
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=2)
            bulk_server.close()
            collector.close()


def forwarded_scenario(directory: Path) -> None:
    """Normal DNAT handshakes cross distinct client/service interfaces both ways."""
    server_code = """
import socket, sys
sys.stdin.readline()
with socket.socket() as listener:
    listener.settimeout(5)
    listener.bind(('10.90.0.2', 55123))
    listener.listen(4)
    print('ready', flush=True)
    for _ in range(3):
        connection, _ = listener.accept()
        connection.close()
"""
    client_code = """
import socket, sys
sys.stdin.readline()
for _ in range(3):
    with socket.create_connection(('10.89.0.1', 55124), timeout=2):
        pass
"""
    server = subprocess.Popen(
        ["unshare", "--net", sys.executable, "-c", server_code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    client = subprocess.Popen(
        ["unshare", "--net", sys.executable, "-c", client_code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    collector = ConnectionAttemptCollector(directory)
    try:
        for process, interface, router_address, endpoint_address, remote_network in (
            (client, "omrin", "10.89.0.1", "10.89.0.2", "10.90.0.0/24"),
            (server, "omrout", "10.90.0.1", "10.90.0.2", "10.89.0.0/24"),
        ):
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if os.readlink(f"/proc/{process.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                    break
                time.sleep(0.02)
            peer = interface + "peer"
            command("ip", "link", "add", interface, "type", "veth", "peer", "name", peer)
            command("ip", "link", "set", peer, "netns", str(process.pid))
            command("ip", "address", "add", router_address + "/24", "dev", interface)
            command("ip", "link", "set", interface, "up")
            namespace = f"--net=/proc/{process.pid}/ns/net"
            command(
                "nsenter", namespace, "ip", "address", "add", endpoint_address + "/24", "dev", peer
            )
            command("nsenter", namespace, "ip", "link", "set", peer, "up")
            command(
                "nsenter", namespace, "ip", "route", "add", remote_network, "via", router_address
            )
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
        command(
            "iptables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            "omrin",
            "-p",
            "tcp",
            "--dport",
            "55124",
            "-j",
            "DNAT",
            "--to-destination",
            "10.90.0.2:55123",
        )
        config = Configuration(
            filter_rules=[
                FilterRule(
                    name="Forwarded endpoint",
                    chain="forward",
                    action="accept",
                    protocol="tcp",
                    in_interface="omrin",
                    out_interface="omrout",
                    dst_address="10.90.0.2",
                    dst_ports="55123",
                    protection=RuleProtection(enabled=True, event_source="connections"),
                )
            ]
        )
        settings = effective_fail2ban(config)
        profile = next(item for item in settings.profiles if item.service == "connections")
        LinuxIPSetDriver(directory).ensure_temporary(f"f2b_{profile.id}")
        collector.configure(settings)
        filters = LinuxFilterDriver()
        filters.restore(filter_patch(filters.snapshot(), config), test=True)
        filters.restore(filter_patch(filters.snapshot(), config))
        assert server.stdin is not None and server.stdout is not None
        server.stdin.write(b"go\n")
        server.stdin.flush()
        assert server.stdout.readline() == b"ready\n"
        _stdout, stderr = client.communicate(b"go\n", timeout=8)
        assert client.returncode == 0, stderr
        _stdout, stderr = server.communicate(timeout=5)
        assert server.returncode == 0, stderr
        wait_events(collector, 3)
        assert collector.status()["events"] == 3, collector.status()
        assert collector.status()["unverified_path"] == 0, collector.status()
        assert collector.status()["healthy"], collector.status()
    finally:
        collector.close()
        for process in (client, server):
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=3)


def send_spoofed_syns() -> None:
    """Called only inside the child disposable namespace, after its veth is ready."""

    def checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\0"
        value = sum(struct.unpack(f"!{len(data) // 2}H", data))
        while value >> 16:
            value = (value & 0xFFFF) + (value >> 16)
        return int(~value & 0xFFFF)

    source, destination = socket.inet_aton("10.89.0.99"), socket.inet_aton("10.89.0.1")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sender:
        for index in range(20):
            tcp = struct.pack(
                "!HHIIBBHHH", 50000 + index, 55123, 1000 + index, 0, 80, 2, 8192, 0, 0
            )
            pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp))
            tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
            header = struct.pack(
                "!BBHHHBBH4s4s", 69, 0, 40, index, 0, 64, 6, 0, source, destination
            )
            header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
            sender.sendto(header + tcp, ("10.89.0.1", 0))


def unconfirmed_scenario(directory: Path, *, spoofed: bool = False) -> None:
    """Real ingress whose conntrack entry is destroyed after a later INPUT drop."""
    sender = subprocess.Popen(
        [
            "unshare",
            "--net",
            sys.executable,
            "-c",
            (
                "import runpy, sys; sys.stdin.readline(); "
                "runpy.run_path('tests/test_fail2ban_attempts_kernel.py')['send_spoofed_syns']()"
                if spoofed
                else "import socket, sys; sys.stdin.readline(); "
                "client = socket.socket(); client.settimeout(2.5); "
                "client.connect_ex(('10.89.0.1', 55123)); client.close()"
            ),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    collector = ConnectionAttemptCollector(directory)
    listener = socket.socket()
    try:
        # Wait for unshare to finish before moving the peer into the child netns.
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if os.readlink(f"/proc/{sender.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.02)
        command("ip", "link", "add", "omrhost", "type", "veth", "peer", "name", "omrclient")
        command("ip", "link", "set", "omrclient", "netns", str(sender.pid))
        command("ip", "address", "add", "10.89.0.1/24", "dev", "omrhost")
        command("ip", "link", "set", "omrhost", "up")
        namespace = f"--net=/proc/{sender.pid}/ns/net"
        command("nsenter", namespace, "ip", "address", "add", "10.89.0.2/24", "dev", "omrclient")
        command("nsenter", namespace, "ip", "link", "set", "omrclient", "up")
        settings = F2BConfiguration(
            enabled=True,
            profiles=[
                F2BProfile(
                    id=PROFILE,
                    name="Ingress",
                    service="connections",
                    enabled=True,
                    rule_id=UUID("12345678-90ab-cdef-1234-567890abcdef"),
                    rule_table="filter",
                    scope=F2BServiceScope(),
                )
            ],
        )
        collector.configure(settings)
        install_observation(settings.profiles[0])
        if spoofed:
            listener.bind(("10.89.0.1", 55123))
            listener.listen(32)
        else:
            command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "55123", "-j", "DROP")
        _stdout, stderr = sender.communicate(b"go\n", timeout=5)
        assert sender.returncode == 0, stderr
        deadline = time.monotonic() + 4
        while not collector.status()["tracked_connections"] and time.monotonic() < deadline:
            time.sleep(0.05)
        assert collector.status()["tracked_connections"], collector.status()
        assert collector.status()["events"] == 0, collector.status()
        assert collector.journal.path.read_bytes() == b""
        assert collector.status()["healthy"], collector.status()
    finally:
        listener.close()
        collector.close()
        if sender.poll() is None:
            sender.terminate()
            sender.wait(timeout=2)


def spoofed_scenario(directory: Path) -> None:
    """A reachable listener receives SYNs naming a different, uninvolved source."""
    unconfirmed_scenario(directory, spoofed=True)


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Requires opt-in Linux root; every mutation is in a fresh network namespace",
)
@pytest.mark.parametrize(
    "scenario_name",
    [
        "scenario",
        "ban_scenario",
        "bulk_scenario",
        "forwarded_scenario",
        "unconfirmed_scenario",
        "spoofed_scenario",
    ],
)
def test_connection_attempts_real_kernel(scenario_name: str) -> None:
    for binary in ("unshare", "nsenter", "ip", "iptables", "ipset", "fail2ban-server"):
        assert shutil.which(binary), f"Install {binary}"
    with tempfile.TemporaryDirectory() as directory:
        code = (
            "import runpy; from pathlib import Path; "
            f"runpy.run_path('tests/test_fail2ban_attempts_kernel.py')"
            f"[{scenario_name!r}](Path({directory!r}))"
        )
        result = subprocess.run(
            ["unshare", "--net", sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
        )
        assert result.returncode == 0, result.stdout + result.stderr
