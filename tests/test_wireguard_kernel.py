"""Opt-in real Linux WireGuard tests. Every mutation is inside unshare --net."""

import json
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from app.bootstrap import BootstrapError, restore_confirmed_filters
from app.compiler import FirewallError
from app.diagnostics import DiagnosticRequest, NetworkDiagnostics
from app.filtering import FilterDriver, LinuxFilterDriver
from app.link_models import WireGuardInterface, WireGuardServerAccess
from app.links import LinuxLinkDriver
from app.models import Configuration
from app.network_models import DnsSettings, DnsStaticRecord, IpAddress, NetworkConfiguration
from app.networking import LinuxNetworkDriver
from app.runtime import RouterRuntime
from app.wireguard import LinuxWireGuardDriver, WireGuardError
from app.wireguard_models import WireGuardPeer
from app.wireguard_routing import LinuxWireGuardRouting
from app.wireguard_vault import WireGuardVault


def command(*arguments: str, payload: str | None = None, success: bool = True) -> str:
    result = subprocess.run(
        list(arguments), input=payload, capture_output=True, text=True, timeout=12, check=False
    )
    if success:
        assert result.returncode == 0, (arguments, result.stderr)
    else:
        assert result.returncode != 0, arguments
    return result.stdout


def namespace_scenario(directory: Path) -> None:
    command("ip", "link", "set", "lo", "up")
    command("ip", "link", "add", "lan-test", "type", "dummy")
    command("ip", "address", "add", "10.99.0.1/24", "dev", "lan-test")
    command("ip", "link", "set", "lan-test", "up")
    command("ip", "link", "add", "wan-test", "type", "dummy")
    command("ip", "address", "add", "192.0.2.1/24", "dev", "wan-test")
    command("ip", "link", "set", "wan-test", "up")
    command("ip", "route", "add", "default", "dev", "wan-test")
    vault = WireGuardVault(directory)
    own, remote = vault.create("interface"), vault.create("peer-client")
    interface = WireGuardInterface(
        name="wg-server",
        private_key_id=own.id,
        public_key=own.public_key,
        route_allowed_ips=True,
        route_sources=["10.99.0.0/24"],
    )
    target = Configuration(
        network=NetworkConfiguration(
            wireguard_interfaces=[interface],
            wireguard_peers=[
                WireGuardPeer(
                    name="Remote",
                    interface="wg-server",
                    public_key=remote.public_key,
                    allowed_ips=["0.0.0.0/0"],
                    endpoint_host="127.0.0.1",
                    endpoint_port=51821,
                )
            ],
            addresses=[IpAddress(interface="wg-server", address="10.77.0.1/24")],
        )
    )
    links = LinuxLinkDriver(directory)
    wireguard = LinuxWireGuardDriver(directory, Configuration().network, links, vault)
    routing = LinuxWireGuardRouting(directory)
    runtime = RouterRuntime(
        LinuxNetworkDriver(directory), links, LinuxFilterDriver(), wireguard, routing
    )
    namespace_boot_guard(directory, target, runtime.filters, routing)

    # The remote interface's UDP socket is born in this isolated namespace and
    # remains here when the interface moves into a second isolated namespace.
    with subprocess.Popen(
        [
            "unshare",
            "--net",
            sys.executable,
            "-u",
            "-c",
            "import os,time; print(os.getpid(), flush=True); time.sleep(100)",
        ],
        stdout=subprocess.PIPE,
        text=True,
    ) as remote_process:
        assert remote_process.stdout
        pid = remote_process.stdout.readline().strip()
        assert pid.isdigit()
        remote_prefix = ["nsenter", "-t", pid, "-n"]
        try:
            command("ip", "link", "add", "wg-remote", "type", "wireguard")
            remote_private = vault.secret(remote.id, "peer-client")
            profile = (
                f"[Interface]\nPrivateKey={remote_private}\nListenPort=51821\n"
                f"[Peer]\nPublicKey={own.public_key}\nAllowedIPs=0.0.0.0/0\n"
                "Endpoint=127.0.0.1:51820\nPersistentKeepalive=1\n"
            )
            command("wg", "setconf", "wg-remote", "/dev/stdin", payload=profile)
            command("ip", "link", "set", "wg-remote", "netns", pid)
            command(*remote_prefix, "ip", "link", "set", "lo", "up")
            command(*remote_prefix, "ip", "address", "add", "10.77.0.2/32", "dev", "wg-remote")
            command(*remote_prefix, "ip", "address", "add", "198.18.0.1/32", "dev", "lo")
            command(*remote_prefix, "ip", "link", "set", "wg-remote", "up")
            command(*remote_prefix, "ip", "route", "add", "default", "dev", "wg-remote")

            empty = Configuration()
            runtime.check(empty, target)
            initial = runtime.snapshot(empty)
            runtime.apply(empty, target)
            # Validate source routing even with strict reverse-path filtering.
            Path("/proc/sys/net/ipv4/conf/all/rp_filter").write_text("1\n")
            Path("/proc/sys/net/ipv4/conf/wg-server/rp_filter").write_text("1\n")
            command("ping", "-n", "-c", "3", "-W", "2", "10.77.0.2")
            command("ping", "-n", "-c", "3", "-W", "2", "-I", "10.99.0.1", "198.18.0.1")
            peer = wireguard.status()["interfaces"][0]["peers"][0]
            assert peer["connected"] and peer["rx_bytes"] > 0 and peer["tx_bytes"] > 0
            assert vault.secret(own.id, "interface") not in json.dumps(runtime.status())
            vpn_route = json.loads(
                command("ip", "-4", "-j", "route", "get", "198.18.0.1", "from", "10.99.0.1")
            )[0]
            assert vpn_route["dev"] == "wg-server" and int(vpn_route["table"]) == 20000, vpn_route
            escaped = json.loads(
                command(
                    "ip",
                    "-4",
                    "-j",
                    "route",
                    "get",
                    "198.18.0.1",
                    "from",
                    "10.99.0.1",
                    "mark",
                    "0x4f4d0001",
                )
            )[0]
            assert escaped["dev"] == "wan-test"

            healthy = runtime.snapshot(target)
            disabled = target.model_copy(deep=True)
            disabled.network.wireguard_peers[0].enabled = False
            runtime.check(target, disabled)
            runtime.apply(target, disabled)
            assert command("wg", "show", "wg-server", "peers").strip() == ""
            command("ip", "-4", "route", "get", "198.18.0.1", "from", "10.99.0.1", success=False)
            runtime.rollback(healthy)
            command("ping", "-n", "-c", "2", "-W", "2", "-I", "10.99.0.1", "198.18.0.1")

            healthy = runtime.snapshot(target)
            disabled = target.model_copy(deep=True)
            disabled.network.wireguard_interfaces[0].enabled = False
            runtime.check(target, disabled)
            runtime.apply(target, disabled)
            current = next(
                row
                for row in json.loads(command("ip", "-j", "link"))
                if row["ifname"] == "wg-server"
            )
            assert "UP" not in current["flags"]
            command("ip", "-4", "route", "get", "198.18.0.1", "from", "10.99.0.1", success=False)
            runtime.rollback(healthy)
            command("ping", "-n", "-c", "2", "-W", "2", "-I", "10.99.0.1", "198.18.0.1")

            namespace_policy_transitions(runtime, target, routing)
            namespace_server_access(runtime, target, remote_prefix)

            # Delete and recreate the interface through the same recovery protocol.
            healthy = runtime.snapshot(target)
            runtime.check(target, empty)
            runtime.apply(target, empty)
            assert "wg-server" not in {
                row["ifname"] for row in json.loads(command("ip", "-j", "link"))
            }
            runtime.rollback(healthy)
            command("ping", "-n", "-c", "2", "-W", "2", "-I", "10.99.0.1", "198.18.0.1")
            runtime.rollback(initial)
            assert (
                command("ip", "-4", "route", "show", "default").strip()
                == "default dev wan-test scope link"
            )
        finally:
            remote_process.terminate()
            remote_process.wait(timeout=5)


def namespace_policy_transitions(
    runtime: RouterRuntime, target: Configuration, routing: LinuxWireGuardRouting
) -> None:
    original = routing.runner
    mutations: list[list[str]] = []
    fail_add = [False]

    def confined(arguments: list[str]) -> str:
        if "-j" in arguments:
            return original(arguments)
        if fail_add[0] and arguments[2:4] == ["route", "add"]:
            fail_add[0] = False
            raise WireGuardError("Injected route install failure")
        result = original(arguments)
        mutations.append(arguments)
        lookup = subprocess.run(
            ["ip", "-4", "-j", "route", "get", "198.18.0.1", "from", "10.99.0.1"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if lookup.returncode == 0:
            assert json.loads(lookup.stdout)[0]["dev"] == "wg-server", (arguments, lookup.stdout)
        return result

    routing.runner = confined
    try:
        for change in ("table", "source"):
            changed = target.model_copy(deep=True)
            if change == "table":
                changed.network.wireguard_interfaces[0].routing_table = 20001
            else:
                changed.network.wireguard_interfaces[0].route_sources = ["10.99.0.0/25"]
            runtime.check(target, changed)
            healthy = runtime.snapshot(target)
            runtime.apply(target, changed)
            runtime.rollback(healthy)
        changed = target.model_copy(deep=True)
        changed.network.wireguard_interfaces[0].routing_table = 20001
        runtime.check(target, changed)
        healthy = runtime.snapshot(target)
        fail_add[0] = True
        try:
            runtime.apply(target, changed)
        except WireGuardError:
            pass
        else:
            raise AssertionError("Expected injected apply failure")
        # Fail the first attempt to restore the old route as well. Source guards must remain.
        fail_add[0] = True
        try:
            runtime.rollback(healthy)
        except WireGuardError:
            pass
        except Exception as exc:
            assert "Injected route install failure" in str(exc)
        else:
            raise AssertionError("Expected injected rollback failure")
        command("ip", "-4", "route", "get", "198.18.0.1", "from", "10.99.0.1", success=False)
        runtime.rollback(healthy)
        assert len(mutations) > 20
    finally:
        routing.runner = original


def namespace_boot_guard(
    directory: Path, config: Configuration, filters: FilterDriver, routing: LinuxWireGuardRouting
) -> None:
    # The real built-in priority-zero local rule is accepted, foreign early selectors are not.
    routing.check(NetworkConfiguration(), config.network)
    command("ip", "-4", "rule", "add", "priority", "0", "from", "10.99.0.0/24", "lookup", "main")
    try:
        foreign = command("ip", "-4", "-N", "-j", "rule", "show")
        with pytest.raises(WireGuardError, match="priority-zero"):
            routing.restore_guards(config.network)
        assert command("ip", "-4", "-N", "-j", "rule", "show") == foreign
        assert not routing.path.exists()
    finally:
        command(
            "ip", "-4", "rule", "del", "priority", "0", "from", "10.99.0.0/24", "lookup", "main"
        )
    routing.check(NetworkConfiguration(), config.network)
    with sqlite3.connect(directory / "linux.sqlite3") as db:
        db.execute("CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO state VALUES (?, ?)", ("applied", config.model_dump_json()))

    class RejectingFilter:
        def snapshot(self, with_counters: bool = False) -> str:
            return filters.snapshot(with_counters)

        def restore(self, payload: str, test: bool = False) -> None:
            raise FirewallError("Injected bootstrap filter failure")

    try:
        restore_confirmed_filters(directory, RejectingFilter(), routing)
    except BootstrapError:
        pass
    else:
        raise AssertionError("Expected failed bootstrap")
    command("ip", "-4", "route", "get", "198.18.0.1", "from", "10.99.0.1", success=False)
    command("ip", "route", "add", "198.51.100.0/24", "via", "192.0.2.2")
    exception = json.loads(
        command("ip", "-4", "-j", "route", "get", "198.51.100.2", "from", "10.99.0.1")
    )[0]
    assert exception["dev"] == "wan-test"
    transport = json.loads(
        command(
            "ip",
            "-4",
            "-j",
            "route",
            "get",
            "198.18.0.1",
            "from",
            "10.99.0.1",
            "mark",
            "0x4f4d0001",
        )
    )[0]
    assert transport["dev"] == "wan-test"
    restore_confirmed_filters(directory, filters, routing)


def namespace_server_access(
    runtime: RouterRuntime, target: Configuration, client: list[str]
) -> None:
    """The authenticated peer deliberately routes all destinations, against foreign ACCEPTs."""
    with subprocess.Popen(
        [
            "unshare",
            "--net",
            sys.executable,
            "-u",
            "-c",
            "import os,time; print(os.getpid(), flush=True); time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        text=True,
    ) as destination:
        assert destination.stdout
        pid = destination.stdout.readline().strip()
        remote = ["nsenter", "-t", pid, "-n"]
        try:
            command("ip", "link", "add", "lan-policy", "type", "veth", "peer", "name", "lan-remote")
            command("ip", "link", "set", "lan-remote", "netns", pid)
            command("ip", "address", "add", "198.19.0.1/24", "dev", "lan-policy")
            command("ip", "link", "set", "lan-policy", "up")
            command("ip", "route", "add", "198.19.1.0/24", "via", "198.19.0.2")
            command(*remote, "ip", "link", "set", "lo", "up")
            command(*remote, "ip", "address", "add", "198.19.0.2/24", "dev", "lan-remote")
            command(*remote, "ip", "address", "add", "198.19.1.2/24", "dev", "lo")
            command(*remote, "ip", "link", "set", "lan-remote", "up")
            command(*remote, "ip", "route", "add", "default", "via", "198.19.0.1")
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
            command("iptables", "-I", "INPUT", "1", "-j", "ACCEPT")
            command("iptables", "-I", "FORWARD", "1", "-j", "ACCEPT")
            healthy = runtime.snapshot(target)
            restricted = target.model_copy(deep=True)
            restricted.network.wireguard_interfaces[0].server_access = WireGuardServerAccess(
                source_network="10.77.0.0/24", access_networks=["198.19.0.0/24"]
            )
            runtime.check(target, restricted)
            runtime.apply(target, restricted)
            command(*client, "ping", "-n", "-c", "1", "-W", "1", "198.19.0.2")
            command(*client, "ping", "-n", "-c", "1", "-W", "1", "198.19.1.2", success=False)
            command(*client, "ping", "-n", "-c", "1", "-W", "1", "10.77.0.1", success=False)
            # RETURN must not override another administrator's more restrictive policy.
            command("iptables", "-I", "FORWARD", "2", "-d", "198.19.0.2", "-j", "DROP")
            command(*client, "ping", "-n", "-c", "1", "-W", "1", "198.19.0.2", success=False)
            command("iptables", "-D", "FORWARD", "-d", "198.19.0.2", "-j", "DROP")
            permitted = restricted.model_copy(deep=True)
            policy = permitted.network.wireguard_interfaces[0].server_access
            assert policy
            policy.router_access, policy.wan_interface = True, "lan-policy"
            runtime.check(restricted, permitted)
            runtime.snapshot(restricted)
            runtime.apply(restricted, permitted)
            command(*client, "ping", "-n", "-c", "1", "-W", "1", "198.19.1.2")
            command(*client, "ping", "-n", "-c", "1", "-W", "1", "10.77.0.1")
            # Restore the initial network configuration through a fresh valid transaction.
            runtime.check(permitted, target)
            runtime.snapshot(permitted)
            runtime.apply(permitted, target)
            assert "-A INPUT -j ACCEPT" in runtime.filters.snapshot()
            assert "-A FORWARD -j ACCEPT" in runtime.filters.snapshot()
            assert "filter" in healthy
        finally:
            command("ip", "link", "del", "lan-policy")
            destination.terminate()
            destination.wait(timeout=5)


def namespace_dns_and_tools(directory: Path) -> None:
    driver = LinuxNetworkDriver(directory)
    empty = NetworkConfiguration()
    target = NetworkConfiguration(
        addresses=[IpAddress(interface="lan-test", address="10.55.0.1/24")],
        dns=DnsSettings(enabled=True, listen_interfaces=["lan-test"], servers=["192.0.2.53"]),
        dns_static=[DnsStaticRecord(name="nas.test", address="10.55.0.20", ttl=60)],
    )
    snapshot = driver.snapshot(empty)
    try:
        driver.check(empty, target)
        driver.apply(empty, target)
        question = b"\x03nas\x04test\x00" + struct.pack("!HH", 1, 1)
        packet = struct.pack("!6H", 0x2747, 0x0100, 1, 0, 0, 0) + question
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver:
            resolver.settimeout(3)
            resolver.sendto(packet, ("10.55.0.1", 53))
            response, _ = resolver.recvfrom(4096)
        identity, flags, _, answers, _, _ = struct.unpack("!6H", response[:12])
        assert identity == 0x2747 and flags & 15 == 0 and answers == 1
        assert socket.inet_ntoa(response[-4:]) == "10.55.0.20"
        assert struct.unpack("!I", response[-10:-6])[0] == 60

        diagnostics = NetworkDiagnostics(False)
        for tool in ("ping", "traceroute", "dns", "route"):
            request = DiagnosticRequest(
                tool=tool, target="localhost" if tool == "dns" else "127.0.0.1"
            )
            result = diagnostics.run(request)
            assert result["success"] and not result["demo"], (tool, result)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
            result = diagnostics.run(
                DiagnosticRequest(tool="tcp", target="127.0.0.1", port=listener.getsockname()[1])
            )
            assert result["success"]
            accepted, _ = listener.accept()
            with accepted:
                accepted.settimeout(3)
                assert accepted.recv(16) == b"", "TCP diagnostic must send no application payload"
    finally:
        driver.rollback(snapshot)


@pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("NAT_RUN_KERNEL_TESTS") != "1",
    reason="Opt-in root test confined to new Linux network namespaces",
)
def test_real_wireguard_handshake_ipv4_policy_kill_switch_and_recovery() -> None:
    for utility in ("unshare", "nsenter", "ip", "wg", "ping", "iptables-save", "dnsmasq"):
        assert shutil.which(utility), f"Install {utility} for the isolated Linux test"
    result = subprocess.run(
        ["unshare", "--net", sys.executable, str(Path(__file__).resolve()), "--namespace"],
        capture_output=True,
        text=True,
        timeout=110,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
    )
    assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    assert sys.argv[1:] == ["--namespace"]
    with tempfile.TemporaryDirectory() as temporary:
        try:
            namespace_scenario(Path(temporary))
            namespace_dns_and_tools(Path(temporary) / "dns-tools")
        except Exception:
            # Only public routes/rules from this disposable namespace, never wg dump.
            print("Namespace IP rules:", command("ip", "-4", "-N", "-j", "rule"), file=sys.stderr)
            print(
                "Namespace IP routes:",
                command("ip", "-4", "-N", "-j", "route", "show", "table", "all"),
                file=sys.stderr,
            )
            raise
