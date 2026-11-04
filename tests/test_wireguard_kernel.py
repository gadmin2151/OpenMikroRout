"""Opt-in real Linux WireGuard tests. Every mutation is inside unshare --net."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from app.filtering import LinuxFilterDriver
from app.link_models import WireGuardInterface
from app.links import LinuxLinkDriver
from app.models import Configuration
from app.network_models import IpAddress, NetworkConfiguration
from app.networking import LinuxNetworkDriver
from app.runtime import RouterRuntime
from app.wireguard import LinuxWireGuardDriver
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
        except Exception:
            # Only public routes/rules from this disposable namespace, never wg dump.
            print("Namespace IP rules:", command("ip", "-4", "-N", "-j", "rule"), file=sys.stderr)
            print(
                "Namespace IP routes:",
                command("ip", "-4", "-N", "-j", "route", "show", "table", "all"),
                file=sys.stderr,
            )
            raise
