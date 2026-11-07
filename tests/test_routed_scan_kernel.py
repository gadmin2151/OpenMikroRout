"""Opt-in Nmap over real WireGuard; no packets leave fresh network namespaces."""

import ipaddress
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Literal

import pytest

from app.discovery_models import ScanRequest, ScanSettings
from app.scans import ScanService
from app.wireguard_vault import WireGuardVault


def command(*arguments: str, payload: str | None = None) -> str:
    result = subprocess.run(
        arguments, input=payload, capture_output=True, text=True, check=False, timeout=10
    )
    assert result.returncode == 0, (arguments, result.stderr)
    return result.stdout


def wait_for_job(service: ScanService, request: ScanRequest) -> dict[str, Any]:
    job = service.start(request)
    deadline = time.monotonic() + 35
    while job["state"] in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(0.1)
        job = service.job(job["id"])
    assert job["state"] == "completed", job
    return job


def namespace_scenario(directory: Path) -> None:
    command("ip", "link", "set", "lo", "up")
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
    ) as remote:
        assert remote.stdout
        pid = remote.stdout.readline().strip()
        assert pid.isdigit()
        prefix = ["nsenter", "-t", pid, "-n"]
        listener: subprocess.Popen[str] | None = None
        service: ScanService | None = None
        try:
            vault = WireGuardVault(directory)
            own, peer = vault.create("interface"), vault.create("peer-client")
            for name in ("wg-scan", "wg-peer"):
                command("ip", "link", "add", name, "type", "wireguard")
            # Both WireGuard transport sockets are born in this isolated outer
            # namespace and communicate only over its loopback. The remote netdev
            # moves afterward, so no host NIC, bridge, route or firewall is touched.
            command(
                "wg",
                "setconf",
                "wg-scan",
                "/dev/stdin",
                payload=(
                    f"[Interface]\nPrivateKey={vault.secret(own.id, 'interface')}\n"
                    "ListenPort=51821\n[Peer]\n"
                    f"PublicKey={peer.public_key}\n"
                    "AllowedIPs=198.18.1.2/32,198.19.0.0/30\n"
                    "Endpoint=127.0.0.1:51822\nPersistentKeepalive=1\n"
                ),
            )
            command(
                "wg",
                "setconf",
                "wg-peer",
                "/dev/stdin",
                payload=(
                    f"[Interface]\nPrivateKey={vault.secret(peer.id, 'peer-client')}\n"
                    "ListenPort=51822\n[Peer]\n"
                    f"PublicKey={own.public_key}\nAllowedIPs=198.18.1.1/32\n"
                    "Endpoint=127.0.0.1:51821\nPersistentKeepalive=1\n"
                ),
            )
            command("ip", "address", "add", "198.18.1.1/32", "dev", "wg-scan")
            command("ip", "link", "set", "wg-scan", "up")
            command("ip", "route", "add", "198.18.1.2/32", "dev", "wg-scan")
            command("ip", "route", "add", "198.19.0.0/30", "dev", "wg-scan")
            command("ip", "link", "set", "wg-peer", "netns", pid)
            command(*prefix, "ip", "link", "set", "lo", "up")
            command(*prefix, "ip", "address", "add", "198.18.1.2/32", "dev", "wg-peer")
            command(*prefix, "ip", "address", "add", "198.19.0.2/32", "dev", "lo")
            command(*prefix, "ip", "link", "set", "wg-peer", "up")
            command(*prefix, "ip", "route", "add", "198.18.1.1/32", "dev", "wg-peer")
            command("ping", "-n", "-c", "2", "-W", "2", "-I", "wg-scan", "198.19.0.2")
            route = json.loads(command("ip", "-j", "-4", "route", "get", "198.19.0.2"))[0]
            assert route["dev"] == "wg-scan", route
            assert int(command("wg", "show", "wg-scan", "latest-handshakes").split()[1]) > 0
            code = """
import socket,threading,time
tcp=socket.socket(); tcp.bind(('0.0.0.0',44444)); tcp.listen()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind(('198.19.0.2',44444))
def answer():
    while True:
        data,peer=udp.recvfrom(2048); udp.sendto(b'probe-response',peer)
threading.Thread(target=answer,daemon=True).start()
print('ready',flush=True)
time.sleep(90)
"""
            listener = subprocess.Popen(
                [*prefix, sys.executable, "-u", "-c", code], stdout=subprocess.PIPE, text=True
            )
            assert listener.stdout and listener.stdout.readline().strip() == "ready"
            settings = ScanSettings(enabled=True, interfaces=["wg-scan"], timeout_seconds=30)
            service = ScanService(directory, False, lambda: settings)
            connected = service.status()["networks"]["wg-scan"]
            assert connected == ["198.18.1.1/32"], connected
            assert all(
                ipaddress.IPv4Address("198.19.0.2") not in ipaddress.IPv4Network(network)
                for network in connected
            )
            profiles: tuple[Literal["custom", "udp"], ...] = ("custom", "udp")
            for protocol in profiles:
                job = wait_for_job(
                    service,
                    ScanRequest(
                        kind="ports",
                        interface="wg-scan",
                        target="198.19.0.2",
                        profile=protocol,
                        ports="44444-44445",
                    ),
                )
                found = next(
                    host for host in job["result"]["hosts"] if "198.19.0.2" in host["addresses"]
                )
                ports = {port["port"]: port["state"] for port in found["ports"]}
                assert ports.get(44444) == "open", found
                states = {port["state"] for port in found["ports"]}
                states.update(extra["state"] for extra in found["other_ports"])
                assert "closed" in states, found
            job = wait_for_job(
                service,
                ScanRequest(kind="network", interface="wg-scan", target="198.19.0.0/30"),
            )
            found = next(
                host for host in job["result"]["hosts"] if "198.19.0.2" in host["addresses"]
            )
            assert found["state"] == "up", found
        finally:
            if service:
                service.close()
            if listener:
                listener.terminate()
                listener.wait(timeout=3)
                if listener.stdout:
                    listener.stdout.close()
            remote.terminate()
            remote.wait(timeout=3)


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Requires opt-in Linux namespaces; never scans the host or external networks",
)
def test_real_nmap_scans_remote_ipv4_beyond_wireguard_connected_cidr(tmp_path: Path) -> None:
    unshare = shutil.which("unshare")
    assert unshare and shutil.which("nmap") and shutil.which("wg")
    code = (
        "from pathlib import Path; "
        "from tests.test_routed_scan_kernel import namespace_scenario; "
        f"namespace_scenario(Path({str(tmp_path)!r}))"
    )
    result = subprocess.run(
        [unshare, "--net", sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=100,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
