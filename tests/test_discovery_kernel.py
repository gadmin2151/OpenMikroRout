"""Opt-in Nmap acceptance: all traffic stays inside two fresh network namespaces."""

import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.discovery import DiscoveryService
from app.discovery_models import DiscoverySettings, ScanRequest, ScanSettings
from app.scans import ScanService


def command(*arguments: str) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, (arguments, result.stderr)
    return result.stdout


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
        settings = ScanSettings(enabled=True, interfaces=["scan-test"], timeout_seconds=30)
        hosts = DiscoveryService(directory, False, DiscoverySettings)
        service = ScanService(directory, False, lambda: settings, hosts.ingest_scan)
        try:
            command("ip", "link", "add", "scan-test", "type", "veth", "peer", "name", "scan-peer")
            command("ip", "link", "set", "scan-peer", "netns", pid)
            command("ip", "address", "add", "198.18.0.1/30", "dev", "scan-test")
            command("ip", "link", "set", "scan-test", "up")
            command(*prefix, "ip", "link", "set", "lo", "up")
            command(*prefix, "ip", "address", "add", "198.18.0.2/30", "dev", "scan-peer")
            command(*prefix, "ip", "link", "set", "scan-peer", "up")
            # A reachable service outside the selected interface's connected subnet.
            command(*prefix, "ip", "address", "add", "198.19.0.2/32", "dev", "lo")
            command("ip", "route", "add", "198.19.0.0/30", "via", "198.18.0.2", "dev", "scan-test")
            for protocol in ("tcp", "udp"):
                command(
                    *prefix,
                    "iptables",
                    "-A",
                    "INPUT",
                    "-p",
                    protocol,
                    "--dport",
                    "44446",
                    "-j",
                    "DROP",
                )
            code = """
import socket,threading,time
tcp=socket.socket(); tcp.bind(('0.0.0.0',44444)); tcp.listen()
def answer(udp):
    while True:
        data,peer=udp.recvfrom(2048); udp.sendto(b'probe-response',peer)
for address in ('198.18.0.2','198.19.0.2'):
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind((address,44444))
    threading.Thread(target=answer,args=(udp,),daemon=True).start()
print('ready',flush=True)
time.sleep(90)
"""
            listener = subprocess.Popen(
                [*prefix, sys.executable, "-u", "-c", code], stdout=subprocess.PIPE, text=True
            )
            assert listener.stdout and listener.stdout.readline().strip() == "ready"
            requests = [
                ScanRequest(kind="network", interface="scan-test", target="198.18.0.0/30"),
                ScanRequest(
                    kind="ports",
                    interface="scan-test",
                    target="198.18.0.2",
                    profile="custom",
                    ports="44444-44446",
                ),
                ScanRequest(kind="network", interface="scan-test", target="198.19.0.0/30"),
                ScanRequest(
                    kind="ports",
                    interface="scan-test",
                    target="198.19.0.2",
                    profile="custom",
                    ports="44444-44446",
                ),
                ScanRequest(
                    kind="ports",
                    interface="scan-test",
                    target="198.19.0.2",
                    profile="udp",
                    ports="44444-44446",
                ),
                ScanRequest(
                    kind="ports",
                    interface="scan-test",
                    target="198.18.0.2",
                    profile="udp",
                    ports="44444-44446",
                ),
            ]
            for request in requests:
                job = service.start(request)
                deadline = time.monotonic() + 35
                while job["state"] in ("queued", "running") and time.monotonic() < deadline:
                    time.sleep(0.1)
                    job = service.job(job["id"])
                assert job["state"] == "completed", job
                destination = "198.19.0.2" if request.target.startswith("198.19.") else "198.18.0.2"
                found = next(
                    host for host in job["result"]["hosts"] if destination in host["addresses"]
                )
                assert found["state"] == "up"
                if request.kind == "ports":
                    states = {port["state"] for port in found["ports"]}
                    states.update(extra["state"] for extra in found["other_ports"])
                    assert "open" in states and "closed" in states, found
                    assert (
                        "open|filtered" if request.profile == "udp" else "filtered"
                    ) in states, found
            assert hosts.hosts(query="198.18.0.2")["total"] == 1
            assert hosts.hosts(query="198.19.0.2")["total"] == 1
        finally:
            service.close()
            hosts.close()
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
def test_nmap_network_and_tcp_udp_states_in_isolated_namespaces(tmp_path: Path) -> None:
    unshare = shutil.which("unshare")
    assert unshare and shutil.which("nmap")
    code = (
        "from pathlib import Path; "
        "from tests.test_discovery_kernel import namespace_scenario; "
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
