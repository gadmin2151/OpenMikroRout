import json
import os
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from app.discovery_io import DiscoveryError, bounded_command, connected_networks
from app.discovery_models import ScanRequest, ScanSettings
from app.network_models import IpAddress, NetworkConfiguration
from app.scans import ScanOutput, ScanService, parse_host, scan_command, validated_target


def test_target_must_be_allowed_connected_unicast_and_network_bounded() -> None:
    settings = ScanSettings(enabled=True, interfaces=["eth0"])
    networks = {"eth0": ["10.0.0.0/24"]}
    valid = ScanRequest(kind="ports", interface="eth0", target="10.0.0.2")
    assert validated_target(valid, settings, networks) == "10.0.0.2"
    for address in ("127.0.0.1", "10.0.1.2", "10.0.0.0", "10.0.0.255"):
        with pytest.raises(DiscoveryError):
            validated_target(valid.model_copy(update={"target": address}), settings, networks)
    with pytest.raises(DiscoveryError):
        validated_target(valid, ScanSettings(), networks)
    with pytest.raises(DiscoveryError):
        validated_target(
            ScanRequest(kind="network", interface="eth0", target="10.0.0.0/16"),
            settings,
            {"eth0": ["10.0.0.0/16"]},
        )
    assert (
        validated_target(
            ScanRequest(kind="network", interface="eth0", target="10.0.0.0/24"), settings, networks
        )
        == "10.0.0.0/24"
    )


def test_nmap_arguments_are_fixed_and_preserve_explicit_scan_intent() -> None:
    settings = ScanSettings(enabled=True, interfaces=["eth0"])
    quick = ScanRequest(kind="ports", interface="eth0", target="10.0.0.2")
    command = scan_command("/usr/bin/nmap", quick, settings, "10.0.0.2")
    assert "-sS" in command and "--top-ports" in command
    assert "-sV" not in command and "--script" not in command
    assert command[-1] == "10.0.0.2"
    live = scan_command("/usr/bin/nmap", quick, settings, "10.0.0.2", "/dev/fd/99")
    assert "-v" in live and live[live.index("-oX") + 1] == "/dev/fd/99"
    assert live[-1] == "10.0.0.2"
    udp = quick.model_copy(update={"profile": "udp", "ports": "53,123", "service_detection": True})
    command = scan_command("/usr/bin/nmap", udp, settings, "10.0.0.2")
    assert "-sU" in command and "-sV" in command and "53,123" in command
    network = ScanRequest(kind="network", interface="eth0", target="10.0.0.0/24")
    assert "-sn" in scan_command("/usr/bin/nmap", network, settings, network.target)


def test_result_preserves_open_closed_filtered_and_udp_uncertainty() -> None:
    ports = "".join(
        f'<port protocol="tcp" portid="{index + 20}"><state state="{state}"/>'
        '<service name="ssh" method="probed" conf="10" '
        'product="Server &lt;X&gt;" version="1" ostype="Linux &lt;test&gt;"/></port>'
        for index, state in enumerate(["open", "closed", "filtered", "open|filtered"])
    )
    host = parse_host(
        ET.fromstring(
            '<host><status state="up" reason="syn-ack"/>'
            f'<address addrtype="ipv4" addr="10.0.0.2"/><ports>{ports}'
            '<extraports state="closed" count="96"/></ports></host>'
        )
    )
    assert [row["state"] for row in host["ports"]] == [
        "open",
        "closed",
        "filtered",
        "open|filtered",
    ]
    assert host["ports"][0]["product"] == "Server <X>"
    assert host["os_guesses"] == ["Linux <test>"]
    assert host["ports"][0]["os_guess"] == "Linux <test>"
    assert host["other_ports"] == [{"state": "closed", "count": 96}]


def test_demo_is_inert_and_history_persists(tmp_path: Path) -> None:
    settings = ScanSettings(enabled=True, interfaces=["br-lan"])
    service = ScanService(tmp_path, True, lambda: settings)
    job = service.start(ScanRequest(kind="network", interface="br-lan", target="192.168.10.0/24"))
    deadline = time.monotonic() + 2
    while service.job(job["id"])["state"] in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(0.01)
    result = service.job(job["id"])
    assert result["state"] == "completed"
    assert result["result"]["demo"] and result["result"]["hosts"] == []
    assert "result" not in service.jobs()["items"][0]
    service.close()
    recovered = ScanService(tmp_path, True, lambda: settings)
    assert recovered.job(job["id"])["state"] == "completed"
    assert recovered.path.stat().st_mode & 0o777 == 0o600


def test_restart_marks_jobs_interrupted(tmp_path: Path) -> None:
    service = ScanService(tmp_path, True, ScanSettings)
    with service.connect() as db:
        db.execute("INSERT INTO jobs VALUES ('old','running',1,1,'{}','10.0.0.2','{}','',10)")
    recovered = ScanService(tmp_path, True, ScanSettings)
    assert recovered.job("old")["state"] == "running"
    recovered.recover()
    assert recovered.job("old")["state"] == "interrupted"
    assert not recovered.threads


def test_demo_scan_networks_follow_applied_configuration(tmp_path: Path) -> None:
    applied = NetworkConfiguration(
        addresses=[IpAddress(interface="br-lan", address="10.55.0.1/24")]
    )
    service = ScanService(
        tmp_path,
        True,
        ScanSettings,
        network_configuration=lambda: applied,
    )
    networks = service.status()["networks"]
    assert networks["br-lan"] == ["10.55.0.0/24"]
    assert networks["eth0"] == ["203.0.113.0/24"]
    assert "eth1" not in networks and "bridge-lan" not in networks
    applied.addresses = [IpAddress(interface="vlan20", address="192.168.20.1/24")]
    networks = service.status()["networks"]
    assert "br-lan" not in networks
    assert networks["vlan20"] == ["192.168.20.0/24"]


def test_disabled_scan_status_exposes_candidates_without_granting_scan_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = ScanSettings()
    before = settings.model_dump()
    networks = {"vmbr1": ["10.30.0.0/24"], "eth0": ["203.0.113.0/24"]}
    monkeypatch.setattr("app.scans.connected_networks", lambda: networks)
    monkeypatch.setattr("app.scans.shutil.which", lambda _: "/usr/bin/nmap")
    service = ScanService(tmp_path, False, lambda: settings)
    status = service.status()
    assert status["networks"] == networks
    assert status["settings"] == before == settings.model_dump()
    assert not status["settings"]["enabled"] and not status["settings"]["interfaces"]
    for interface, target in (("vmbr1", "10.30.0.2"), ("eth0", "203.0.113.2")):
        with pytest.raises(DiscoveryError, match="disabled for this interface"):
            service.start(ScanRequest(kind="ports", interface=interface, target=target))
    assert service.jobs()["total"] == 0
    assert not service.threads and not service.requests
    assert settings.model_dump() == before


def test_candidate_inventory_does_not_broaden_an_applied_interface_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = ScanSettings(enabled=True, interfaces=["vmbr1", "missing0"])
    networks = {"vmbr1": ["10.30.0.0/24"], "eth0": ["203.0.113.0/24"]}
    monkeypatch.setattr("app.scans.connected_networks", lambda: networks)
    service = ScanService(tmp_path, False, lambda: settings)
    status = service.status()
    assert set(status["networks"]) == {"vmbr1", "eth0"}
    assert status["settings"]["interfaces"] == ["vmbr1", "missing0"]
    assert (
        validated_target(
            ScanRequest(kind="ports", interface="vmbr1", target="10.30.0.2"),
            settings,
            status["networks"],
        )
        == "10.30.0.2"
    )
    for interface, target, message in (
        ("eth0", "203.0.113.2", "disabled for this interface"),
        ("vmbr1", "203.0.113.2", "selected connected network"),
        ("missing0", "10.30.0.2", "no connected IPv4 network"),
    ):
        with pytest.raises(DiscoveryError, match=message):
            service.start(ScanRequest(kind="ports", interface=interface, target=target))
    assert service.jobs()["total"] == 0
    assert not service.threads


def test_linux_candidate_inventory_reads_bridge_and_veth_ipv4_without_changing_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "eth0", "addr_info": []},
        {
            "ifname": "vmbr0",
            "addr_info": [
                {"family": "inet", "local": "203.0.113.17", "prefixlen": 24},
                {"family": "inet6", "local": "2001:db8::17", "prefixlen": 64},
            ],
        },
        {
            "ifname": "vmbr1",
            "addr_info": [{"family": "inet", "local": "10.30.0.1", "prefixlen": 24}],
        },
        {
            "ifname": "veth100i0",
            "addr_info": [{"family": "inet", "local": "192.0.2.14", "prefixlen": 32}],
        },
    ]
    snapshot = json.dumps(rows)
    commands: list[list[str]] = []

    def read_addresses(arguments: list[str]) -> bytes:
        commands.append(arguments)
        return snapshot.encode()

    monkeypatch.setattr("app.discovery_io.shutil.which", lambda _: "/usr/sbin/ip")
    monkeypatch.setattr("app.discovery_io.bounded_command", read_addresses)
    assert connected_networks() == {
        "vmbr0": ["203.0.113.0/24"],
        "vmbr1": ["10.30.0.0/24"],
        "veth100i0": ["192.0.2.14/32"],
    }
    assert commands == [["/usr/sbin/ip", "-j", "-4", "address", "show"]]
    assert json.dumps(rows) == snapshot


def test_runner_parses_live_results_and_bounds_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ScanService(tmp_path, False, ScanSettings)
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addrtype="ipv4" addr="10.0.0.2"/></host></nmaprun>'
    )
    monkeypatch.setattr(
        "app.scans.scan_command",
        lambda *args: [
            sys.executable,
            "-c",
            f"import os,sys; os.write(int(sys.argv[1].rsplit('/', 1)[1]), {xml.encode()!r})",
            args[4],
        ],
    )
    request = ScanRequest(kind="ports", interface="eth0", target="10.0.0.2")
    result: dict[str, Any] = {"hosts": [], "partial": True}
    service._execute(
        "unused", request, ScanSettings(), request.target, "nmap", threading.Event(), result
    )
    assert not result["partial"] and result["hosts"][0]["addresses"] == ["10.0.0.2"]
    monkeypatch.setattr(
        "app.scans.scan_command", lambda *_: [sys.executable, "-c", "import time; time.sleep(10)"]
    )
    event = threading.Event()
    event.set()
    started = time.monotonic()
    with pytest.raises(DiscoveryError, match="cancelled"):
        service._execute("unused", request, ScanSettings(), request.target, "nmap", event, result)
    assert time.monotonic() - started < 3


def test_runner_rejects_xml_entities_and_excess_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ScanService(tmp_path, False, ScanSettings)
    request = ScanRequest(kind="ports", interface="eth0", target="10.0.0.2")
    xml = '<!DOCTYPE nmaprun [<!ENTITY x "bad">]><nmaprun>&x;</nmaprun>'
    monkeypatch.setattr(
        "app.scans.scan_command",
        lambda *args: [
            sys.executable,
            "-c",
            f"import os,sys; os.write(int(sys.argv[1].rsplit('/', 1)[1]), {xml.encode()!r})",
            args[4],
        ],
    )
    with pytest.raises(DiscoveryError, match="XML"):
        service._execute(
            "unused",
            request,
            ScanSettings(),
            request.target,
            "nmap",
            threading.Event(),
            {"hosts": []},
        )
    monkeypatch.setattr("app.scans.MAX_OUTPUT", 100)
    monkeypatch.setattr(
        "app.scans.scan_command", lambda *_: [sys.executable, "-c", "print('x'*200)"]
    )
    with pytest.raises(DiscoveryError, match="limit"):
        service._execute(
            "unused",
            request,
            ScanSettings(),
            request.target,
            "nmap",
            threading.Event(),
            {"hosts": []},
        )


def test_bounded_discovery_adapter_rejects_large_output_and_timeout() -> None:
    assert bounded_command([sys.executable, "-c", "print('{}')"]).strip() == b"{}"
    with pytest.raises(DiscoveryError, match="limit"):
        bounded_command([sys.executable, "-c", "print('x'*1000)"], limit=20)
    with pytest.raises(DiscoveryError, match="timed out"):
        bounded_command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)


@pytest.mark.parametrize("change", ["settings", "network"])
def test_running_scan_stops_when_scope_is_revoked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    allowed = ScanSettings(enabled=True, interfaces=["eth0"])
    service = ScanService(
        tmp_path, False, lambda: ScanSettings() if change == "settings" else allowed
    )
    monkeypatch.setattr(
        "app.scans.scan_command", lambda *_: [sys.executable, "-c", "import time; time.sleep(10)"]
    )
    monkeypatch.setattr("app.scans.SETTINGS_CHECK_SECONDS", 0.01)
    monkeypatch.setattr("app.scans.TOPOLOGY_CHECK_SECONDS", 0.01)
    monkeypatch.setattr("app.scans.connected_networks", lambda: {})
    event = threading.Event()
    request = ScanRequest(kind="ports", interface="eth0", target="10.0.0.2")
    started = time.monotonic()
    with pytest.raises(DiscoveryError, match="cancelled"):
        service._execute("unused", request, allowed, request.target, "nmap", event, {"hosts": []})
    assert event.is_set()
    assert time.monotonic() - started < 3


def test_live_parser_bounds_alerts_scope_and_ports_and_final_xml_is_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.scans.MAX_PORT_RESULTS", 2)
    request = ScanRequest(kind="ports", interface="eth0", target="10.0.0.2")
    result: dict[str, Any] = {"hosts": [], "partial": True}
    output = ScanOutput(request, ScanSettings(max_hosts=1), request.target, result)
    output.xml(b'<nmaprun><taskbegin task="SYN Stealth Scan"/>')
    output.xml(b'<taskprogress task="SYN Stealth Scan" percent="50"/>')
    assert result["phase"] == "scanning" and output.progress == 50
    for percent in ("100", "NaN", "inf"):
        output.xml(f'<taskprogress task="SYN Stealth Scan" percent="{percent}"/>'.encode())
        assert output.progress == 99
    output.interactive(b"x" * 2048)
    assert len(output.console) <= 1024
    output.interactive(b"Discovered open port 80/tcp on 10.0.0.2\n")
    assert not result["hosts"]  # A tail of an oversized line is never a new alert.
    output.interactive(
        b"Discovered open port 22/tcp on 10.0.0.99\n"
        b"Discovered open port 22/udp on 10.0.0.2\n"
        b"Discovered open port 99999/tcp on 10.0.0.2\n"
        b"Discovered open port 22/tcp on 10.0.0."
    )
    assert not result["hosts"]
    output.interactive(b"2\nDiscovered open port 22/tcp on 10.0.0.2\n")
    output.interactive(b"Discovered open port 23/tcp on 10.0.0.2\n")
    output.interactive(b"Discovered open port 24/tcp on 10.0.0.2\n")
    assert len(result["hosts"]) == 1
    assert [port["port"] for port in result["hosts"][0]["ports"]] == [22, 23]
    assert result["hosts"][0]["ports_truncated"]
    output.xml(
        b'<taskend task="SYN Stealth Scan"/><taskbegin task="Service scan"/>'
        b'<host><status state="up"/><address addrtype="ipv4" addr="10.0.0.2"/>'
        b'<ports><port protocol="tcp" portid="22"><state state="open"/>'
        b'<service name="ssh" method="probed"/></port>'
    )
    assert result["phase"] == "services" and output.progress == 0
    assert result["hosts"][0]["ports"][0]["service"] == "ssh"
    output.xml(b"</ports></host></nmaprun>")
    output.parser.close()
    assert [port["port"] for port in result["hosts"][0]["ports"]] == [22]
    assert not result["hosts"][0]["ports_truncated"]
    assert output.completed == {request.target}


@pytest.mark.parametrize("cancel", [False, True])
def test_job_exposes_partial_discoveries_and_phases_before_process_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    settings = ScanSettings(enabled=True, interfaces=["eth0"], timeout_seconds=10)
    monkeypatch.setattr("app.scans.connected_networks", lambda: {"eth0": ["10.0.0.0/24"]})
    monkeypatch.setattr("app.scans.shutil.which", lambda _: sys.executable)
    code = """
import os,sys,time
xml=os.fdopen(int(sys.argv[1].rsplit('/',1)[1]),'w',buffering=1)
xml.write('<nmaprun><taskbegin task="SYN Stealth Scan"/>'
          '<taskprogress task="SYN Stealth Scan" percent="45"/>\\n')
print('Discovered open port 22/tcp on 10.0.0.2',flush=True)
time.sleep(1.2)
xml.write('<taskend task="SYN Stealth Scan"/><taskbegin task="Service scan"/>'
          '<host><status state="up"/><address addrtype="ipv4" addr="10.0.0.2"/>'
          '<ports><port protocol="tcp" portid="22"><state state="open"/>'
          '<service name="ssh" method="probed"/></port>\\n')
time.sleep(1.2)
xml.write('</ports></host></nmaprun>')
xml.close()
"""
    monkeypatch.setattr(
        "app.scans.scan_command", lambda *args: [sys.executable, "-c", code, args[4]]
    )
    callbacks: list[list[dict[str, Any]]] = []
    service = ScanService(
        tmp_path, False, lambda: settings, lambda _, hosts: callbacks.append(hosts)
    )
    try:
        job = service.start(ScanRequest(kind="ports", interface="eth0", target="10.0.0.2"))
        deadline = time.monotonic() + 2
        while not job["result"]["hosts"] and time.monotonic() < deadline:
            time.sleep(0.02)
            job = service.job(job["id"])
        assert job["state"] == "running" and job["progress"] == 45, job
        assert job["result"]["partial"] and job["result"]["phase"] == "scanning"
        assert job["result"]["elapsed_seconds"] >= 0.5
        assert job["result"]["hosts"][0]["ports"][0]["method"] == "discovery"
        assert not callbacks
        if cancel:
            service.cancel(job["id"])
        deadline = time.monotonic() + 4
        phases = set()
        while job["state"] in ("queued", "running") and time.monotonic() < deadline:
            phases.add(job["result"]["phase"])
            time.sleep(0.02)
            job = service.job(job["id"])
        service.close()
        if cancel:
            assert job["state"] == "cancelled" and job["progress"] == 45, job
            assert job["result"]["partial"] and not callbacks
            assert job["result"]["hosts"][0]["ports"]
        else:
            assert "services" in phases
            assert job["state"] == "completed" and job["progress"] == 100, job
            assert job["result"]["phase"] == "completed" and not job["result"]["partial"]
            assert job["result"]["hosts"][0]["ports"][0]["service"] == "ssh"
            assert callbacks and len(callbacks[0]) == 1
    finally:
        service.close()
    assert not service.threads and not service.cancelled


def test_failed_process_start_closes_private_xml_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ScanService(tmp_path, False, ScanSettings)
    request = ScanRequest(kind="ports", interface="eth0", target="10.0.0.2")
    pipe = os.pipe()
    monkeypatch.setattr("app.scans.os.pipe", lambda: pipe)

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise OSError("Nmap unavailable")

    monkeypatch.setattr("app.scans.subprocess.Popen", unavailable)
    with pytest.raises(OSError, match="unavailable"):
        service._execute(
            "unused",
            request,
            ScanSettings(),
            request.target,
            "nmap",
            threading.Event(),
            {"hosts": []},
        )
    for descriptor in pipe:
        with pytest.raises(OSError):
            os.fstat(descriptor)
