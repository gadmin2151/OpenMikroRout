import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from app.discovery_io import DiscoveryError, bounded_command
from app.discovery_models import ScanRequest, ScanSettings
from app.network_models import IpAddress, NetworkConfiguration
from app.scans import ScanService, parse_host, scan_command, validated_target


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


def test_runner_parses_live_results_and_bounds_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = ScanService(tmp_path, False, ScanSettings)
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addrtype="ipv4" addr="10.0.0.2"/></host></nmaprun>'
    )
    monkeypatch.setattr(
        "app.scans.scan_command", lambda *_: [sys.executable, "-c", f"print({xml!r})"]
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
        "app.scans.scan_command", lambda *_: [sys.executable, "-c", f"print({xml!r})"]
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
