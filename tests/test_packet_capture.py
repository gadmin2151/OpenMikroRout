import asyncio
import json
import os
import sys
import time
from collections.abc import AsyncGenerator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import aclosing
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.diagnostics import DiagnosticRequest, NetworkDiagnostics
from app.main import Settings, create_app
from app.packet_capture import CaptureRequest, PacketCapture, capture_command
from app.wireguard import WireGuardError

PASSWORD = "test-only-packet-capture-password"
HEADERS = {"X-NAT-Request": "1"}


def command(code: str) -> list[str]:
    return [sys.executable, "-u", "-c", code]


async def next_event(stream: AsyncGenerator[dict[str, Any] | None, None]) -> dict[str, Any]:
    async with asyncio.timeout(3):
        while True:
            event = await anext(stream)
            if event is not None:
                return event


@pytest.fixture
def processes(monkeypatch: pytest.MonkeyPatch) -> list[asyncio.subprocess.Process]:
    children: list[asyncio.subprocess.Process] = []
    create = asyncio.create_subprocess_exec

    async def capture(*arguments: Any, **options: Any) -> asyncio.subprocess.Process:
        child = await create(*arguments, **options)
        children.append(child)
        return child

    monkeypatch.setattr("app.diagnostics.asyncio.create_subprocess_exec", capture)
    monkeypatch.setattr("app.packet_capture.socket.if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    monkeypatch.setattr("app.packet_capture.shutil.which", lambda _: "/usr/bin/tcpdump")
    return children


def test_capture_filter_is_typed_ipv4_only_and_does_not_accept_arbitrary_expressions() -> None:
    request = CaptureRequest(
        interface="eth0", protocol="tcp", source="192.0.2.17/24", destination="10.0.0.8", port=443
    )
    assert request.source == "192.0.2.0/24" and request.destination == "10.0.0.8/32"
    args = capture_command("/usr/bin/tcpdump", request)
    assert args == [
        "/usr/bin/tcpdump",
        "-nn",
        "-l",
        "-tttt",
        "-q",
        "-p",
        "-i",
        "eth0",
        "-s",
        "96",
        *(["-Z", "root"] if os.geteuid() == 0 else []),
        "--",
        "ip",
        "and",
        "tcp",
        "and",
        "src",
        "net",
        "192.0.2.0/24",
        "and",
        "dst",
        "net",
        "10.0.0.8/32",
        "and",
        "port",
        "443",
    ]
    assert not any(flag in args for flag in ("-A", "-X", "-x", "-w", "-r", "-F", "-z"))
    assert capture_command("tcpdump", CaptureRequest(interface="any", port=53))[-10:] == [
        "ip",
        "and",
        "(",
        "tcp",
        "or",
        "udp",
        ")",
        "and",
        "port",
        "53",
    ]
    assert capture_command("tcpdump", CaptureRequest(interface="lo", protocol="icmp"))[-3:] == [
        "ip",
        "and",
        "icmp",
    ]


def test_negated_capture_criteria_are_grouped_fixed_bpf_tokens() -> None:
    request = CaptureRequest(
        interface="eth0",
        protocol="tcp",
        source="192.0.2.0/24",
        destination="198.51.100.9",
        port=443,
        negate=["protocol", "source", "destination", "port"],
    )
    args = capture_command("tcpdump", request)
    assert args[args.index("--") + 1 :] == [
        "ip",
        "and",
        "not",
        "(",
        "tcp",
        ")",
        "and",
        "(",
        "tcp",
        "or",
        "udp",
        ")",
        "and",
        "not",
        "(",
        "src",
        "net",
        "192.0.2.0/24",
        ")",
        "and",
        "not",
        "(",
        "dst",
        "net",
        "198.51.100.9/32",
        ")",
        "and",
        "not",
        "(",
        "port",
        "443",
        ")",
    ]
    # Inverting a port remains scoped to TCP/UDP even when no protocol was chosen.
    no_protocol = capture_command(
        "tcpdump", CaptureRequest(interface="any", port=53, negate=["port"])
    )
    assert no_protocol[no_protocol.index("--") + 1 :] == [
        "ip",
        "and",
        "(",
        "tcp",
        "or",
        "udp",
        ")",
        "and",
        "not",
        "(",
        "port",
        "53",
        ")",
    ]
    assert CaptureRequest(
        interface="lo", source="192.0.2.1", negate=["source", "source"]
    ).negate == ["source"]
    # !ICMP with a port has a well-defined TCP/UDP meaning; positive ICMP does not.
    assert CaptureRequest(interface="lo", protocol="icmp", port=53, negate=["protocol"]).port == 53


def test_capture_advanced_expression_is_typed_grouped_and_independent_of_quick_filters() -> None:
    request = CaptureRequest.model_validate(
        {
            "interface": "lo",
            "protocol": "udp",
            "expression": {
                "kind": "group",
                "join": "or",
                "children": [
                    {
                        "kind": "condition",
                        "field": "source",
                        "op": "in",
                        "value": "192.0.2.0/24,198.51.100.0/24",
                    },
                    {"kind": "condition", "field": "port", "op": "neq", "value": "53"},
                ],
            },
        }
    )
    args = capture_command("tcpdump", request)
    assert args[args.index("--") + 1 :][:4] == ["ip", "and", "udp", "and"]
    assert "or" in args and "not" in args
    assert "192.0.2.0/24" in args and "198.51.100.0/24" in args
    # Port protocol guards belong inside their leaf; source OR port must not
    # impose TCP/UDP on the source branch or change acquisition interface.
    assert args[args.index("-i") + 1] == "lo"
    assert request.expression is not None
    assert CaptureRequest.model_validate(request.model_dump()).expression == request.expression


@pytest.mark.parametrize(
    "change",
    [
        {"interface": "eth0;id"},
        {"interface": "-i"},
        {"interface": "../../etc/passwd"},
        {"source": "1.1.1.1 or ip6"},
        {"destination": "$(id)"},
        {"source": "::1"},
        {"source": "router.example"},
        {"port": "443"},
        {"port": True},
        {"port": 0},
        {"port": 65536},
        {"protocol": "icmp", "port": 53},
        {"protocol": "ip6"},
        {"filter": "tcp or udp"},
        {"flags": "-X"},
        {"file": "/tmp/capture.pcap"},
        {"negate": ["source"]},
        {"negate": ["destination"]},
        {"negate": ["port"]},
        {"protocol": "all", "negate": ["protocol"]},
        {"negate": ["interface"]},
        {"negate": [""]},
        {"negate": ["protocol;id"]},
        {"source": "192.0.2.1", "negate": ["source"] * 5},
        {"source": "192.0.2.1", "negate": "source"},
        {"expression": {"kind": "condition", "field": "interface", "op": "eq", "value": "lo"}},
        {
            "expression": {
                "kind": "condition",
                "field": "protocol",
                "op": "contains",
                "value": "tcp",
            }
        },
        {"expression": {"kind": "condition", "field": "port", "op": "eq", "value": "443 or ip6"}},
        {"expression": {"kind": "condition", "field": "source", "op": "in", "value": "::/0"}},
        {
            "expression": {
                "kind": "condition",
                "field": "source",
                "op": "eq",
                "value": "192.0.2.0/24",
            }
        },
        {"expression": {"kind": "condition", "field": "source", "op": "empty", "value": ""}},
    ],
)
def test_invalid_fields_cannot_turn_into_options_or_payload_capture(
    change: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        CaptureRequest.model_validate({"interface": "eth0", **change})


def test_capture_status_enumerates_system_interfaces_without_running_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def interfaces() -> list[tuple[int, str]]:
        calls.append("if_nameindex")
        return [(1, "lo"), (2, "eth0"), (3, "vmbr0"), (4, "eth0"), (5, "bad;name")]

    monkeypatch.setattr("app.packet_capture.socket.if_nameindex", interfaces)
    monkeypatch.setattr("app.packet_capture.shutil.which", lambda _: "/usr/bin/tcpdump")
    status = PacketCapture(False).status()
    assert status["available"] and not status["demo"]
    assert status["interfaces"] == ["any", "eth0", "lo", "vmbr0"]
    assert calls == ["if_nameindex"]


def test_capture_cannot_start_on_an_interface_outside_the_current_host(
    processes: list[asyncio.subprocess.Process],
) -> None:
    service = PacketCapture(False)

    async def scenario() -> None:
        with pytest.raises(WireGuardError, match="not available on this host"):
            async for _ in service.stream(CaptureRequest(interface="otherhost0")):
                pass

    asyncio.run(scenario())
    assert not processes and not service.lock.locked()


def test_packet_capture_and_ping_have_independent_admission_locks(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.packet_capture.capture_command",
        lambda *_: command("import time; print('IPv4 header', flush=True); time.sleep(30)"),
    )
    capture = PacketCapture(False)

    async def scenario() -> None:
        stream = capture.stream(CaptureRequest(interface="eth0"))
        assert (await next_event(stream))["tool"] == "capture"
        assert (await next_event(stream))["text"] == "IPv4 header\n"
        assert (
            await asyncio.to_thread(
                NetworkDiagnostics(True).run, DiagnosticRequest(tool="ping", target="127.0.0.1")
            )
        )["demo"]
        async with aclosing(capture.stream(CaptureRequest(interface="eth0"))) as second:
            with pytest.raises(WireGuardError, match="Another packet capture"):
                await anext(second)
        await stream.aclose()
        assert processes[0].returncode is not None and not capture.lock.locked()

    asyncio.run(scenario())


def test_partial_capture_output_arrives_before_exit_and_cancellation_reaps_process(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.packet_capture.capture_command",
        lambda *_: command(
            "import time; print('IP 10.0.0.1.1 > 10.0.0.2.2: UDP, length 8', flush=True); "
            "time.sleep(30)"
        ),
    )
    service = PacketCapture(False)

    async def scenario() -> None:
        stream = service.stream(CaptureRequest(interface="eth0", protocol="udp"))
        assert (await next_event(stream))["continuous"] is True
        assert "UDP, length 8" in (await next_event(stream))["text"]
        assert processes[0].returncode is None
        await stream.aclose()
        assert processes[0].returncode is not None and not service.lock.locked()

    asyncio.run(scenario())


def test_capture_flood_is_batched_and_retains_only_a_bounded_recent_tail(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.packet_capture.capture_command",
        lambda *_: command("import os; os.write(1,('header\\n'*50_000+'LAST HEADER\\n').encode())"),
    )
    service = PacketCapture(False)

    async def scenario() -> None:
        async with aclosing(service.stream(CaptureRequest(interface="eth0"))) as stream:
            events = [event async for event in stream if event is not None]
        outputs = [event["text"] for event in events if event["type"] == "output"]
        result = events[-1]["result"]
        assert result["success"] and result["output_truncated"]
        assert len(result["output"].encode()) <= 32768
        assert result["output"].endswith("LAST HEADER\n")
        assert all(len(text.encode()) <= 8192 for text in outputs)
        assert len(outputs) < 10  # Packet count does not drive browser updates.
        assert processes[0].returncode == 0 and not service.lock.locked()

    asyncio.run(scenario())


def test_capture_start_rate_is_bounded_and_releases_the_lock_after_rejection() -> None:
    service = PacketCapture(True)

    async def consume() -> None:
        async for _ in service.stream(CaptureRequest(interface="any")):
            pass

    for _ in range(12):
        asyncio.run(consume())
    with pytest.raises(WireGuardError, match="12 starts per minute"):
        asyncio.run(consume())
    assert len(service.requests) == 12 and not service.lock.locked()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(
        create_app(
            Settings(
                data_dir=tmp_path, auth_enabled=True, password=PASSWORD, read_password=PASSWORD
            )
        )
    ) as connection:
        yield connection


def login(client: TestClient, username: str = "admin") -> None:
    assert (
        client.post(
            "/api/login", headers=HEADERS, json={"username": username, "password": PASSWORD}
        ).status_code
        == 200
    )


def test_capture_status_and_start_keep_auth_csrf_and_read_only_boundaries(
    client: TestClient,
) -> None:
    body = {"interface": "any", "protocol": "udp", "port": 53}
    assert client.get("/api/tools/capture/status").status_code == 401
    assert client.post("/api/tools/capture/stream", headers=HEADERS, json=body).status_code == 401
    login(client, "viewer")
    assert client.get("/api/tools/capture/status").status_code == 200
    assert client.post("/api/tools/capture/stream", headers=HEADERS, json=body).status_code == 403
    client.post("/api/logout", headers=HEADERS)
    login(client)
    assert client.post("/api/tools/capture/stream", json=body).status_code == 403
    assert (
        client.post(
            "/api/tools/capture/stream",
            headers={**HEADERS, "Origin": "https://foreign.example"},
            json=body,
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/tools/capture/stream", headers=HEADERS, json={**body, "filter": "ip"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/tools/capture/stream",
            headers=HEADERS,
            json={**body, "negate": ["source"]},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/tools/capture/stream",
            headers=HEADERS,
            json={**body, "negate": ["port"]},
        ).status_code
        == 200
    )


def test_demo_capture_is_inert_and_uses_the_shared_ndjson_protocol(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden() -> list[tuple[int, str]]:
        pytest.fail("demo capture must not inspect host interfaces")

    async def no_process(*_: Any, **__: Any) -> None:
        pytest.fail("demo capture must not start a process")

    monkeypatch.setattr("app.packet_capture.socket.if_nameindex", forbidden)
    monkeypatch.setattr("app.diagnostics.asyncio.create_subprocess_exec", no_process)
    login(client)
    response = client.post("/api/tools/capture/stream", headers=HEADERS, json={"interface": "any"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-ndjson"
    assert response.headers["cache-control"] == "no-store"
    events = [json.loads(line) for line in response.text.splitlines()]
    assert [event["type"] for event in events] == ["started", "output", "completed"]
    assert events[0]["tool"] == events[-1]["result"]["tool"] == "capture"
    assert events[-1]["result"]["demo"] and isinstance(events[-1]["result"]["output"], str)


def test_capture_expression_keeps_full_access_and_api_validation(client: TestClient) -> None:
    body = {
        "interface": "any",
        "expression": {"kind": "condition", "field": "port", "op": "not_in", "value": "53,80"},
    }
    login(client, "viewer")
    assert client.post("/api/tools/capture/stream", headers=HEADERS, json=body).status_code == 403
    client.post("/api/logout", headers=HEADERS)
    login(client)
    assert client.post("/api/tools/capture/stream", headers=HEADERS, json=body).status_code == 200
    body["expression"] = {"kind": "condition", "field": "interface", "op": "eq", "value": "lo"}
    assert client.post("/api/tools/capture/stream", headers=HEADERS, json=body).status_code == 422


@pytest.mark.parametrize("reason", ["logout", "update"])
def test_capture_rechecks_session_and_queued_updates_while_idle(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    processes: list[asyncio.subprocess.Process],
    reason: str,
) -> None:
    marker = tmp_path / "started"
    gate = tmp_path / "finish"
    monkeypatch.setattr(
        "app.packet_capture.capture_command",
        lambda *_: command(
            "import time; from pathlib import Path; "
            f"Path({str(marker)!r}).touch(); print('first header', flush=True); "
            f"gate=Path({str(gate)!r});\n"
            "while not gate.exists(): time.sleep(.01)\nprint('AFTER_REVOKE', flush=True)"
        ),
    )
    app = client.app
    app.state.packet_capture.demo = False  # type: ignore[attr-defined]
    updating = [False]
    monkeypatch.setattr(app.state.updates, "active", lambda: updating[0])  # type: ignore[attr-defined]
    login(client)
    token = client.cookies.get("nat_session")
    assert token
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            client.post, "/api/tools/capture/stream", headers=HEADERS, json={"interface": "eth0"}
        )
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        try:
            assert marker.exists()
            if reason == "logout":
                app.state.auth.logout(token)  # type: ignore[attr-defined]
            else:
                updating[0] = True
            response = pending.result(timeout=3)
        finally:
            gate.touch()
    events = [json.loads(line) for line in response.text.splitlines()]
    assert events[-1]["type"] == "error"
    assert "AFTER_REVOKE" not in response.text
    assert not any(event["type"] == "completed" for event in events)
    assert processes[0].returncode is not None
    assert not app.state.packet_capture.lock.locked()  # type: ignore[attr-defined]
