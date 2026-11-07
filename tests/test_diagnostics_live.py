import asyncio
import json
import sys
import time
from collections.abc import AsyncGenerator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import aclosing
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect
from starlette.types import Message, Scope

from app.diagnostics import DiagnosticRequest, NetworkDiagnostics, diagnostic_command
from app.main import DiagnosticStreamResponse, Settings, create_app
from app.wireguard import WireGuardError

PASSWORD = "test-only-live-diagnostics-password"
HEADERS = {"X-NAT-Request": "1"}
REQUEST = DiagnosticRequest(tool="ping", target="127.0.0.1")


def child_command(code: str) -> list[str]:
    return [sys.executable, "-u", "-c", code]


async def next_event(
    stream: AsyncGenerator[dict[str, Any] | None, None],
) -> dict[str, Any]:
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
    return children


def test_output_is_emitted_before_completion_and_final_result_is_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    gate = tmp_path / "continue"
    command = child_command(
        "import time; from pathlib import Path; print('first', flush=True); "
        f"gate=Path({str(gate)!r});\n"
        "while not gate.exists(): time.sleep(.01)\n"
        "print('second', flush=True)"
    )
    monkeypatch.setattr("app.diagnostics.diagnostic_command", lambda *_: command)
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        async with aclosing(service.stream(REQUEST)) as stream:
            assert (await next_event(stream))["type"] == "started"
            first = await next_event(stream)
            assert first == {"type": "output", "text": "first\n"}
            assert processes[0].returncode is None and not gate.exists()
            gate.touch()
            remaining = [event async for event in stream if event is not None]
        assert remaining[-1]["type"] == "completed"
        result = remaining[-1]["result"]
        assert result["output"] == "first\nsecond\n" and result["success"]
        assert result["address"] == "127.0.0.1" and not result["demo"]
        assert processes[0].returncode == 0 and not service.lock.locked()

    asyncio.run(scenario())


def test_close_between_output_chunks_reaps_process_and_releases_shared_admission(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import time; print('first', flush=True); time.sleep(30)"),
    )
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        stream = service.stream(REQUEST)
        await next_event(stream)
        assert (await next_event(stream))["text"] == "first\n"
        with pytest.raises(WireGuardError, match="Another diagnostic"):
            await asyncio.to_thread(service.run, REQUEST)
        started = time.monotonic()
        await stream.aclose()
        assert time.monotonic() - started < 2
        assert processes[0].returncode is not None
        assert not service.lock.locked()
        service.demo = True
        assert (await asyncio.to_thread(service.run, REQUEST))["demo"]

    asyncio.run(scenario())


def test_legacy_and_live_diagnostics_share_the_same_rate_limit() -> None:
    service = NetworkDiagnostics(True)

    async def consume() -> None:
        events = [event async for event in service.stream(REQUEST) if event is not None]
        assert events[-1]["result"]["demo"]

    for index in range(12):
        if index % 2:
            assert service.run(REQUEST)["demo"]
        else:
            asyncio.run(consume())
    with pytest.raises(WireGuardError, match="12 runs per minute"):
        service.run(REQUEST)
    with pytest.raises(WireGuardError, match="12 runs per minute"):
        asyncio.run(consume())
    assert len(service.requests) == 12 and not service.lock.locked()


def test_output_limit_terminates_the_process_without_retaining_unbounded_data(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr("app.diagnostics.MAX_OUTPUT_BYTES", 100)
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import time; print('x'*200, flush=True); time.sleep(30)"),
    )
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        async with aclosing(service.stream(REQUEST)) as stream:
            with pytest.raises(WireGuardError, match="output exceeded"):
                async for event in stream:
                    if event is not None and event["type"] == "output":
                        assert len(event["text"]) <= 100

    asyncio.run(scenario())
    assert processes[0].returncode is not None and not service.lock.locked()


def test_flooded_pipe_is_drained_after_kill_instead_of_deadlocking_cleanup(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import os; os.write(1,b'x'*1_000_000)"),
    )
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        async with asyncio.timeout(3), aclosing(service.stream(REQUEST)) as stream:
            with pytest.raises(WireGuardError, match="output exceeded"):
                async for _ in stream:
                    pass

    asyncio.run(scenario())
    assert processes[0].returncode is not None and not service.lock.locked()


def test_asgi_cancellation_while_waiting_for_output_reaps_the_process(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import time; time.sleep(30)"),
    )
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        async def consume() -> None:
            async with aclosing(service.stream(REQUEST)) as stream:
                async for _ in stream:
                    pass

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(consume)
            while not processes:
                await asyncio.sleep(0.01)
            tasks.cancel_scope.cancel()
        assert processes[0].returncode is not None and not service.lock.locked()

    asyncio.run(scenario())


def test_quiet_process_obeys_timeout_and_returns_a_failed_legacy_compatible_result(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr("app.diagnostics.PROCESS_SECONDS", 0.15)
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import time; print('waiting', flush=True); time.sleep(30)"),
    )
    service = NetworkDiagnostics(False)
    started = time.monotonic()
    result = service.run(REQUEST)
    assert time.monotonic() - started < 2
    assert not result["success"] and result["output"] == "waiting\n"
    assert processes[0].returncode is not None and not service.lock.locked()


def test_partial_utf8_characters_are_preserved_across_live_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command(
            "import os,time; os.write(1,b'\\xd0'); time.sleep(.03); "
            "os.write(1,b'\\x9f\\xd1\\x80\\xd0\\xb8\\xd0\\xb2\\xd0\\xb5\\xd1\\x82\\n')"
        ),
    )
    result = NetworkDiagnostics(False).run(REQUEST)
    assert result["success"] and result["output"] == "Привет\n"


def test_cancellation_during_hostname_resolution_reaps_the_resolver(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import time; time.sleep(30)"),
    )
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        stream = service.stream(DiagnosticRequest(tool="ping", target="router.example"))
        await anext(stream)
        assert await anext(stream) is None
        await stream.aclose()
        assert processes[0].returncode is not None and not service.lock.locked()

    asyncio.run(scenario())


def test_tcp_live_check_closes_without_sending_application_data() -> None:
    async def scenario() -> None:
        received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

        async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                received.set_result(await reader.read(16))
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        async with server:
            request = DiagnosticRequest(
                tool="tcp", target="127.0.0.1", port=server.sockets[0].getsockname()[1]
            )
            events = [
                event
                async for event in NetworkDiagnostics(False).stream(request)
                if event is not None
            ]
            assert events[-1]["result"]["success"]
            assert await asyncio.wait_for(received, 1) == b""

    asyncio.run(scenario())


def test_command_arguments_remain_fixed_and_never_invoke_a_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.diagnostics.shutil.which", lambda name: f"/usr/bin/{name}")
    assert diagnostic_command("ping", "127.0.0.1") == [
        "/usr/bin/stdbuf",
        "-oL",
        "-eL",
        "/usr/bin/ping",
        "-4",
        "-n",
        "-c",
        "4",
        "-W",
        "1",
        "-w",
        "6",
        "127.0.0.1",
    ]
    assert diagnostic_command("dns", "router.example") == [
        "/usr/bin/getent",
        "ahostsv4",
        "router.example",
    ]


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
    result = client.post(
        "/api/login", headers=HEADERS, json={"username": username, "password": PASSWORD}
    )
    assert result.status_code == 200


def test_stream_requires_fresh_full_access_same_origin_and_validated_targets(
    client: TestClient,
) -> None:
    body = {"tool": "ping", "target": "127.0.0.1"}
    assert client.post("/api/tools/stream", headers=HEADERS, json=body).status_code == 401
    login(client, "viewer")
    assert client.post("/api/tools/stream", headers=HEADERS, json=body).status_code == 403
    client.post("/api/logout", headers=HEADERS)
    login(client)
    assert client.post("/api/tools/stream", json=body).status_code == 403
    assert (
        client.post(
            "/api/tools/stream",
            headers={**HEADERS, "Origin": "https://untrusted.example"},
            json=body,
        ).status_code
        == 403
    )
    for change in (
        {"target": "$(id)"},
        {"target": "127.0.0.1;reboot"},
        {"target": "https://example.com"},
        {"tool": "shell"},
        {"script": "id"},
    ):
        assert (
            client.post("/api/tools/stream", headers=HEADERS, json={**body, **change}).status_code
            == 422
        )


def test_demo_ndjson_is_incremental_in_shape_and_matches_the_legacy_result(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login(client)

    async def forbidden(*_: Any, **__: Any) -> None:
        pytest.fail("demo diagnostics must never start a subprocess")

    monkeypatch.setattr("app.diagnostics.asyncio.create_subprocess_exec", forbidden)
    body = {"tool": "ping", "target": "router.example"}
    response = client.post("/api/tools/stream", headers=HEADERS, json=body)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-ndjson"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-accel-buffering"] == "no"
    events = [json.loads(line) for line in response.text.splitlines()]
    assert [event["type"] for event in events] == ["started", "output", "completed"]
    legacy = client.post("/api/tools/run", headers=HEADERS, json=body)
    assert events[-1]["result"] == legacy.json()
    assert events[1]["text"] == legacy.json()["output"]


def test_logout_during_a_quiet_process_stops_further_output_and_reaps_child(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    processes: list[asyncio.subprocess.Process],
) -> None:
    marker = tmp_path / "started"
    gate = tmp_path / "continue"
    command = child_command(
        "import time; from pathlib import Path; "
        f"Path({str(marker)!r}).touch(); print('first', flush=True); "
        f"gate=Path({str(gate)!r});\n"
        "while not gate.exists(): time.sleep(.01)\n"
        "print('SECRET_AFTER_REVOKE', flush=True)"
    )
    monkeypatch.setattr("app.diagnostics.diagnostic_command", lambda *_: command)
    app = client.app
    app.state.diagnostics.demo = False  # type: ignore[attr-defined]
    login(client)
    token = client.cookies.get("nat_session")
    assert token
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            client.post, "/api/tools/stream", headers=HEADERS, json=REQUEST.model_dump()
        )
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        try:
            assert marker.exists()
            app.state.auth.logout(token)  # type: ignore[attr-defined]
            response = pending.result(timeout=3)
        finally:
            gate.touch()
    events = [json.loads(line) for line in response.text.splitlines()]
    assert events[-1]["type"] == "error"
    assert "SECRET_AFTER_REVOKE" not in response.text
    assert not any(event["type"] == "completed" for event in events)
    assert processes[0].returncode is not None
    assert not app.state.diagnostics.lock.locked()  # type: ignore[attr-defined]


def test_stream_socket_send_failure_closes_a_suspended_runner(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import time; print('first', flush=True); time.sleep(30)"),
    )
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        async def events() -> AsyncGenerator[str, None]:
            async with aclosing(service.stream(REQUEST)) as stream:
                async for event in stream:
                    if event is not None:
                        yield json.dumps(event) + "\n"

        async def send(message: Message) -> None:
            if message["type"] == "http.response.body" and b"first" in message.get("body", b""):
                raise OSError("client disconnected")

        async def receive() -> Message:
            await asyncio.sleep(30)
            return {"type": "http.disconnect"}

        scope: Scope = {"type": "http", "asgi": {"spec_version": "2.4"}}
        with pytest.raises(ClientDisconnect):
            await DiagnosticStreamResponse(events())(scope, receive, send)
        assert processes[0].returncode is not None and not service.lock.locked()

    asyncio.run(scenario())


def test_wall_limit_closes_a_runner_when_the_client_stops_consuming_output(
    monkeypatch: pytest.MonkeyPatch, processes: list[asyncio.subprocess.Process]
) -> None:
    monkeypatch.setattr("app.main.DIAGNOSTIC_WALL_SECONDS", 0.05)
    monkeypatch.setattr(
        "app.diagnostics.diagnostic_command",
        lambda *_: child_command("import time; print('first', flush=True); time.sleep(30)"),
    )
    service = NetworkDiagnostics(False)

    async def scenario() -> None:
        async def events() -> AsyncGenerator[str, None]:
            async with aclosing(service.stream(REQUEST)) as stream:
                async for event in stream:
                    if event is not None:
                        yield json.dumps(event) + "\n"

        async def send(message: Message) -> None:
            if message["type"] == "http.response.body" and b"first" in message.get("body", b""):
                await asyncio.sleep(30)  # Simulate a connected consumer that stopped reading.

        async def receive() -> Message:
            await asyncio.sleep(30)
            return {"type": "http.disconnect"}

        scope: Scope = {"type": "http", "asgi": {"spec_version": "2.4"}}
        started = time.monotonic()
        await DiagnosticStreamResponse(events())(scope, receive, send)
        assert time.monotonic() - started < 3
        assert processes[0].returncode is not None and not service.lock.locked()

    asyncio.run(scenario())
