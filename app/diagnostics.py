"""Bounded, full-role network diagnostics; no shell, scripts, URLs or payload probes."""

import asyncio
import codecs
import os
import shutil
import socket
import subprocess
import threading
import time
from collections import deque
from collections.abc import AsyncGenerator
from contextlib import aclosing
from typing import Any, Literal

import anyio
from pydantic import Field, field_validator

from app.ipv4 import endpoint_host, ipv4
from app.link_models import LinkModel
from app.wireguard import WireGuardError

Tool = Literal["ping", "traceroute", "dns", "route", "tcp"]
MAX_OUTPUT_BYTES = 32768
DIAGNOSTIC_WALL_SECONDS = 20.0
PROCESS_SECONDS = 14.0
RESOLUTION_SECONDS = 3.0
POLL_SECONDS = 0.1
DiagnosticEvent = dict[str, Any]


class DiagnosticRequest(LinkModel):
    tool: Tool
    target: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)

    _target = field_validator("target")(endpoint_host)


def diagnostic_command(tool: Tool, address: str) -> list[str]:
    binary = {"ping": "ping", "traceroute": "traceroute", "dns": "getent", "route": "ip"}.get(tool)
    if not binary or not (path := shutil.which(binary)):
        raise WireGuardError(f"Install the {binary or tool} utility to run this diagnostic")
    arguments = {
        "ping": ["-4", "-n", "-c", "4", "-W", "1", "-w", "6", address],
        "traceroute": ["-4", "-n", "-I", "-m", "12", "-q", "1", "-w", "1", address],
        "dns": ["ahostsv4", address],
        "route": ["-4", "-j", "route", "get", address],
    }
    command = [path, *arguments[tool]]
    # Linux ping/traceroute normally flush each response. Where supported,
    # explicitly request line buffering when their stdout is a pipe.
    if tool in ("ping", "traceroute") and (buffer := shutil.which("stdbuf")):
        command = [buffer, "-oL", "-eL", *command]
    return command


class NetworkDiagnostics:
    def __init__(self, demo: bool) -> None:
        self.demo = demo
        self.lock = threading.Lock()
        self.requests: deque[float] = deque()

    def run(self, request: DiagnosticRequest) -> dict[str, Any]:
        """Compatibility API consumes the same bounded runner as live output."""

        async def collect() -> dict[str, Any]:
            async with aclosing(self.stream(request)) as events:
                async for event in events:
                    if event is not None and event["type"] == "completed":
                        result: dict[str, Any] = event["result"]
                        return result
            raise WireGuardError("Diagnostic ended without a result")

        return asyncio.run(collect())

    async def stream(
        self, request: DiagnosticRequest
    ) -> AsyncGenerator[DiagnosticEvent | None, None]:
        """Yield live events; None lets the transport check disconnect/auth while idle.

        The caller must close this iterator on disconnect. Closing it reaps any
        subprocess and releases the shared admission lock, including between chunks.
        """
        if not self.lock.acquire(blocking=False):
            raise WireGuardError("Another diagnostic is running; wait for its result")
        try:
            started = time.monotonic()
            while self.requests and self.requests[0] < started - 60:
                self.requests.popleft()
            if len(self.requests) >= 12:
                raise WireGuardError("Diagnostics are limited to 12 runs per minute")
            self.requests.append(started)
            yield {"type": "started", "tool": request.tool, "target": request.target}
            if self.demo:
                result = {
                    "tool": request.tool,
                    "target": request.target,
                    "address": "",
                    "demo": True,
                    "success": False,
                    "elapsed_ms": 0,
                    "output": (
                        "Деморежим: диагностика доступна после установки на Linux. "
                        "Сеть компьютера не опрашивается."
                    ),
                }
                yield {"type": "output", "text": result["output"]}
                yield {"type": "completed", "result": result}
                return

            address = request.target
            if request.tool != "dns":
                try:
                    address = ipv4(request.target)
                except ValueError:
                    # Resolve through the same cancellable bounded process runner;
                    # do not leave a blocking getaddrinfo or resolver thread behind.
                    output = ""
                    success = False
                    async with aclosing(
                        self._command(
                            diagnostic_command("dns", request.target),
                            min(
                                started + DIAGNOSTIC_WALL_SECONDS,
                                time.monotonic() + RESOLUTION_SECONDS,
                            ),
                        )
                    ) as steps:
                        async for event in steps:
                            if event is None:
                                yield None
                            elif "text" in event:
                                output += event["text"]
                            else:
                                success = event["exit_code"] == 0
                    if success:
                        for line in output.splitlines()[:32]:
                            try:
                                address = ipv4(line.split()[0])
                            except (ValueError, IndexError):
                                continue
                            break
                        else:
                            success = False
                    if not success:
                        raise WireGuardError(
                            "Cannot resolve the diagnostic target to IPv4"
                        ) from None

            output = ""
            success = False
            if request.tool == "tcp":
                # Connect only: send no request, credentials or application payload.
                async with aclosing(self._tcp(ipv4(address), request.port)) as steps:
                    async for event in steps:
                        if event is None:
                            yield None
                        else:
                            success = event["exit_code"] == 0
                output = (
                    f"TCP {address}:{request.port}: connected"
                    if success
                    else f"TCP {address}:{request.port}: unavailable or timed out"
                )
                yield {"type": "output", "text": output}
            else:
                arguments = diagnostic_command(request.tool, address)
                async with aclosing(
                    self._command(
                        arguments,
                        min(started + DIAGNOSTIC_WALL_SECONDS, time.monotonic() + PROCESS_SECONDS),
                    )
                ) as steps:
                    async for event in steps:
                        if event is None:
                            yield None
                        elif "text" in event:
                            output += event["text"]
                            yield {"type": "output", "text": event["text"]}
                        else:
                            success = event["exit_code"] == 0
            result = {
                "tool": request.tool,
                "target": request.target,
                "address": address,
                "demo": False,
                "success": success,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "output": output,
            }
            yield {"type": "completed", "result": result}
        finally:
            self.lock.release()

    @staticmethod
    async def _command(
        arguments: list[str], deadline: float
    ) -> AsyncGenerator[DiagnosticEvent | None, None]:
        """One cancellable subprocess, bounded reads and an incremental UTF-8 decoder."""
        try:
            process = await asyncio.create_subprocess_exec(
                *arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env={"PATH": os.defpath, "LC_ALL": "C", "PYTHONUNBUFFERED": "1"},
                limit=8192,
            )
        except OSError as exc:
            raise WireGuardError("Diagnostic utility could not be started") from exc
        assert process.stdout is not None
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        total = 0
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    yield {"exit_code": -1}
                    return
                try:
                    chunk = await asyncio.wait_for(
                        process.stdout.read(4096), min(POLL_SECONDS, remaining)
                    )
                except TimeoutError:
                    yield None
                    continue
                if not chunk:
                    tail = decoder.decode(b"", final=True)
                    if tail:
                        yield {"text": tail}
                    break
                total += len(chunk)
                if total > MAX_OUTPUT_BYTES:
                    raise WireGuardError("Diagnostic output exceeded the 32 KiB limit")
                text = decoder.decode(chunk)
                if text:
                    yield {"text": text}
            try:
                code = await asyncio.wait_for(
                    process.wait(), max(0.001, deadline - time.monotonic())
                )
            except TimeoutError:
                code = -1
            yield {"exit_code": code}
        finally:
            with anyio.CancelScope(shield=True):
                if process.returncode is None:
                    process.kill()
                # Drain the bounded pipe backlog after killing. Process.wait()
                # alone can hang if the StreamReader paused on excessive output.
                await process.communicate()

    @staticmethod
    async def _tcp(address: str, port: int) -> AsyncGenerator[DiagnosticEvent | None, None]:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.setblocking(False)
        task = asyncio.create_task(
            asyncio.get_running_loop().sock_connect(connection, (address, port))
        )
        deadline = time.monotonic() + 4
        try:
            while not task.done() and time.monotonic() < deadline:
                await asyncio.wait({task}, timeout=POLL_SECONDS)
                if not task.done():
                    yield None
            success = False
            if task.done():
                try:
                    task.result()
                    success = True
                except OSError:
                    pass  # An unreachable service is a normal diagnostic result.
            yield {"exit_code": 0 if success else -1}
        finally:
            connection.close()
            with anyio.CancelScope(shield=True):
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
