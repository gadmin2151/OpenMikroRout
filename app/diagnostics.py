"""Bounded, full-role network diagnostics; no shell, scripts, URLs or payload probes."""

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections import deque
from typing import Any, Literal

from pydantic import Field, field_validator

from app.ipv4 import endpoint_host, ipv4
from app.link_models import LinkModel
from app.wireguard import WireGuardError, resolve_ipv4

Tool = Literal["ping", "traceroute", "dns", "route", "tcp"]


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
    return [path, *arguments[tool]]


class NetworkDiagnostics:
    def __init__(self, demo: bool) -> None:
        self.demo = demo
        self.lock = threading.Lock()
        self.requests: deque[float] = deque()

    def run(self, request: DiagnosticRequest) -> dict[str, Any]:
        if not self.lock.acquire(blocking=False):
            raise WireGuardError("Another diagnostic is running; wait for its result")
        try:
            started = time.monotonic()
            while self.requests and self.requests[0] < started - 60:
                self.requests.popleft()
            if len(self.requests) >= 12:
                raise WireGuardError("Diagnostics are limited to 12 runs per minute")
            self.requests.append(started)
            if self.demo:
                return {
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
            address = resolve_ipv4(request.target) if request.tool != "dns" else request.target
            if request.tool == "tcp":
                # Connect only: send no request, credentials or application payload.
                try:
                    with socket.create_connection((ipv4(address), request.port), timeout=4):
                        output, success = f"TCP {address}:{request.port}: connected", True
                except OSError:
                    output, success = (
                        f"TCP {address}:{request.port}: unavailable or timed out",
                        False,
                    )
            else:
                arguments = diagnostic_command(request.tool, address)
                with tempfile.TemporaryFile() as stream:
                    try:
                        result = subprocess.run(
                            arguments,
                            stdout=stream,
                            stderr=stream,
                            timeout=14,
                            check=False,
                            env={"PATH": os.defpath, "LC_ALL": "C"},
                        )
                        success = result.returncode == 0
                    except subprocess.TimeoutExpired:
                        success = False
                    except OSError as exc:
                        raise WireGuardError("Diagnostic utility could not be started") from exc
                    stream.seek(0)
                    output = stream.read(32768).decode("utf-8", errors="replace")
            return {
                "tool": request.tool,
                "target": request.target,
                "address": address,
                "demo": False,
                "success": success,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "output": output,
            }
        finally:
            self.lock.release()
