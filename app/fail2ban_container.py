"""Explicit container-only companion lifecycle, separate from web authentication sessions."""

import os
import subprocess
import sys
import time
from pathlib import Path

from app.compiler import FirewallError
from app.fail2ban_models import F2BConfiguration
from app.fail2ban_runtime import Fail2banService


class ContainerFail2ban:
    def __init__(self, service: Fail2banService) -> None:
        self.service = service
        self.process: subprocess.Popen[bytes] | None = None

    def start(self, confirmed: F2BConfiguration) -> None:
        if os.environ.get("OMR_FAIL2BAN_COMPANION") != "1" or self.service.demo:
            return
        # Root-managed files, not a user HTTP command. Seed the confirmed configuration,
        # then normal recovery resolves any interrupted application before listeners open.
        self.service.initialize_files(confirmed)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "app.fail2ban_runtime",
                "daemon",
                "--data-dir",
                str(self.service.data_dir),
            ],
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.DEVNULL,
            # Inherit container logs; no captured pipe that can fill or leak auth bodies.
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise FirewallError("Fail2ban container companion exited during startup")
                try:
                    if "pong" in self.service._client(["ping"]).lower():
                        return
                except FirewallError:
                    pass  # The bounded readiness loop retries only the local startup socket.
                time.sleep(0.1)
            raise FirewallError("Fail2ban container companion did not become ready")
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None
