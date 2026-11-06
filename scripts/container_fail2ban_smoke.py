"""Verify opt-in native Fail2ban lifecycle in an isolated, constrained Linux container."""

import http.cookiejar
import json
import os
import secrets
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, cast

BASE = "http://127.0.0.1:8088"
DATA = Path(os.environ.get("OMR_DATA_DIR", "/data"))


def main() -> None:
    password = secrets.token_urlsafe(32)
    environment = {
        **os.environ,
        "OMR_MODE": "linux",
        "OMR_ADMIN_PASSWORD": password,
        "OMR_FAIL2BAN_COMPANION": "1",
        "OMR_MONITOR_ENABLED": "0",
    }
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def request(
        path: str, body: dict[str, Any] | None = None, method: str | None = None
    ) -> dict[str, Any]:
        operation = urllib.request.Request(
            BASE + "/api/" + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Content-Type": "application/json", "X-NAT-Request": "1", "Origin": BASE},
        )
        with opener.open(operation, timeout=30) as response:
            return cast(dict[str, Any], json.load(response))

    def start() -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                "8088",
                "--no-access-log",
                "--no-proxy-headers",
            ],
            env=environment,
        )
        for _ in range(150):
            try:
                assert request("health")["mode"] == "linux"
                request("login", {"username": "admin", "password": password})
                assert (DATA / "fail2ban" / "engine.sock").exists()
                return process
            except (OSError, urllib.error.URLError):
                if process.poll() is not None:
                    raise RuntimeError("The Linux container did not become healthy") from None
                time.sleep(0.1)
        process.terminate()
        process.wait(timeout=15)
        raise RuntimeError("The Linux container startup timed out")

    def stop(process: subprocess.Popen[bytes]) -> None:
        companion_pid = int((DATA / "fail2ban" / "engine.pid").read_text())
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise AssertionError("The app failed to stop its Fail2ban companion") from None
        # Uvicorn may re-raise SIGTERM after completing its graceful shutdown.
        assert process.returncode in (0, -signal.SIGTERM)
        try:
            os.kill(companion_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("The app left a running Fail2ban companion after shutdown")
        assert not (DATA / "fail2ban" / "engine.sock").exists()

    def configure(enabled: bool, confirm: bool = True) -> None:
        state = request("state")
        state["config"]["fail2ban"]["enabled"] = enabled
        state = request("config", {"revision": state["revision"], "config": state["config"]}, "PUT")
        assert request("preview", {})["valid"]
        pending = request(
            "apply", {"revision": state["revision"], "proof": {"password": password}}
        )["pending"]
        if confirm:
            request("confirm", {"token": pending["token"]})

    process = start()
    try:
        assert not request("security/fail2ban")["enabled"]
        configure(True)
        status = request("security/fail2ban")
        assert status["running"] and status["effective"] and not status["demo"]
        configure(False, confirm=False)
        stop(process)
        # Graceful app shutdown must roll back the unconfirmed disable before stopping its engine.
        with sqlite3.connect(DATA / "linux.sqlite3") as database:
            applied = json.loads(
                database.execute("SELECT value FROM state WHERE key='applied'").fetchone()[0]
            )
            assert applied["fail2ban"]["enabled"]
        process = start()
        assert request("security/fail2ban")["effective"]
        configure(False)
        stop(process)
        print(
            "Restricted Linux container: startup, authenticated apply, companion, "
            "shutdown rollback and restart passed."
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
