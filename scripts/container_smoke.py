"""Exercise the built image in demo mode with no capabilities or external network."""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, cast


def request(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    operation = urllib.request.Request(
        "http://127.0.0.1:8088/api/" + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-NAT-Request": "1"},
    )
    with urllib.request.urlopen(operation, timeout=5) as response:
        return cast(dict[str, Any], json.load(response))


def main() -> None:
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
        ],
        stdout=subprocess.DEVNULL,
    )
    try:
        for attempt in range(100):
            try:
                health = request("health")
                break
            except (OSError, urllib.error.URLError):
                if process.poll() is not None or attempt == 99:
                    raise RuntimeError("The built container did not become healthy") from None
                time.sleep(0.1)
        assert health["mode"] == "demo" and health["status"] == "ok"
        for utility in ("wg", "ip", "dnsmasq", "ping", "traceroute", "getent"):
            from shutil import which

            assert which(utility), f"The image is missing {utility}"
        saved = request(
            "wireguard/server", {"revision": 0, "name": "wg-ci", "endpoint": "192.0.2.1"}
        )
        saved = request(
            "wireguard/peers",
            {"revision": saved["revision"], "interface": "wg-ci", "name": "Container test"},
        )
        peer = saved["config"]["network"]["wireguard_peers"][0]
        profile = request("wireguard/export", {"object_id": peer["id"]})
        assert "PrivateKey = " in profile["configuration"]
        assert profile["qr_data_url"].startswith("data:image/svg+xml;base64,")
        assert request("preview", {})["valid"]
        pending = request("apply", {"revision": saved["revision"]})["pending"]
        assert not request("confirm", {"token": pending["token"]})["dirty"]
        status = request("wireguard/status")
        assert status["demo"] and not status["interfaces"][0]["peers"][0]["connected"]
        print("Container healthy; VPN setup, QR, preview and confirmed demo apply passed.")
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    main()
