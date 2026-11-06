"""Opt-in real ipset/NAT/filter traffic tests confined to a new network namespace."""

import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from app.compiler import FirewallError, patch
from app.filtering import LinuxFilterDriver, filter_patch, filter_rollback
from app.firewall import LinuxDriver
from app.ipsets import LinuxIPSetDriver
from app.models import Configuration


def command(*args: str, success: bool = True) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=10)
    assert (result.returncode == 0) == success, (args, result.stderr)
    return result.stdout


def scenario(directory: Path) -> None:
    command("ip", "link", "set", "lo", "up")
    command("ip", "address", "add", "1.1.1.1/32", "dev", "lo")
    command("ipset", "create", "administrator_set", "hash:ip")
    command("ipset", "add", "administrator_set", "9.9.9.9")
    sets = LinuxIPSetDriver(directory)
    sets.ensure_country("geo_AU", ["1.1.1.0/24"])
    command("ipset", "test", "omr_geo_AU", "1.1.1.1")
    sets.ensure_temporary("f2b_test")
    sets.add_temporary("f2b_test", "1.1.1.1", 2)
    command("ipset", "test", "omr_f2b_test", "1.1.1.1")
    assert sets.temporary_entries("f2b_test")[0]["address"] == "1.1.1.1"
    time.sleep(2.2)
    command("ipset", "test", "omr_f2b_test", "1.1.1.1", success=False)
    assert sets.temporary_entries("f2b_test") == []

    # Foreign sets, including colliding reserved names, remain unchanged.
    command("ipset", "create", "omr_geo_US", "hash:net")
    command("ipset", "add", "omr_geo_US", "8.8.8.0/24")
    try:
        sets.replace_country("geo_US", ["9.9.9.0/24"])
    except FirewallError:
        pass
    else:
        raise AssertionError("A foreign reserved set was overwritten")
    command("ipset", "test", "omr_geo_US", "8.8.8.8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 55332))
        server.settimeout(0.25)

        def send(port: int, receive: bool) -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind(("1.1.1.1", 0))
                client.sendto(b"omr-kernel-test", ("127.0.0.1", port))
            try:
                payload, _ = server.recvfrom(128)
            except TimeoutError:
                assert not receive, "Expected packet did not arrive"
            else:
                assert receive and payload == b"omr-kernel-test", "Blocked packet arrived"

        send(55332, True)
        filters = LinuxFilterDriver()
        filters_before = filters.snapshot()
        configuration = Configuration.model_validate(
            {
                "system_lists": [{"name": "geo_AU", "kind": "country", "country": "AU"}],
                "filter_rules": [
                    {
                        "name": "Country input",
                        "chain": "input",
                        "action": "drop",
                        "protocol": "udp",
                        "src_list": "geo_AU",
                        "dst_ports": "55332",
                    }
                ],
            }
        )
        filters.restore(filter_patch(filters.snapshot(), configuration), test=True)
        send(55332, True)
        filters.restore(filter_patch(filters.snapshot(), configuration))
        send(55332, False)
        filters.restore(filter_rollback(filters.snapshot(), filters_before))
        send(55332, True)

        nat = LinuxDriver()
        configuration = Configuration.model_validate(
            {
                "system_lists": [{"name": "geo_AU", "kind": "country", "country": "AU"}],
                "rules": [
                    {
                        "name": "Country NAT",
                        "chain": "output",
                        "protocol": "udp",
                        "src_list": "geo_AU",
                        "dst_ports": "55333",
                        "to_address": "127.0.0.1",
                        "to_ports": "55332",
                    }
                ],
            }
        )
        nat.restore(patch(nat.snapshot(), configuration), test=True)
        nat.restore(patch(nat.snapshot(), configuration))
        send(55333, True)
        sets.replace_country("geo_AU", ["2.2.2.0/24"])
        send(55333, False)
        sets.replace_country("geo_AU", ["1.1.1.0/24"])
        send(55333, True)
        # Invalid staging does not destroy the active country set.
        try:
            sets.replace_country("geo_AU", ["not-an-address"])
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid network accepted")
        send(55333, True)
    command("ipset", "test", "administrator_set", "9.9.9.9")
    assert "omr_stage_" not in command("ipset", "list", "-name")


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Requires opt-in Linux root; all mutations use a fresh network namespace",
)
def test_system_lists_real_kernel() -> None:
    assert shutil.which("unshare"), "Install util-linux"
    with tempfile.TemporaryDirectory() as directory:
        code = (
            "import runpy; from pathlib import Path; "
            f"runpy.run_path('tests/test_system_lists_kernel.py')['scenario'](Path({directory!r}))"
        )
        result = subprocess.run(
            ["unshare", "--net", sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Requires opt-in Linux tools; uses isolated private engine and network namespace",
)
def test_private_engine_drains_before_pinned_updater_snapshot() -> None:
    code = r"""
import shutil, sqlite3, subprocess, sys, tempfile, threading, time
from pathlib import Path
from app.fail2ban_models import F2BConfiguration
from app.fail2ban_runtime import Fail2banService
from app.fail2ban_maintenance import stop_private_engine
from app.ipsets import LinuxIPSetDriver
with tempfile.TemporaryDirectory(prefix='omr-drain-') as temporary:
    data=Path(temporary)/'data'
    service=Fail2banService(data,False,LinuxIPSetDriver(data))
    service.initialize_files(F2BConfiguration())
    process=subprocess.Popen([sys.executable,'-m','app.fail2ban_runtime','daemon',
                              '--data-dir',str(data)],stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            try:
                if 'pong' in service._client(['ping']).lower(): break
            except Exception:
                time.sleep(.1)
        else: raise AssertionError('Private engine did not become ready')
        assert service.socket.exists()
        # A real systemd manager reaps this process concurrently with the main stop hook.
        reaper=threading.Thread(target=process.wait,daemon=True)
        reaper.start()
        stop_private_engine(data)
        reaper.join(timeout=2)
        assert process.returncode == 0
        assert not service.socket.exists()
        assert not service.pidfile.exists()
        backup=Path(temporary)/'backup'
        shutil.copytree(data,backup,
            ignore=shutil.ignore_patterns('*.sqlite3-wal','*.sqlite3-shm','*.lock'))
        with sqlite3.connect(backup/'fail2ban'/'engine.sqlite3') as db:
            assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    finally:
        service.journal.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
"""
    result = subprocess.run(
        ["unshare", "--net", sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        timeout=50,
    )
    assert result.returncode == 0, result.stdout + result.stderr
