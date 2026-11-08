"""Opt-in isolated three-namespace proof for the native application datapath.

No host firewall, host sysctl or existing interface is modified. Run as root only
with OMR_RUN_NATIVE_KERNEL_TESTS=1. Every created process and namespace is owned
by this invocation and cleaned up in finally blocks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--json", action="store_true")
parser.add_argument("--backend-quarantine", action="store_true")
parser.add_argument(
    "--license-profile",
    choices=("lgpl-only", "not-for-profit", "commercial-license"),
    default="lgpl-only",
)
args = parser.parse_args()
if os.geteuid() != 0 or os.environ.get("OMR_RUN_NATIVE_KERNEL_TESTS") != "1":
    raise SystemExit("Requires root and explicit OMR_RUN_NATIVE_KERNEL_TESTS=1")
for tool in ("ip", "iptables", "iptables-save", "sysctl", "python3"):
    if not shutil.which(tool):
        raise SystemExit(f"Missing namespace test tool: {tool}")
binary = args.binary.resolve(strict=True)
if not binary.is_file():
    raise SystemExit("Native binary must be an existing regular file")
inventory_sha256 = ""
manifest_path = binary.parent.parent / "manifest.json"
if manifest_path.is_file():
    manifest = json.loads(manifest_path.read_text())
    inventory = manifest.get("files", {})
    if not isinstance(inventory, dict) or not inventory:
        raise SystemExit("The native bundle inventory is missing")
    root = manifest_path.parent
    for relative, digest in inventory.items():
        path = root / relative
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise SystemExit("The native bundle inventory does not match its actual files")
    inventory_sha256 = hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
capabilities = json.loads(
    subprocess.check_output(
        [str(binary), "capabilities", "--json", "--license-profile", args.license_profile],
        text=True,
        timeout=10,
    )
)
if capabilities.get("test_instrumentation") is not False:
    raise SystemExit("Kernel proof requires the production binary with its complete sandbox")
identity = "omr-app-" + uuid.uuid4().hex[:8]
client, router, server = [identity + suffix for suffix in ("-c", "-r", "-s")]
created: list[str] = []
processes: list[subprocess.Popen[str]] = []


def command(*values: str, namespace: str | None = None) -> str:
    argv = [*values] if namespace is None else ["ip", "netns", "exec", namespace, *values]
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, timeout=15)


def firewall(table: str, *values: str) -> None:
    command("iptables", "-w", "2", "-t", table, *values, namespace=router)


def launch(values: list[str], namespace: str) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        ["ip", "netns", "exec", namespace, *values],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    processes.append(process)
    return process


def line(process: subprocess.Popen[str], timeout: float = 6) -> str:
    if process.stdout is None or not select.select([process.stdout], [], [], timeout)[0]:
        raise AssertionError("Namespace process response timed out")
    value = process.stdout.readline().strip()
    if not value:
        raise AssertionError(f"Namespace process exited: {process.poll()}")
    return value


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(2)


def connection_allowed(connection: subprocess.Popen[str]) -> bool:
    assert connection.stdin is not None
    connection.stdin.write("test\n")
    connection.stdin.flush()
    return line(connection) == "ALLOWED"


def packet_test(connection: subprocess.Popen[str], expected: str) -> None:
    assert connection_allowed(connection) == (expected == "ALLOWED"), expected


SERVER = r"""
import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('198.51.100.2',443));s.listen(16);print('READY',flush=True)
def handle(c):
 try:
  c.settimeout(8)
  while True:
   d=c.recv(4096)
   if not d:break
   c.sendall(d)
 except OSError:pass
 finally:c.close()
while True:
 c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
"""
CLIENT = r"""
import socket,sys
h=b'\x13BitTorrent protocol'+bytes(8)+b'I'*20+b'-OM0001-'+b'P'*12
s=socket.create_connection(('198.51.100.2',443),timeout=3);s.settimeout(2)
def test():
 try:
  s.sendall(h);d=s.recv(4096);print('ALLOWED' if d==h else 'BLOCKED',flush=True)
 except OSError:print('BLOCKED',flush=True)
test()
for line in sys.stdin:
 if line.strip()=='test':test()
 else:break
"""
NEGATIVE = r"""
import socket
try:
 s=socket.create_connection(('198.51.100.2',443),timeout=2);s.settimeout(2)
 s.sendall(b'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n')
 print('LEAKED' if s.recv(4096) else 'BLOCKED',flush=True)
except OSError:print('BLOCKED',flush=True)
"""


def policy(action: str) -> dict[str, Any]:
    return {
        "schema": 1,
        "generation": "b" * 64,
        "epoch": 7,
        "mode": "enforce",
        "engine_license_profile": args.license_profile,
        "interfaces": ["lan"],
        "source_networks": ["192.0.2.0/24"],
        "queue_num": 5089,
        "ct_mask": 0xFFFFFF,
        "ct_valid_bit": 64,
        "ct_pending_bit": 128,
        "ct_epoch_shift": 8,
        "unknown_policy": "firewall",
        "failure_policy": "block",
        "rules": [
            {
                "id": "proof",
                "action": action,
                "application_ids": ["app.bittorrent"],
                "connection_states": [],
            }
        ],
        "catalog": {
            "version": "proof",
            "entries": [
                {
                    "id": "app.bittorrent",
                    "protocol_names": ["BitTorrent"],
                    "allow_over_port_deny": True,
                }
            ],
        },
    }


def start_native(folder: Path, action: str) -> subprocess.Popen[str]:
    config = folder / "policy.json"
    config.write_text(json.dumps(policy(action)))
    (folder / "status.json").unlink(missing_ok=True)
    native = launch(
        [str(binary), "run", "--policy", str(config), "--state-dir", str(folder)], router
    )
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if native.poll() is not None:
            raise AssertionError(
                "Native startup failed: " + (native.stderr.read() if native.stderr else "")
            )
        try:
            status = json.loads((folder / "status.json").read_text())
            if status.get("healthy") is True:
                return native
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise AssertionError("Native readiness timed out")


try:
    for name in (client, router, server):
        command("ip", "netns", "add", name)
        created.append(name)
        command("ip", "-n", name, "link", "set", "lo", "up")
    command(
        "ip",
        "-n",
        router,
        "link",
        "add",
        "lan",
        "type",
        "veth",
        "peer",
        "name",
        "eth0",
        "netns",
        client,
    )
    command(
        "ip",
        "-n",
        router,
        "link",
        "add",
        "wan",
        "type",
        "veth",
        "peer",
        "name",
        "eth0",
        "netns",
        server,
    )
    for ns, interface, address in (
        (client, "eth0", "192.0.2.2/24"),
        (router, "lan", "192.0.2.1/24"),
        (router, "wan", "198.51.100.1/24"),
        (server, "eth0", "198.51.100.2/24"),
    ):
        command("ip", "-n", ns, "address", "add", address, "dev", interface)
        command("ip", "-n", ns, "link", "set", interface, "up")
    command("ip", "-n", client, "route", "add", "default", "via", "192.0.2.1")
    command("ip", "-n", server, "route", "add", "default", "via", "198.51.100.1")
    command("sysctl", "-qw", "net.ipv4.ip_forward=1", namespace=router)
    compiler_proof = None
    if args.backend_quarantine:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from backend_quarantine_probe import verify_compiler

        compiler_proof = verify_compiler(router)
    echo = launch(["python3", "-u", "-c", SERVER], server)
    assert line(echo) == "READY"
    with tempfile.TemporaryDirectory(prefix="omr-native-kernel-") as name:
        folder = Path(name)
        native = start_native(folder, "allow")
        status = json.loads((folder / "status.json").read_text())
        worker = int(status["worker_pid"])
        proc_status = Path(f"/proc/{worker}/status").read_text()
        assert re.search(r"^Uid:\s+65534\s+65534\s+65534\s+65534$", proc_status, re.M)
        assert re.search(r"^CapEff:\s+0+$", proc_status, re.M)
        assert re.search(r"^NoNewPrivs:\s+1$", proc_status, re.M)
        assert re.search(r"^Seccomp:\s+2$", proc_status, re.M)
        limits = Path(f"/proc/{worker}/limits").read_text()
        assert re.search(r"^Max address space\s+268435456\s+268435456\s+bytes[ \t]*$", limits, re.M)
        # Own skb mark is an independent routing/WG-like mark and must survive.
        firewall("mangle", "-A", "FORWARD", "-j", "MARK", "--set-mark", "0x4f4d0001")
        # This fixture alone writes foreign CT bits before the queue to prove
        # that the nested CTA_MARK_MASK preserves them. Production preflight
        # separately rejects foreign CONNMARK writers; this is not its policy.
        firewall(
            "mangle", "-A", "FORWARD", "-j", "CONNMARK", "--set-xmark", "0xa5000000/0xff000000"
        )
        firewall("mangle", "-A", "FORWARD", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "5089")
        for chain in ("OMR_APP", "OMR_PORT", "OMR_LATE", "OMR_SYN"):
            firewall("filter", "-N", chain)
        firewall("filter", "-A", "FORWARD", "-m", "mark", "!", "--mark", "0x4f4d0001", "-j", "DROP")
        firewall("filter", "-A", "FORWARD", "-j", "OMR_APP")
        firewall("filter", "-A", "FORWARD", "-j", "OMR_SYN")
        firewall(
            "filter",
            "-A",
            "OMR_SYN",
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST,ACK",
            "SYN",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-m",
            "connmark",
            "--mark",
            "0xa5000741/0xffffff43",
            "-j",
            "RETURN",
        )
        for state, shift in (("NEW", 0), ("ESTABLISHED", 2), ("RELATED", 4)):
            mask = 0xFFFF00 | 0x40 | (3 << shift)
            firewall(
                "filter",
                "-A",
                "OMR_APP",
                "-m",
                "conntrack",
                "--ctstate",
                state,
                "-m",
                "connmark",
                "--mark",
                f"{0x740 | (3 << shift):#x}/{mask:#x}",
                "-j",
                "DROP",
            )
            for outcome in (1, 2):
                firewall(
                    "filter",
                    "-A",
                    "OMR_PORT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    state,
                    "-m",
                    "connmark",
                    "--mark",
                    f"{0x740 | (outcome << shift):#x}/{mask:#x}",
                    "-j",
                    "RETURN",
                )
        firewall("filter", "-A", "OMR_PORT", "-j", "DROP")
        for flag in ("--dport", "--sport"):
            firewall("filter", "-A", "FORWARD", "-p", "tcp", flag, "443", "-j", "OMR_PORT")
        firewall("filter", "-A", "FORWARD", "-j", "OMR_LATE")
        firewall("filter", "-A", "FORWARD", "-j", "ACCEPT")
        connection = launch(["python3", "-u", "-c", CLIENT], client)
        assert line(connection) == "ALLOWED", (
            "Real BitTorrent must override the eligible port denial"
        )
        saved = command("iptables-save", "-c", "-t", "filter", namespace=router)
        seen = re.search(r"\[(\d+):\d+\] -A OMR_SYN ", saved)
        assert seen and int(seen[1]) > 0, (
            "The unconfirmed first SYN's nested CT mark was not visible in filter"
        )
        negative = launch(["python3", "-u", "-c", NEGATIVE], client)
        negative_result = line(negative)
        assert negative_result == "BLOCKED", (
            f"HTTP on the same port must not inherit application Allow: {negative_result}"
        )
        firewall("filter", "-A", "OMR_LATE", "-j", "DROP")
        packet_test(connection, "BLOCKED")
        firewall("filter", "-F", "OMR_LATE")
        stop(connection)
        # A known application Block must still win over ESTABLISHED ACCEPT.
        stop(native)
        native = start_native(folder, "block")
        firewall(
            "filter",
            "-I",
            "FORWARD",
            "4",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED",
            "-j",
            "ACCEPT",
        )
        # Port now open for initial transport establishment, Block still precedes it.
        firewall("filter", "-F", "OMR_PORT")
        blocked = launch(["python3", "-u", "-c", CLIENT], client)
        assert line(blocked) == "BLOCKED", "Application Block must precede ESTABLISHED ACCEPT"
        stop(blocked)
        stop(native)
        native = start_native(folder, "allow")
        current = launch(["python3", "-u", "-c", CLIENT], client)
        assert line(current) == "ALLOWED"
        result = {
            "schema": 1,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "native_inventory_sha256": inventory_sha256,
            "engine_license_profile": args.license_profile,
            "kernel_release": os.uname().release,
            "first_syn": True,
            "mask_preservation": True,
            "application_block": True,
            "application_allow": True,
            "failure_recovery": False,
            "classifier_sandbox": True,
            "first_syn_nested_conntrack_mark": True,
            "routing_skb_mark_preserved": True,
            "real_bittorrent_allow_over_port_deny": True,
            "http_same_port_denied": True,
            "later_ip_deny_preserved": True,
            "app_block_before_established": True,
            "namespaces_only": True,
        }
        if args.backend_quarantine:
            # Match the real fast path: final current-generation flows skip the
            # queue. Closing the consumer alone must not be mistaken for protection.
            firewall(
                "mangle",
                "-I",
                "FORWARD",
                "3",
                "-m",
                "connmark",
                "--mark",
                "0x740/0xffff40",
                "-m",
                "connmark",
                "!",
                "--mark",
                "0x80/0x80",
                "-j",
                "RETURN",
            )
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            from backend_quarantine_probe import verify_quarantine

            result["backend_quarantine"] = verify_quarantine(
                router, native, policy("allow"), lambda: connection_allowed(current)
            )
            result["compiler_restore_validation"] = compiler_proof
            result["failure_recovery"] = True
            result["worker_exit_detected"] = True
        else:
            status = json.loads((folder / "status.json").read_text())
            worker = int(status["worker_pid"])
            proc_status = Path(f"/proc/{worker}/status").read_text()
            assert re.search(r"^PPid:\s+" + str(native.pid) + r"$", proc_status, re.M)
            os.kill(worker, signal.SIGKILL)
            deadline = time.monotonic() + 3
            while native.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert native.poll() is not None, "Supervisor must notice classifier death"
            refused = launch(["python3", "-u", "-c", NEGATIVE], client)
            assert line(refused) == "BLOCKED", "Queue without its consumer must fail closed"
            result["worker_exit_detected"] = True
            result["queue_without_consumer_drops"] = True
        print(json.dumps(result, sort_keys=True))
finally:
    for process in reversed(processes):
        stop(process)
    for name in reversed(created):
        subprocess.run(
            ["ip", "netns", "delete", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
