"""Inspect competing nft datapaths with fixed commands and bounded JSON input."""

import json
import os
import selectors
import shutil
import subprocess
import time
from typing import Any

from app.application_policy import QUEUE_CHAIN, QUEUE_NUMBER
from app.compiler import FirewallError

MAX_NFT_BYTES = 1024 * 1024
NFT_SECONDS = 3.0


def read_nft_ruleset() -> bytes:
    executable = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        raise FirewallError("nftables inspection tooling is required before enabling Applications")
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [executable, "-j", "list", "ruleset"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + NFT_SECONDS
        with process.stdout, selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FirewallError("nftables compatibility inspection exceeded its deadline")
                if not selector.select(min(remaining, 0.25)):
                    continue
                part = os.read(process.stdout.fileno(), min(65536, MAX_NFT_BYTES + 1 - len(output)))
                if not part:
                    break
                output.extend(part)
                if len(output) > MAX_NFT_BYTES:
                    raise FirewallError("nftables ruleset exceeds the application inspection limit")
        if process.wait(timeout=max(0.01, deadline - time.monotonic())):
            raise FirewallError(
                "Cannot inspect the nftables datapath before application enforcement"
            )
        return bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewallError(
            "Cannot inspect the nftables datapath before application enforcement"
        ) from exc
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1)


def queue_number_conflict(value: object) -> bool:
    if type(value) is int:
        return value == QUEUE_NUMBER
    if isinstance(value, dict) and set(value) == {"range"}:
        bounds = value["range"]
        if (
            isinstance(bounds, list)
            and len(bounds) == 2
            and all(type(bound) is int for bound in bounds)
        ):
            return bool(bounds[0] <= QUEUE_NUMBER <= bounds[1])
    # Dynamic queue expressions cannot establish exclusive ownership safely.
    return True


def verify_iptables_queue(tokens: list[str], *, allow_owned_mangle: bool = False) -> None:
    if "-j" not in tokens or tokens[tokens.index("-j") + 1] != "NFQUEUE":
        return
    if (
        allow_owned_mangle
        and tokens[1] == QUEUE_CHAIN
        and "--comment" in tokens
        and tokens[tokens.index("--comment") + 1] == "openmikrorout:application-inspect"
        and "--queue-num" in tokens
        and tokens[tokens.index("--queue-num") + 1] == str(QUEUE_NUMBER)
        and not any(
            flag in tokens for flag in ("--queue-balance", "--queue-bypass", "--queue-cpu-fanout")
        )
    ):
        return  # queue_patch separately checks the exact owned mangle hook.
    try:
        if "--queue-balance" in tokens:
            low, high = tokens[tokens.index("--queue-balance") + 1].split(":")
            value: object = {"range": [int(low), int(high)]}
        else:
            value = int(tokens[tokens.index("--queue-num") + 1]) if "--queue-num" in tokens else 0
    except (ValueError, IndexError) as exc:
        raise FirewallError("Cannot establish exclusive application NFQUEUE ownership") from exc
    if queue_number_conflict(value):
        raise FirewallError("A foreign NFQUEUE conflicts with the application queue number")


def competing_nft_datapath(raw: bytes) -> None:
    """Reject writers/offload; ordinary metadata matches and skb marks are readable."""
    if len(raw) > MAX_NFT_BYTES:
        raise FirewallError("nftables ruleset exceeds the application inspection limit")
    try:
        root = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise FirewallError("Invalid nftables inspection response") from exc
    if not isinstance(root, dict) or not isinstance(root.get("nftables"), list):
        raise FirewallError("Invalid nftables inspection response")
    stack: list[tuple[Any, int, bool]] = [(root, 0, False)]
    count = 0
    while stack:
        node, depth, owned_queue = stack.pop()
        count += 1
        if count > 50000 or depth > 32:
            raise FirewallError("nftables ruleset exceeds its structural inspection limit")
        if isinstance(node, dict):
            if isinstance(node.get("rule"), dict):
                rule = node["rule"]
                owned_queue = (
                    rule.get("chain") == QUEUE_CHAIN
                    and rule.get("table") == "mangle"
                    and rule.get("family") == "ip"
                    and rule.get("comment") == "openmikrorout:application-inspect"
                )
            queue = node.get("queue")
            if (
                isinstance(queue, dict)
                and queue_number_conflict(queue.get("num", 0))
                and not (owned_queue and queue.get("num") == QUEUE_NUMBER and set(queue) <= {"num"})
            ):
                raise FirewallError(
                    "A native nft queue conflicts with application NFQUEUE ownership"
                )
            if any(key in node for key in ("flowtable", "notrack", "ct helper", "ct expectation")):
                raise FirewallError(
                    "Native nft offload/notrack/CT helpers conflict with Applications"
                )
            assignment = node.get("mangle")
            if isinstance(assignment, dict):
                target = assignment.get("key")
                if (
                    isinstance(target, dict)
                    and isinstance(target.get("ct"), dict)
                    and target["ct"].get("key") in ("mark", "helper")
                ):
                    raise FirewallError("A native nft conntrack writer conflicts with Applications")
            opaque = node.get("xt")
            if (
                isinstance(opaque, dict)
                and opaque.get("type") == "target"
                and str(opaque.get("name", "")).upper() in ("CONNMARK", "NOTRACK", "CT")
            ):
                raise FirewallError("An opaque nft conntrack writer conflicts with Applications")
            stack.extend((value, depth + 1, owned_queue) for value in node.values())
        elif isinstance(node, list):
            stack.extend((value, depth + 1, owned_queue) for value in node)
