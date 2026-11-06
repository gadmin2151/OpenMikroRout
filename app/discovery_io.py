"""Small bounded adapters shared by passive discovery and active scan validation."""

import ipaddress
import json
import os
import selectors
import shutil
import subprocess
import time
from typing import Any

from app.compiler import FirewallError
from app.link_models import interface_name
from app.network_models import NetworkConfiguration


class DiscoveryError(FirewallError):
    pass


def bounded_command(
    arguments: list[str], limit: int = 4 * 1024 * 1024, timeout: float = 5
) -> bytes:
    """Bound output while reading, rather than capturing unbounded subprocess output."""
    try:
        process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": os.defpath, "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise DiscoveryError("The discovery utility could not be started") from exc
    assert process.stdout is not None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise DiscoveryError("The discovery utility timed out")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    output.extend(chunk)
                    if len(output) > limit:
                        raise DiscoveryError("The discovery utility exceeded its output limit")
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if process.returncode != 0:
            raise DiscoveryError("The discovery utility failed; check installation and permissions")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        process.stdout.close()


def connected_networks(
    demo: bool = False,
    configuration: NetworkConfiguration | None = None,
) -> dict[str, list[str]]:
    if demo:
        if configuration is None:
            from app.demo import demo_config

            configuration = demo_config().network
        # Match the same unmanaged fixtures shown by /api/interfaces. Managed
        # addresses come from the applied demo configuration, never from a draft.
        demo_networks = {"eth0": ["203.0.113.0/24"], "wg0": ["10.8.0.0/24"]}
        managed: dict[str, list[str]] = {}
        for address in configuration.addresses:
            if address.enabled:
                demo_subnet = str(ipaddress.IPv4Interface(address.address).network)
                managed.setdefault(address.interface, []).append(demo_subnet)
        demo_networks.update({name: sorted(set(values)) for name, values in managed.items()})
        return demo_networks
    binary = shutil.which("ip")
    if not binary:
        raise DiscoveryError("Install iproute2 to enumerate connected networks")
    try:
        rows = json.loads(bounded_command([binary, "-j", "-4", "address", "show"]))
    except (ValueError, RecursionError) as exc:
        raise DiscoveryError("Invalid network interface response") from exc
    result: dict[str, list[str]] = {}
    if not isinstance(rows, list):
        raise DiscoveryError("Invalid network interface response")
    for row in rows[:1024]:
        if not isinstance(row, dict):
            continue
        name = row.get("ifname", "")
        try:
            interface_name(name)
        except (ValueError, TypeError):
            continue
        networks = []
        addresses = row.get("addr_info", [])
        if not isinstance(addresses, list):
            continue
        for item in addresses[:64]:
            if not isinstance(item, dict) or item.get("family") != "inet":
                continue
            try:
                network = ipaddress.IPv4Network(
                    f"{item['local']}/{item['prefixlen']}", strict=False
                )
            except (KeyError, ValueError):
                continue
            if network.prefixlen == 0 or network.is_loopback or network.is_multicast:
                continue
            networks.append(str(network))
        if networks:
            result[name] = sorted(set(networks))
    return result


def json_object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
