"""Ingress-only WireGuard access boundaries, independent of host ACCEPT policies."""

import shlex

from app.models import Configuration

WG_CHAINS = {"INPUT": "OMR_WG_INPUT", "FORWARD": "OMR_WG_FORWARD"}
WG_ANCHOR = "openmikrorout:wireguard-anchor"


def wg_anchor(hook: str) -> list[str]:
    return ["-A", hook, "-m", "comment", "--comment", WG_ANCHOR, "-j", WG_CHAINS[hook]]


def access_rules(*configs: Configuration) -> list[str]:
    """The first policy for a name wins; retain removed interfaces until link teardown."""
    seen: set[str] = set()
    result: list[str] = []
    for config in configs:
        for interface in config.network.wireguard_interfaces:
            policy = interface.server_access
            if policy is None or interface.name in seen:
                continue
            seen.add(interface.name)
            for hook, chain in WG_CHAINS.items():
                base = ["-A", chain, "-i", interface.name]
                source = ["-s", policy.source_network]
                marker = ["-m", "comment", "--comment", f"openmikrorout:wg-access:{interface.id}"]
                matches: list[list[str]] = []
                if hook == "INPUT" and policy.router_access:
                    matches.append(source)
                if hook == "FORWARD":
                    matches += [[*source, "-d", prefix] for prefix in policy.access_networks]
                    if policy.wan_interface:
                        matches.append([*source, "-o", policy.wan_interface])
                result += [" ".join([*base, *match, *marker, "-j", "RETURN"]) for match in matches]
                result.append(" ".join([*base, *marker, "-j", "DROP"]))
    return result


def snapshot_access_rules(snapshot: str) -> list[str]:
    return [
        line
        for line in snapshot.splitlines()
        if any(line.startswith(f"-A {chain} ") for chain in WG_CHAINS.values())
    ]


def rollback_access_rules(current: str, previous: str) -> list[str]:
    """Restore old boundaries while keeping new-interface guards until teardown completes."""
    old = snapshot_access_rules(previous)
    names = {shlex.split(line)[shlex.split(line).index("-i") + 1] for line in old}
    return old + [
        line
        for line in snapshot_access_rules(current)
        if shlex.split(line)[shlex.split(line).index("-i") + 1] not in names
    ]
