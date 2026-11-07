"""Compile validated objects into a patch that touches only our three chains."""

import itertools
import re
import shlex
from collections.abc import Iterator

from app.match_expansion import address_list_matches
from app.models import Configuration, NatRule, RuleMatch
from app.system_lists import is_system_list, kernel_set_name, resolved_system_lists

CHAINS = {"dstnat": "NATP_PRE", "srcnat": "NATP_POST", "output": "NATP_OUT"}
HOOKS = {"PREROUTING": "NATP_PRE", "POSTROUTING": "NATP_POST", "OUTPUT": "NATP_OUT"}
ANCHOR = "nat-panel:anchor"


class FirewallError(Exception):
    """An operational firewall failure safe to describe to an administrator."""


def anchor_tokens(hook: str, chain: str) -> list[str]:
    return ["-A", hook, "-m", "comment", "--comment", ANCHOR, "-j", chain]


def inspect_snapshot(snapshot: str) -> tuple[list[str], set[str]]:
    if not snapshot.startswith("*nat\n") or "\nCOMMIT" not in snapshot:
        raise FirewallError("iptables-save did not return a valid NAT table")
    rules = []
    anchors: set[str] = set()
    for line in snapshot.splitlines():
        if not line.startswith("-A "):
            continue
        tokens = shlex.split(line)
        chain = tokens[1]
        if chain in CHAINS.values():
            if "--comment" not in tokens or not tokens[tokens.index("--comment") + 1].startswith(
                "nat-panel:"
            ):
                raise FirewallError(f"Reserved chain {chain} contains an unmanaged rule")
            rules.append(line)
        for flag in ("-j", "-g"):
            if flag in tokens and tokens[tokens.index(flag) + 1] in CHAINS.values():
                if chain not in HOOKS or tokens != anchor_tokens(chain, HOOKS[chain]):
                    raise FirewallError("An unmanaged rule references a reserved NATP chain")
                if chain in anchors:
                    raise FirewallError("Duplicate NAT Panel hook detected")
                anchors.add(chain)
    return rules, anchors


def match_tokens(
    rule: RuleMatch,
    source: str,
    destination: str,
    incoming: str,
    outgoing: str,
    marker: str = "nat-panel",
) -> list[str]:
    tokens: list[str] = []
    if rule.protocol != "any":
        tokens += [*(["!"] if "protocol" in rule.negate else []), "-p", rule.protocol]
    for key, flag, value in (
        ("src_address", "-s", source),
        ("dst_address", "-d", destination),
        ("in_interface", "-i", incoming),
        ("out_interface", "-o", outgoing),
    ):
        if value:
            tokens += [*(["!"] if key in rule.negate else []), flag, value]
    for key, flag, value in (
        ("src_ports", "--sports", rule.src_ports),
        ("dst_ports", "--dports", rule.dst_ports),
    ):
        if value:
            tokens += [
                "-m",
                "multiport",
                *(["!"] if key in rule.negate else []),
                flag,
                value.replace("-", ":"),
            ]
    set_matches = [
        (rule.src_list, "src", "src_list" in rule.negate),
        (rule.dst_list, "dst", "dst_list" in rule.negate),
    ]
    if rule.src_country:
        set_matches.append((f"geo_{rule.src_country}", "src", "src_country" in rule.negate))
    if rule.dst_country:
        set_matches.append((f"geo_{rule.dst_country}", "dst", "dst_country" in rule.negate))
    if rule.f2b_profile:
        set_matches.append((f"f2b_{rule.f2b_profile}", "src", rule.f2b_match == "not_banned"))
    for ref, direction, invert in dict.fromkeys(set_matches):
        if is_system_list(ref):
            tokens += [
                "-m",
                "set",
                *(["!"] if invert else []),
                "--match-set",
                kernel_set_name(ref),
                direction,
            ]
    if rule.connection_states:
        tokens += [
            "-m",
            "conntrack",
            *(["!"] if "connection_states" in rule.negate else []),
            "--ctstate",
            ",".join(rule.connection_states),
        ]
    tokens += ["-m", "comment", "--comment", f"{marker}:{rule.id}"]
    return tokens


def expanded_matches(config: Configuration, rule: RuleMatch) -> Iterator[tuple[str, str, str, str]]:
    lists = {item.name: item.addresses for item in config.address_lists}
    lists.update({name: [""] for name in resolved_system_lists(config)})
    interfaces = {item.name: item.members for item in config.network.interface_lists}
    sources = lists[rule.src_list] if rule.src_list else [rule.src_address]
    destinations = lists[rule.dst_list] if rule.dst_list else [rule.dst_address]
    if rule.src_list and not is_system_list(rule.src_list):
        sources = address_list_matches(sources, negate="src_list" in rule.negate)
    if rule.dst_list and not is_system_list(rule.dst_list):
        destinations = address_list_matches(destinations, negate="dst_list" in rule.negate)
    incoming = interfaces[rule.in_interface_list] if rule.in_interface_list else [rule.in_interface]
    outgoing = (
        interfaces[rule.out_interface_list] if rule.out_interface_list else [rule.out_interface]
    )
    yield from itertools.product(sources, destinations, incoming, outgoing)


def rule_tokens(
    rule: NatRule,
    source: str,
    destination: str,
    incoming: str | None = None,
    outgoing: str | None = None,
) -> list[str]:
    tokens = ["-A", CHAINS[rule.chain]] + match_tokens(
        rule,
        source,
        destination,
        rule.in_interface if incoming is None else incoming,
        rule.out_interface if outgoing is None else outgoing,
    )
    targets = {
        "dst-nat": "DNAT",
        "src-nat": "SNAT",
        "masquerade": "MASQUERADE",
        "redirect": "REDIRECT",
        "accept": "ACCEPT",
    }
    tokens += ["-j", targets[rule.action]]
    if rule.action in ("src-nat", "dst-nat"):
        target = rule.to_address + (f":{rule.to_ports}" if rule.to_ports else "")
        tokens += ["--to-source" if rule.action == "src-nat" else "--to-destination", target]
    elif rule.to_ports:
        tokens += ["--to-ports", rule.to_ports]
    return tokens


def compiled_rules(config: Configuration) -> list[str]:
    lines = []
    for rule in config.rules:
        if not rule.enabled:
            continue
        for src, dst, incoming, outgoing in expanded_matches(config, rule):
            # All tokens are strict enums, UUIDs, IPs, ports or validated interface names.
            lines.append(" ".join(rule_tokens(rule, src, dst, incoming, outgoing)))
    return lines


def patch(snapshot: str, config: Configuration) -> str:
    _, anchors = inspect_snapshot(snapshot)
    lines = ["*nat", *(f":{chain} - [0:0]" for chain in CHAINS.values())]
    lines += compiled_rules(config)
    lines += [
        " ".join(anchor_tokens(hook, chain)) for hook, chain in HOOKS.items() if hook not in anchors
    ]
    return "\n".join([*lines, "COMMIT", ""])


def rollback_patch(current: str, previous: str) -> str:
    _, current_anchors = inspect_snapshot(current)
    previous_rules, previous_anchors = inspect_snapshot(previous)
    lines = ["*nat", *(f":{chain} - [0:0]" for chain in CHAINS.values()), *previous_rules]
    for hook, chain in HOOKS.items():
        tokens = anchor_tokens(hook, chain)
        if hook in current_anchors and hook not in previous_anchors:
            tokens[0] = "-D"
            lines.append(" ".join(tokens))
        elif hook in previous_anchors and hook not in current_anchors:
            lines.append(" ".join(tokens))
    return "\n".join([*lines, "COMMIT", ""])


def counters(snapshot: str) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for line in snapshot.splitlines():
        match = re.match(r"\[(\d+):(\d+)\] (-A NATP_\w+ .*)", line)
        if not match:
            continue
        tokens = shlex.split(match[3])
        if "--comment" in tokens:
            comment = tokens[tokens.index("--comment") + 1]
            if comment.startswith("nat-panel:"):
                key = comment.removeprefix("nat-panel:")
                values = result.setdefault(key, {"packets": 0, "bytes": 0})
                values["packets"] += int(match[1])
                values["bytes"] += int(match[2])
    return result
