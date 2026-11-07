"""Compile service-scoped Fail2ban rules into owned IPv4 filter chains."""

import base64
import itertools
from collections.abc import Iterator
from typing import Literal

from app.fail2ban_models import F2BConfiguration, F2BProfile
from app.system_lists import kernel_set_name

F2B_CHAINS = {"input": "OMR_F2B", "forward": "OMR_F2B_FORWARD", "output": "OMR_F2B_OUTPUT"}
F2B_ANCHOR = "openmikrorout:f2b-anchor"
ATTEMPT_NFLOG_GROUP = 5088
OBSERVATIONS_PER_PROFILE_SECOND = 128
OBSERVATION_BURST = 256
OBSERVATION_TUPLE_CAPACITY = 1024


def observation_limit_name(
    profile: F2BProfile, phase: Literal["profile", "start", "reply", "attempt"] = "profile"
) -> str:
    # The generated ID has exactly 72 bits. Encode all of them without truncating
    # or sharing another profile's bucket, within old hashlimit's 15-char limit.
    prefix = {"profile": "omr", "start": "oms", "reply": "omq", "attempt": "oma"}[phase]
    return prefix + base64.urlsafe_b64encode(bytes.fromhex(profile.id[2:])).decode("ascii")


def observation_rules(
    profile: F2BProfile, chain: str, match: list[str], *, reply: bool = False
) -> list[str]:
    result = []
    phases: list[tuple[Literal["start", "reply", "attempt"], str, list[str]]] = [
        ("start", "NEW", ["--syn"]),
        ("attempt", "ESTABLISHED", ["--tcp-flags", "SYN,RST,ACK", "ACK"]),
    ]
    if reply:
        phases = [("reply", "ESTABLISHED", ["--tcp-flags", "SYN,RST,ACK", "SYN,ACK"])]
    for phase, state, tcp in phases:
        tokens = [
            "-A",
            chain,
            *match,
            "-m",
            "conntrack",
            "--ctstate",
            state,
            "--ctdir",
            "REPLY" if reply else "ORIGINAL",
        ]
        if phase == "attempt":
            tokens += ["--ctstatus", "ASSURED"]
        tokens += [
            "-m",
            "tcp",
            *tcp,
            # Throttle repeated data/retransmissions for one tuple BEFORE the
            # profile budget. Separate phases preserve the first SYN/SYN-ACK/ACK.
            "-m",
            "hashlimit",
            "--hashlimit-name",
            observation_limit_name(profile, phase),
            "--hashlimit-mode",
            "srcip,srcport,dstip,dstport",
            "--hashlimit-upto",
            "1/second",
            "--hashlimit-burst",
            "1",
            "--hashlimit-htable-size",
            "128",
            "--hashlimit-htable-max",
            str(OBSERVATION_TUPLE_CAPACITY),
            "--hashlimit-htable-expire",
            "10000",
            # No --hashlimit-mode: one bounded bucket per profile, shared across
            # all three phases, expanded endpoints and hooks. No packet
            # or connection marks are read or changed.
            "-m",
            "hashlimit",
            "--hashlimit-name",
            observation_limit_name(profile),
            "--hashlimit-upto",
            f"{OBSERVATIONS_PER_PROFILE_SECOND}/second",
            "--hashlimit-burst",
            str(OBSERVATION_BURST),
            "--hashlimit-htable-size",
            "1",
            "--hashlimit-htable-max",
            "1",
            "-m",
            "comment",
            "--comment",
            f"openmikrorout:f2b-{phase}:{profile.id}",
            "-j",
            "NFLOG",
            "--nflog-group",
            str(ATTEMPT_NFLOG_GROUP),
            "--nflog-prefix",
            profile.id,
            "--nflog-threshold",
            "1",
            "--nflog-size",
            "0",
        ]
        result.append(" ".join(tokens))
    return result


def f2b_anchor(hook: str) -> list[str]:
    return ["-A", hook, "-m", "comment", "--comment", F2B_ANCHOR, "-j", F2B_CHAINS[hook.lower()]]


def service_match_tokens(profile: F2BProfile) -> Iterator[list[str]]:
    """The same bounded endpoint scope is shared by bans and event collection."""
    scope = profile.scope
    destinations = scope.destinations if scope else [profile.destination]
    incoming = scope.in_interfaces if scope else [profile.in_interface]
    outgoing = scope.out_interfaces if scope else []
    for destination, interface_in, interface_out, country in itertools.product(
        destinations or [""], incoming or [""], outgoing or [""], profile.include_countries or [""]
    ):
        tokens = ["-p", "tcp"]
        for flag, value in (("-i", interface_in), ("-o", interface_out), ("-d", destination)):
            if value:
                tokens += [flag, value]
        tokens += ["-m", "multiport", "--dports", ",".join(map(str, profile.ports))]
        if scope:
            for name in scope.destination_sets:
                tokens += ["-m", "set", "--match-set", kernel_set_name(name), "dst"]
        if country:
            tokens += ["-m", "set", "--match-set", kernel_set_name(f"geo_{country}"), "src"]
        for excluded in profile.exclude_countries:
            tokens += ["-m", "set", "!", "--match-set", kernel_set_name(f"geo_{excluded}"), "src"]
        yield tokens


def profile_chains(profile: F2BProfile) -> list[str]:
    return list(profile.scope.chains) if profile.scope and profile.scope.chains else [profile.chain]


def profile_hooks(profile: F2BProfile) -> list[str]:
    chains = profile_chains(profile)
    if profile.service == "connections" and "input" in chains:
        chains.append("output")
    return chains


def reply_match_tokens(match: list[str]) -> list[str]:
    """The reply must leave the same service endpoint and reverse its selectors."""
    reverse = {"-i": "-o", "-o": "-i", "-d": "-s", "--dports": "--sports"}
    result = match.copy()
    for index, token in enumerate(match):
        if token in reverse:
            result[index] = reverse[token]
        elif index >= 2 and match[index - 2] == "--match-set":
            result[index] = {"src": "dst", "dst": "src"}[token]
    return result


def f2b_rules(config: F2BConfiguration) -> list[str]:
    result: list[str] = []
    if not config.enabled:
        return result
    for profile in config.profiles:
        if not profile.enabled:
            continue
        for chain, match in itertools.product(
            profile_chains(profile), service_match_tokens(profile)
        ):
            tokens = ["-A", F2B_CHAINS[chain], *match]
            tokens += ["-m", "set", "--match-set", kernel_set_name(f"f2b_{profile.id}"), "src"]
            tokens += [
                "-m",
                "comment",
                "--comment",
                f"openmikrorout:f2b:{profile.id}",
                "-j",
                "DROP",
            ]
            result.append(" ".join(tokens))
            if profile.service == "connections":
                result += observation_rules(profile, F2B_CHAINS[chain], match)
                reply_chain = "output" if chain == "input" else "forward"
                result += observation_rules(
                    profile, F2B_CHAINS[reply_chain], reply_match_tokens(match), reply=True
                )
    for chain in F2B_CHAINS.values():
        result.append(f"-A {chain} -m comment --comment openmikrorout:f2b-return -j RETURN")
    return result
