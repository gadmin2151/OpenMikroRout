"""Compile service-scoped Fail2ban rules into owned IPv4 filter chains."""

import itertools
from collections.abc import Iterator

from app.fail2ban_models import F2BConfiguration, F2BProfile
from app.system_lists import kernel_set_name

F2B_CHAINS = {"input": "OMR_F2B", "forward": "OMR_F2B_FORWARD"}
F2B_ANCHOR = "openmikrorout:f2b-anchor"
ATTEMPT_NFLOG_GROUP = 5088


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
                result.append(
                    " ".join(
                        [
                            "-A",
                            F2B_CHAINS[chain],
                            *match,
                            "-m",
                            "conntrack",
                            "--ctstate",
                            "NEW",
                            "-m",
                            "tcp",
                            "--syn",
                            "-m",
                            "comment",
                            "--comment",
                            f"openmikrorout:f2b-attempt:{profile.id}",
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
                    )
                )
    for chain in F2B_CHAINS.values():
        result.append(f"-A {chain} -m comment --comment openmikrorout:f2b-return -j RETURN")
    return result
