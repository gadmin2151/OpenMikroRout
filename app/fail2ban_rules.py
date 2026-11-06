"""Compile service-scoped Fail2ban rules into owned IPv4 filter chains."""

from app.fail2ban_models import F2BConfiguration
from app.system_lists import kernel_set_name

F2B_CHAINS = {"input": "OMR_F2B", "forward": "OMR_F2B_FORWARD"}
F2B_ANCHOR = "openmikrorout:f2b-anchor"


def f2b_anchor(hook: str) -> list[str]:
    return ["-A", hook, "-m", "comment", "--comment", F2B_ANCHOR, "-j", F2B_CHAINS[hook.lower()]]


def f2b_rules(config: F2BConfiguration) -> list[str]:
    result: list[str] = []
    if not config.enabled:
        return result
    for profile in config.profiles:
        if not profile.enabled:
            continue
        for country in profile.include_countries or [""]:
            tokens = ["-A", F2B_CHAINS[profile.chain], "-p", "tcp"]
            if profile.in_interface:
                tokens += ["-i", profile.in_interface]
            if profile.destination:
                tokens += ["-d", profile.destination]
            tokens += ["-m", "multiport", "--dports", ",".join(map(str, profile.ports))]
            tokens += ["-m", "set", "--match-set", kernel_set_name(f"f2b_{profile.id}"), "src"]
            if country:
                tokens += ["-m", "set", "--match-set", kernel_set_name(f"geo_{country}"), "src"]
            for excluded in profile.exclude_countries:
                tokens += [
                    "-m",
                    "set",
                    "!",
                    "--match-set",
                    kernel_set_name(f"geo_{excluded}"),
                    "src",
                ]
            tokens += [
                "-m",
                "comment",
                "--comment",
                f"openmikrorout:f2b:{profile.id}",
                "-j",
                "DROP",
            ]
            result.append(" ".join(tokens))
    for chain in F2B_CHAINS.values():
        result.append(f"-A {chain} -m comment --comment openmikrorout:f2b-return -j RETURN")
    return result
