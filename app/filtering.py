"""Owned iptables filter chains: compile, inspect, apply and restore without table flushing."""

import re
import shlex
import shutil
from typing import Protocol

from app.application_policy import (
    APP_CHAIN,
    app_anchor,
    denial_chain,
    denial_rules,
    guard_rules,
)
from app.application_policy import (
    active as applications_active,
)
from app.application_policy import (
    owned_chain as application_owned_chain,
)
from app.compiler import FirewallError, expanded_matches, match_tokens
from app.fail2ban_rules import F2B_CHAINS, f2b_anchor, f2b_rules, profile_hooks
from app.models import Configuration
from app.rule_protection import effective_fail2ban
from app.wireguard_filter import (
    WG_CHAINS,
    access_rules,
    rollback_access_rules,
    snapshot_access_rules,
    wg_anchor,
)

CHAINS = {"input": "OMR_INPUT", "forward": "OMR_FORWARD", "output": "OMR_OUTPUT"}
HOOKS = {key.upper(): value for key, value in CHAINS.items()}
ANCHOR = "openmikrorout:filter-anchor"
MARKER = "openmikrorout:"
EMPTY_FILTER = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"


class FilterDriver(Protocol):
    def snapshot(self, with_counters: bool = False) -> str: ...
    def restore(self, payload: str, test: bool = False) -> None: ...


def anchor(hook: str, chain: str) -> list[str]:
    return ["-A", hook, "-m", "comment", "--comment", ANCHOR, "-j", chain]


def inspect(snapshot: str) -> tuple[list[str], set[str]]:
    if not snapshot.startswith("*filter\n") or "\nCOMMIT" not in snapshot:
        raise FirewallError("iptables-save did not return a valid filter table")
    rules: list[str] = []
    hooks: set[str] = set()
    for line in snapshot.splitlines():
        if not line.startswith("-A "):
            continue
        tokens = shlex.split(line)
        chain = tokens[1]
        if chain in (
            *CHAINS.values(),
            *F2B_CHAINS.values(),
            *WG_CHAINS.values(),
        ) or application_owned_chain(chain):
            if "--comment" not in tokens or not tokens[tokens.index("--comment") + 1].startswith(
                MARKER
            ):
                raise FirewallError(f"Reserved chain {chain} contains an unmanaged rule")
            rules.append(line)
        for flag in ("-j", "-g"):
            if flag in tokens and application_owned_chain(tokens[tokens.index(flag) + 1]):
                target = tokens[tokens.index(flag) + 1]
                if target == APP_CHAIN:
                    if tokens != app_anchor():
                        raise FirewallError("An unmanaged rule references the application guard")
                    if "applications" in hooks:
                        raise FirewallError("Duplicate application guard anchor")
                    hooks.add("applications")
                elif chain not in CHAINS.values():
                    raise FirewallError(
                        "An unmanaged rule references an application port exception"
                    )
            if flag in tokens and tokens[tokens.index(flag) + 1] in WG_CHAINS.values():
                if chain not in WG_CHAINS or tokens != wg_anchor(chain):
                    raise FirewallError("An unmanaged rule references a reserved WireGuard chain")
                key = f"wg:{chain}"
                if key in hooks:
                    raise FirewallError("Duplicate OpenMikroRout WireGuard hook detected")
                hooks.add(key)
            if flag in tokens and tokens[tokens.index(flag) + 1] in F2B_CHAINS.values():
                if chain.lower() not in F2B_CHAINS or tokens != f2b_anchor(chain):
                    raise FirewallError("An unmanaged rule references a reserved Fail2ban chain")
                key = f"f2b:{chain}"
                if key in hooks:
                    raise FirewallError("Duplicate OpenMikroRout Fail2ban hook detected")
                hooks.add(key)
            if flag in tokens and tokens[tokens.index(flag) + 1] in CHAINS.values():
                if chain not in HOOKS or tokens != anchor(chain, HOOKS[chain]):
                    raise FirewallError(
                        "An unmanaged rule references an OpenMikroRout filter chain"
                    )
                if chain in hooks:
                    raise FirewallError("Duplicate OpenMikroRout filter hook detected")
                hooks.add(chain)
    return rules, hooks


def compiled_filters(config: Configuration, application_epoch: int | None = None) -> list[str]:
    result: list[str] = []
    for rule in config.filter_rules:
        if not rule.enabled:
            continue
        for source, destination, incoming, outgoing in expanded_matches(config, rule):
            tokens = [
                "-A",
                CHAINS[rule.chain],
                *match_tokens(rule, source, destination, incoming, outgoing, "openmikrorout"),
                "-j",
                denial_chain(rule)
                if applications_active(config)
                and application_epoch is not None
                and rule.application_override_eligible
                else rule.action.upper(),
            ]
            result.append(" ".join(tokens))
    return result


def _f2b_declarations(snapshot: str, enabled: bool) -> list[str]:
    return [
        f":{chain} - [0:0]" for chain in F2B_CHAINS.values() if enabled or f":{chain} " in snapshot
    ]


def _wireguard_patch(snapshot: str, rules: list[str], hooks: set[str]) -> list[str]:
    lines = [
        f":{chain} - [0:0]" for chain in WG_CHAINS.values() if rules or f":{chain} " in snapshot
    ]
    lines += rules
    for hook in WG_CHAINS:
        tokens = wg_anchor(hook)
        if f"wg:{hook}" in hooks:
            lines.append(" ".join(["-D", *tokens[1:]]))
        if rules:
            # Only this ingress-scoped guard moves ahead of foreign/PVE ACCEPT rules.
            lines.append(" ".join(["-I", hook, "1", *tokens[2:]]))
    return lines


def wireguard_guard_patch(snapshot: str, *configs: Configuration) -> str:
    _, hooks = inspect(snapshot)
    return "\n".join(
        ["*filter", *_wireguard_patch(snapshot, access_rules(*configs), hooks), "COMMIT", ""]
    )


def wireguard_guard_rollback(current: str, previous: str) -> str:
    _, hooks = inspect(current)
    inspect(previous)
    return "\n".join(
        [
            "*filter",
            *_wireguard_patch(current, rollback_access_rules(current, previous), hooks),
            "COMMIT",
            "",
        ]
    )


def _application_declarations(
    snapshot: str, config: Configuration | None = None, epoch: int | None = None
) -> list[str]:
    names = {
        line.split()[0][1:]
        for line in snapshot.splitlines()
        if line.startswith(":") and application_owned_chain(line.split()[0][1:])
    }
    if config is not None and applications_active(config):
        names.add(APP_CHAIN)
        if epoch is not None:
            names.update(
                denial_chain(rule)
                for rule in config.filter_rules
                if rule.enabled and rule.application_override_eligible
            )
    return [f":{name} - [0:0]" for name in sorted(names)]


def filter_patch(
    snapshot: str, config: Configuration, *, application_epoch: int | None = None
) -> str:
    _, hooks = inspect(snapshot)
    protection = effective_fail2ban(config)
    lines = ["*filter", *(f":{chain} - [0:0]" for chain in CHAINS.values())]
    lines += _f2b_declarations(snapshot, protection.enabled)
    lines += _application_declarations(snapshot, config, application_epoch)
    lines += compiled_filters(config, application_epoch)
    lines += guard_rules(config, application_epoch)
    lines += denial_rules(config, application_epoch)
    application_jump = app_anchor()
    if "applications" in hooks:
        lines.append(" ".join(["-D", *application_jump[1:]]))
    if applications_active(config):
        lines.append(" ".join(["-I", "FORWARD", "1", *application_jump[2:]]))
    lines += _wireguard_patch(snapshot, access_rules(config), hooks)
    lines += f2b_rules(protection)
    lines += [" ".join(anchor(hook, chain)) for hook, chain in HOOKS.items() if hook not in hooks]
    for hook in (chain.upper() for chain in F2B_CHAINS):
        tokens = f2b_anchor(hook)
        if f"f2b:{hook}" in hooks:
            lines.append(" ".join(["-D", *tokens[1:]]))
        if protection.enabled and any(
            p.enabled and hook.lower() in profile_hooks(p) for p in protection.profiles
        ):
            # Move ONLY our jump to the front so even earlier foreign ACCEPT rules cannot bypass it.
            lines.append(" ".join(["-I", hook, "1", *tokens[2:]]))
    return "\n".join([*lines, "COMMIT", ""])


def filter_rollback(
    current: str,
    previous: str,
    *,
    keep_wireguard_guards: bool = False,
    keep_application_guards: bool = False,
) -> str:
    _, current_hooks = inspect(current)
    rules, old_hooks = inspect(previous)
    lines = ["*filter", *(f":{chain} - [0:0]" for chain in CHAINS.values())]
    lines += _f2b_declarations(current + previous, False)
    lines += _application_declarations(current + previous)
    lines += [
        line
        for line in rules
        if line not in snapshot_access_rules(previous)
        and not (keep_application_guards and line.startswith(f"-A {APP_CHAIN} "))
    ]
    if keep_application_guards:
        current_rules, _ = inspect(current)
        lines += [line for line in current_rules if line.startswith(f"-A {APP_CHAIN} ")]
    guard_rules = (
        rollback_access_rules(current, previous)
        if keep_wireguard_guards
        else snapshot_access_rules(previous)
    )
    lines += _wireguard_patch(current + previous, guard_rules, current_hooks)
    for hook, chain in HOOKS.items():
        tokens = anchor(hook, chain)
        if hook in current_hooks and hook not in old_hooks:
            tokens[0] = "-D"
            lines.append(" ".join(tokens))
        elif hook in old_hooks and hook not in current_hooks:
            lines.append(" ".join(tokens))
    for hook in (chain.upper() for chain in F2B_CHAINS):
        tokens = f2b_anchor(hook)
        if f"f2b:{hook}" in current_hooks:
            lines.append(" ".join(["-D", *tokens[1:]]))
        if f"f2b:{hook}" in old_hooks:
            lines.append(" ".join(["-I", hook, "1", *tokens[2:]]))
    application_jump = app_anchor()
    if "applications" in current_hooks:
        lines.append(" ".join(["-D", *application_jump[1:]]))
    if "applications" in old_hooks or (keep_application_guards and "applications" in current_hooks):
        lines.append(" ".join(["-I", "FORWARD", "1", *application_jump[2:]]))
    return "\n".join([*lines, "COMMIT", ""])


def filter_counters(snapshot: str) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for line in snapshot.splitlines():
        found = re.match(r"\[(\d+):(\d+)\] (-A OMR_\w+ .*)", line)
        if not found:
            continue
        tokens = shlex.split(found[3])
        if "--comment" not in tokens:
            continue
        marker = tokens[tokens.index("--comment") + 1]
        if not marker.startswith(MARKER):
            continue
        values = result.setdefault(marker.removeprefix(MARKER), {"bytes": 0, "packets": 0})
        values["packets"] += int(found[1])
        values["bytes"] += int(found[2])
    return result


class LinuxFilterDriver:
    def __init__(self) -> None:
        save = shutil.which("iptables-save")
        restore = shutil.which("iptables-restore")
        if not save or not restore:
            raise RuntimeError("Linux mode requires iptables-save and iptables-restore")
        self.save_bin = save
        self.restore_bin = restore

    def snapshot(self, with_counters: bool = False) -> str:
        # Import locally so the existing command adapter stays the only process runner.
        from app.firewall import LinuxDriver

        args = [self.save_bin, "-t", "filter"]
        if with_counters:
            args.append("-c")
        return (
            "\n".join(
                line
                for line in LinuxDriver.run(args).splitlines()
                if line and not line.startswith("#")
            )
            + "\n"
        )

    def restore(self, payload: str, test: bool = False) -> None:
        from app.firewall import LinuxDriver

        args = [self.restore_bin, "--noflush", "--wait", "5"]
        if test:
            args.append("--test")
        LinuxDriver.run(args, payload)


class DemoFilterDriver:
    def __init__(self, config: Configuration) -> None:
        from app.firewall import DemoDriver

        self._table = DemoDriver(Configuration())
        self._table.table = EMPTY_FILTER
        self.restore(filter_patch(EMPTY_FILTER, config))

    def snapshot(self, with_counters: bool = False) -> str:
        return self._table.snapshot(with_counters)

    def restore(self, payload: str, test: bool = False) -> None:
        self._table.restore(payload, test)
