"""Resolve typed scopes and compile application gates without a global ACCEPT."""

import hashlib
import itertools
import json
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.application_models import ApplicationRule
    from app.models import Configuration, FilterRule

CT_MASK = 0x00FFFFFF
CT_VALID = 0x40
CT_PENDING = 0x80
EPOCH_SHIFT = 8
EPOCH_MASK = 0x00FFFF00
VALID_EPOCH_MASK = EPOCH_MASK | CT_VALID
STATE_SHIFTS = {"NEW": 0, "ESTABLISHED": 2, "RELATED": 4}
APP_CHAIN = "OMR_APP_FORWARD"
APP_ANCHOR = "openmikrorout:applications-anchor"
DENIAL_PREFIX = "OMR_APD_"
QUEUE_CHAIN = "OMR_APP_QUEUE"
QUEUE_ANCHOR = "openmikrorout:applications-queue"
QUEUE_NUMBER = 5089


def owned_chain(name: str) -> bool:
    return name == APP_CHAIN or bool(re.fullmatch(DENIAL_PREFIX + r"[a-f0-9]{18}", name))


def denial_chain(rule: "FilterRule") -> str:
    return DENIAL_PREFIX + rule.id.hex[:18]


def app_anchor() -> list[str]:
    return ["-A", "FORWARD", "-m", "comment", "--comment", APP_ANCHOR, "-j", APP_CHAIN]


def active(config: "Configuration") -> bool:
    return config.applications.enabled and config.applications.mode == "enforce"


def security_scope(config: "Configuration") -> dict[str, Any]:
    """MFA review includes transitive list membership, not only reference names."""
    eligible = [rule for rule in config.filter_rules if rule.application_override_eligible]
    references: list[ApplicationRule | FilterRule] = [*config.applications.rules, *eligible]
    address_names = {name for rule in references for name in (rule.src_list, rule.dst_list) if name}
    interface_names = {
        name
        for rule in references
        for name in (rule.in_interface_list, rule.out_interface_list)
        if name
    }
    return {
        "addresses": {
            item.name: item.addresses for item in config.address_lists if item.name in address_names
        },
        "interfaces": {
            item.name: item.members
            for item in config.network.interface_lists
            if item.name in interface_names
        },
    }


def reevaluate_interfaces(config: "Configuration") -> bool:
    return any(
        rule.enabled
        and (
            rule.in_interface
            or rule.out_interface
            or rule.in_interface_list
            or rule.out_interface_list
        )
        for rule in config.applications.rules
    )


def metadata(epoch: int, outcome: int, state: str) -> tuple[int, int]:
    shift = STATE_SHIFTS[state]
    return (epoch << EPOCH_SHIFT) | CT_VALID | (outcome << shift), VALID_EPOCH_MASK | (3 << shift)


def scoped_matches(config: "Configuration") -> list[list[str]]:
    result = []
    for interface, network, protocol in itertools.product(
        config.applications.interfaces, config.applications.source_networks, ("tcp", "udp")
    ):
        result += [
            [
                "-p",
                protocol,
                "-i",
                interface,
                "-m",
                "conntrack",
                "--ctdir",
                "ORIGINAL",
                "--ctorigsrc",
                network,
            ],
            [
                "-p",
                protocol,
                "-o",
                interface,
                "-m",
                "conntrack",
                "--ctdir",
                "REPLY",
                "--ctorigsrc",
                network,
            ],
        ]
    return result


def guard_rules(config: "Configuration", epoch: int | None) -> list[str]:
    if not active(config):
        return []
    marker = ["-m", "comment", "--comment", "openmikrorout:application-guard"]
    result = []
    for scope in scoped_matches(config):
        base = ["-A", APP_CHAIN, *scope]
        if epoch is None:
            result.append(" ".join([*base, *marker, "-j", "DROP"]))
            continue
        result.append(
            " ".join(
                [
                    *base,
                    "-m",
                    "connmark",
                    "!",
                    "--mark",
                    f"{(epoch << EPOCH_SHIFT) | CT_VALID:#x}/{VALID_EPOCH_MASK:#x}",
                    *marker,
                    "-j",
                    "DROP",
                ]
            )
        )
        for state in STATE_SHIFTS:
            value, mask = metadata(epoch, 3, state)
            result.append(
                " ".join(
                    [
                        *base,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        state,
                        "-m",
                        "connmark",
                        "--mark",
                        f"{value:#x}/{mask:#x}",
                        *marker,
                        "-j",
                        "DROP",
                    ]
                )
            )
    # Untracked packets have no usable original tuple. Constrain both LAN edges.
    for interface, network, protocol in itertools.product(
        config.applications.interfaces, config.applications.source_networks, ("tcp", "udp")
    ):
        for selectors in (("-i", interface, "-s", network), ("-o", interface, "-d", network)):
            result.append(
                " ".join(
                    [
                        "-A",
                        APP_CHAIN,
                        "-p",
                        protocol,
                        *selectors,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "INVALID,UNTRACKED",
                        *marker,
                        "-j",
                        "DROP",
                    ]
                )
            )
    return [*result, f"-A {APP_CHAIN} {' '.join(marker)} -j RETURN"]


def denial_rules(config: "Configuration", epoch: int | None) -> list[str]:
    if not active(config) or epoch is None:
        return []
    result = []
    for rule in config.filter_rules:
        if not rule.enabled or not rule.application_override_eligible:
            continue
        name = denial_chain(rule)
        marker = ["-m", "comment", "--comment", f"openmikrorout:app-port-exception:{rule.id}"]
        scopes = [scope for scope in scoped_matches(config) if scope[1] == rule.protocol]
        for state, outcome, scope in itertools.product(STATE_SHIFTS, (1, 2), scopes):
            value, mask = metadata(epoch, outcome, state)
            result.append(
                " ".join(
                    [
                        "-A",
                        name,
                        *scope,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        state,
                        "-m",
                        "connmark",
                        "--mark",
                        f"{value:#x}/{mask:#x}",
                        *marker,
                        "-j",
                        "RETURN",
                    ]
                )
            )
        result.append(" ".join(["-A", name, *marker, "-j", rule.action.upper()]))
    return result


def resolve_policy(
    config: "Configuration",
    catalog_entries: list[dict[str, Any]],
    epoch: int,
    *,
    engine_license_profile: str = "lgpl-only",
) -> dict[str, Any]:
    if engine_license_profile not in ("lgpl-only", "not-for-profit", "commercial-license"):
        raise ValueError("Unknown trusted nDPI license profile")
    settings = config.applications
    entries = {entry["id"]: entry for entry in catalog_entries}
    addresses = {item.name: item.addresses for item in config.address_lists}
    interfaces = {item.name: item.members for item in config.network.interface_lists}
    rules = []
    for rule in settings.rules:
        for reference in rule.application_ids:
            if reference not in entries or entries[reference]["kind"] != "application":
                raise ValueError(
                    "Application rules require known concrete catalog IDs; expand families first"
                )
            if settings.enabled and settings.mode == "enforce" and rule.enabled:
                if rule.action == "block" and set(rule.connection_states) == {"NEW"}:
                    raise ValueError(
                        "NEW-only application blocking requires a verified first-packet detector"
                    )
                capability = "allow_over_port_deny" if rule.action == "allow" else "block_validated"
                if not entries[reference].get(capability):
                    raise ValueError(
                        f"Application {reference} has no validated {rule.action} capability"
                    )
        resolved: dict[str, Any] = rule.model_dump(mode="json")
        for side, key in (("src", "src_addresses"), ("dst", "dst_addresses")):
            reference = getattr(rule, f"{side}_list")
            if reference and reference not in addresses:
                raise ValueError(
                    "Application scopes require an existing explicit IPv4 address list"
                )
            value = getattr(rule, f"{side}_address")
            resolved[key] = addresses[reference] if reference else ([value] if value else [])
        for side, key in (("in", "in_interfaces"), ("out", "out_interfaces")):
            reference = getattr(rule, f"{side}_interface_list")
            if reference and reference not in interfaces:
                raise ValueError("Unknown application interface list")
            value = getattr(rule, f"{side}_interface")
            resolved[key] = interfaces[reference] if reference else ([value] if value else [])
        rules.append(resolved)
    if len(settings.interfaces) * len(settings.source_networks) > 64 and settings.mode == "enforce":
        raise ValueError(
            "Application enforcement supports at most 64 interface/network combinations"
        )
    if sum(entry["kind"] in ("application", "protocol") for entry in catalog_entries) > 4096:
        raise ValueError("The native policy supports at most 4096 applications and protocols")
    policy: dict[str, Any] = {
        "schema": 1,
        "engine_license_profile": engine_license_profile,
        "mode": settings.mode,
        "epoch": epoch,
        "interfaces": settings.interfaces,
        "source_networks": settings.source_networks,
        "queue_num": QUEUE_NUMBER,
        "ct_mask": CT_MASK,
        "ct_valid_bit": CT_VALID,
        "ct_pending_bit": CT_PENDING,
        "ct_epoch_shift": EPOCH_SHIFT,
        "state_shifts": STATE_SHIFTS,
        "reevaluate_interfaces": reevaluate_interfaces(config),
        "unknown_policy": settings.unknown_policy,
        "failure_policy": settings.failure_policy,
        "limits": {
            name: getattr(settings, name)
            for name in (
                "probe_timeout_ms",
                "probe_packets",
                "probe_bytes",
                "max_pending",
                "max_pending_per_client",
                "queue_limit",
                "verdict_timeout_ms",
            )
        },
        "rules": rules,
        "catalog": {
            "version": settings.catalog_version,
            "entries": [
                {
                    "id": entry["id"],
                    "kind": entry["kind"],
                    "protocol_names": entry.get("protocol_names", []),
                    "domains": entry.get("domains", [])
                    if entry.get("hostname_extraction_supported")
                    and engine_license_profile != "lgpl-only"
                    else [],
                    "allow_over_port_deny": entry.get("allow_over_port_deny", False),
                }
                for entry in catalog_entries
                if entry["kind"] in ("application", "protocol")
            ],
        },
    }
    raw = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    policy["generation"] = hashlib.sha256(raw).hexdigest()
    if len(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()) > 4 * 1024 * 1024:
        raise ValueError("The resolved application policy exceeds 4 MiB")
    return policy


def queue_patch(snapshot: str, config: "Configuration", epoch: int | None) -> str:
    """Own one mangle chain; incompatible terminal paths fail preflight."""
    if not snapshot.startswith("*mangle\n") or "\nCOMMIT" not in snapshot:
        raise ValueError("Invalid mangle snapshot")
    import shlex

    jump = ["-A", "FORWARD", "-m", "comment", "--comment", QUEUE_ANCHOR, "-j", QUEUE_CHAIN]
    hooked = False
    for line in snapshot.splitlines():
        if not line.startswith("-A "):
            continue
        tokens = shlex.split(line)
        if tokens[1] == QUEUE_CHAIN and (
            "--comment" not in tokens
            or not tokens[tokens.index("--comment") + 1].startswith("openmikrorout:application")
        ):
            raise ValueError("An unmanaged rule occupies the application queue chain")
        if any(
            tokens[index + 1] == QUEUE_CHAIN
            for index, token in enumerate(tokens[:-1])
            if token in ("-j", "-g")
        ):
            if tokens != jump:
                raise ValueError("An unmanaged rule references the application queue")
            hooked = True
        if active(config) and "-j" in tokens and tokens[tokens.index("-j") + 1] == "CONNMARK":
            raise ValueError("A foreign connmark writer conflicts with application metadata")
        if active(config) and tokens[1] == "FORWARD" and tokens != jump:
            target = tokens[tokens.index("-j") + 1] if "-j" in tokens else ""
            if "-g" in tokens or target not in (
                "MARK",
                "CONNMARK",
                "DSCP",
                "TOS",
                "TTL",
                "HL",
                "CHECKSUM",
                "LOG",
                "NFLOG",
            ):
                raise ValueError(
                    "An incompatible foreign mangle FORWARD path bypasses application inspection"
                )
            if target == "CONNMARK":
                raise ValueError("A foreign connmark writer conflicts with application metadata")
    lines = ["*mangle", f":{QUEUE_CHAIN} - [0:0]"]
    if hooked:
        lines.append(" ".join(["-D", *jump[1:]]))
    if active(config) and epoch is not None:
        for scope in scoped_matches(config):
            base = ["-A", QUEUE_CHAIN, *scope]
            value = (epoch << EPOCH_SHIFT) | CT_VALID
            mask = VALID_EPOCH_MASK | CT_PENDING
            # Final decisions avoid userspace. Every pending packet remains queued.
            if not reevaluate_interfaces(config):
                lines.append(
                    " ".join(
                        [
                            *base,
                            "-m",
                            "conntrack",
                            "--ctstate",
                            "NEW,ESTABLISHED",
                            "!",
                            "--ctstatus",
                            "EXPECTED",
                            "-m",
                            "connmark",
                            "--mark",
                            f"{value:#x}/{mask:#x}",
                            "-m",
                            "comment",
                            "--comment",
                            "openmikrorout:application-final",
                            "-j",
                            "RETURN",
                        ]
                    )
                )
            lines.append(
                " ".join(
                    [
                        *base,
                        "-m",
                        "comment",
                        "--comment",
                        "openmikrorout:application-inspect",
                        "-j",
                        "NFQUEUE",
                        "--queue-num",
                        str(QUEUE_NUMBER),
                    ]
                )
            )
        lines.append(" ".join(jump))
    return "\n".join([*lines, "COMMIT", ""])
