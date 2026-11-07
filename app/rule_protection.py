"""Derive rule-owned Fail2ban profiles without duplicating editable configuration."""

from typing import TYPE_CHECKING, Literal, cast
from uuid import UUID

from app.fail2ban_models import (
    MAX_INLINE_PROFILES,
    F2BConfiguration,
    F2BProfile,
    F2BServiceScope,
)
from app.system_lists import is_system_list

if TYPE_CHECKING:
    from app.models import Configuration, RuleMatch

MAX_PROTECTION_MATCHES = 1024


def rule_profile_id(identifier: UUID) -> str:
    return "r_" + identifier.hex[:18]


def concrete_ports(value: str) -> list[int]:
    """Turn validated rule port syntax into a bounded service endpoint list."""
    if not value:
        raise ValueError("Automatic Fail2ban protection requires explicit destination ports")
    result: list[int] = []
    for part in value.split(","):
        limits = part.split("-")
        start, end = int(limits[0]), int(limits[-1])
        if len(limits) > 2 or not 1 <= start <= end <= 65535:
            raise ValueError("Automatic protection requires valid TCP ports")
        if end - start + 1 > 15:
            raise ValueError("Automatic Fail2ban protection supports at most 15 service ports")
        result.extend(range(start, end + 1))
        result = list(dict.fromkeys(result))
        if len(result) > 15:
            raise ValueError("Automatic Fail2ban protection supports at most 15 service ports")
    return result


def _interfaces(config: "Configuration", rule: "RuleMatch", direction: str) -> list[str]:
    name = getattr(rule, f"{direction}_interface_list")
    if name:
        row = next((item for item in config.network.interface_lists if item.name == name), None)
        if row is None:
            raise ValueError(f"Unknown interface list: {name}")
        if not row.members:
            raise ValueError("Automatic Fail2ban protection requires a non-empty interface list")
        return list(row.members)
    interface = getattr(rule, f"{direction}_interface")
    return [interface] if interface else []


def managed_profiles(config: "Configuration") -> list[F2BProfile]:
    """Resolve protection for a service endpoint, not a copy of every NAT predicate."""
    result: list[F2BProfile] = []
    matches = 0
    identifiers = {profile.id for profile in config.fail2ban.profiles}
    for table, rules in (("nat", config.rules), ("filter", config.filter_rules)):
        for rule in rules:
            policy = rule.protection
            if not policy.enabled:
                continue
            if len(result) >= MAX_INLINE_PROFILES:
                raise ValueError(f"At most {MAX_INLINE_PROFILES} rules can own Fail2ban protection")
            if rule.protocol != "tcp":
                raise ValueError("Automatic Fail2ban protection currently requires TCP")
            identifier = rule_profile_id(rule.id)
            if identifier in identifiers:
                raise ValueError(
                    "Automatic Fail2ban profile identity conflicts with another profile"
                )
            identifiers.add(identifier)
            scope = F2BServiceScope(in_interfaces=_interfaces(config, rule, "in"))
            if table == "nat":
                if rule.chain != "dstnat" or rule.action not in ("dst-nat", "redirect"):
                    raise ValueError(
                        "Automatic NAT protection requires dstnat with dst-nat or redirect"
                    )
                ports = concrete_ports(rule.to_ports or rule.dst_ports)
                chain = "forward" if rule.action == "dst-nat" else "input"
                if rule.action == "dst-nat":
                    scope.destinations = [rule.to_address + "/32"]
                    # A DNAT target may be router-local or forwarded. An exact endpoint
                    # guard in both hooks covers either route without guessing host IPs.
                    scope.chains = ["input", "forward"]
            else:
                if rule.chain not in ("input", "forward"):
                    raise ValueError("Automatic Filter protection requires input or forward")
                chain = rule.chain
                ports = concrete_ports(rule.dst_ports)
                scope.out_interfaces = _interfaces(config, rule, "out")
                if rule.dst_list:
                    if is_system_list(rule.dst_list):
                        scope.destination_sets.append(rule.dst_list)
                    else:
                        addresses = next(
                            (item for item in config.address_lists if item.name == rule.dst_list),
                            None,
                        )
                        if addresses is None:
                            raise ValueError(f"Unknown address list: {rule.dst_list}")
                        if not addresses.addresses:
                            raise ValueError(
                                "Automatic protection requires a non-empty destination list"
                            )
                        scope.destinations = list(addresses.addresses)
                elif rule.dst_address:
                    scope.destinations = [rule.dst_address]
                if rule.dst_country:
                    scope.destination_sets = list(
                        dict.fromkeys([*scope.destination_sets, f"geo_{rule.dst_country}"])
                    )
            if policy.event_source in ("web", "ssh") and chain != "input":
                raise ValueError(
                    "Router Web/SSH failures cannot protect a forwarded remote service"
                )
            matches += (
                max(1, len(scope.destinations))
                * max(1, len(scope.in_interfaces))
                * max(1, len(scope.out_interfaces))
                * max(1, len(scope.chains))
            )
            if matches > MAX_PROTECTION_MATCHES:
                raise ValueError("Automatic protection expands beyond 1024 service matches")
            result.append(
                F2BProfile(
                    id=identifier,
                    name=rule.name,
                    service=policy.event_source,
                    enabled=rule.enabled,
                    chain=cast(Literal["input", "forward"], chain),
                    ports=ports,
                    in_interface=scope.in_interfaces[0] if len(scope.in_interfaces) == 1 else "",
                    destination=scope.destinations[0] if len(scope.destinations) == 1 else "",
                    max_retry=policy.max_retry,
                    find_time=policy.find_time,
                    ban_time=policy.ban_time,
                    rule_id=rule.id,
                    rule_table=cast(Literal["nat", "filter"], table),
                    scope=scope,
                )
            )
    return result


def effective_fail2ban(config: "Configuration") -> F2BConfiguration:
    """Manual engine toggle gates manual profiles; inline protection is independent."""
    generated = managed_profiles(config)
    active = any(profile.enabled for profile in generated)
    manual = [profile.model_copy(deep=True) for profile in config.fail2ban.profiles]
    if active and not config.fail2ban.enabled:
        for profile in manual:
            profile.enabled = False
    profiles = [*manual, *generated]
    # HTTP proxy trust governs Web authentication events only. Disabled manual
    # Web settings must not prevent independent TCP/SSH protection from starting.
    web_active = any(profile.enabled and profile.service == "web" for profile in profiles)
    proxy_irrelevant = active and not web_active
    return F2BConfiguration(
        enabled=config.fail2ban.enabled or active,
        access_mode="direct" if proxy_irrelevant else config.fail2ban.access_mode,
        trusted_proxies=[] if proxy_irrelevant else list(config.fail2ban.trusted_proxies),
        profiles=profiles,
    )
