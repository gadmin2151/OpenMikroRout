"""Validated router configuration shared by the API, storage and compilers."""

import ipaddress
import re
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config_migrations import migrate_legacy_address_lists
from app.discovery_models import DiscoverySettings, ScanSettings
from app.fail2ban_models import F2BConfiguration, RuleProtection, profile_id
from app.ipv4 import domain_name
from app.match_expansion import MAX_RULE_EXPANSION, address_list_matches
from app.network_models import NetworkConfiguration
from app.system_lists import (
    GeoIPSettings,
    SystemAddressList,
    country_code,
    is_system_list,
    resolved_system_lists,
)

MAX_COMPILED_RULES = 4096

MatchField = Literal[
    "protocol",
    "src_address",
    "dst_address",
    "src_list",
    "dst_list",
    "src_country",
    "dst_country",
    "src_ports",
    "dst_ports",
    "in_interface",
    "out_interface",
    "connection_states",
]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def network(value: str) -> str:
    try:
        return str(ipaddress.IPv4Network(value, strict=False))
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address or subnet, e.g. 192.168.1.0/24") from exc


def interface_name(value: str) -> str:
    if value and not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.:+-]{0,14}", value):
        raise ValueError("Invalid Linux interface name")
    return value


def port_spec(value: str) -> str:
    if not value:
        return value
    parts = value.replace(" ", "").replace(":", "-").split(",")
    slots = 0
    for part in parts:
        if not re.fullmatch(r"[0-9]{1,5}(-[0-9]{1,5})?", part):
            raise ValueError("Ports must be numbers or ranges, e.g. 80,443,8000-8010")
        bounds = [int(x) for x in part.split("-")]
        if not all(1 <= x <= 65535 for x in bounds) or bounds[0] > bounds[-1]:
            raise ValueError("Port range must be ascending and between 1 and 65535")
        slots += len(bounds)
    if slots > 15:
        raise ValueError("At most 15 port slots are allowed; a range uses two slots")
    return ",".join(parts)


class AddressList(Model):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$")
    addresses: list[Annotated[str, Field(max_length=32)]] = Field(min_length=1, max_length=256)
    comment: str = Field(default="", max_length=200)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if is_system_list(value):
            raise ValueError("The geo_ and f2b_ prefixes are reserved for system address lists")
        return value

    @field_validator("addresses")
    @classmethod
    def validate_addresses(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(network(value.strip()) for value in values))


class RuleMatch(Model):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=80)
    enabled: bool = True
    protocol: Literal["any", "tcp", "udp", "icmp", "gre", "esp", "ah"] = "tcp"
    src_address: str = Field(default="", max_length=32)
    dst_address: str = Field(default="", max_length=32)
    src_list: str = Field(default="", max_length=40)
    dst_list: str = Field(default="", max_length=40)
    src_country: str = Field(default="", max_length=2)
    dst_country: str = Field(default="", max_length=2)
    f2b_profile: str = Field(default="", max_length=20)
    f2b_match: Literal["banned", "not_banned"] = "not_banned"
    protection: RuleProtection = Field(default_factory=RuleProtection)
    src_ports: str = Field(default="", max_length=200)
    dst_ports: str = Field(default="", max_length=200)
    in_interface: str = Field(default="", max_length=15)
    out_interface: str = Field(default="", max_length=15)
    in_interface_list: str = Field(default="", max_length=40)
    out_interface_list: str = Field(default="", max_length=40)
    connection_states: list[Literal["NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"]] = (
        Field(default_factory=list, max_length=5)
    )
    negate: list[MatchField] = Field(default_factory=list, max_length=12)
    comment: str = Field(default="", max_length=200)

    @field_validator("negate")
    @classmethod
    def unique_negations(cls, values: list[MatchField]) -> list[MatchField]:
        return list(dict.fromkeys(values))

    @field_validator("src_address", "dst_address")
    @classmethod
    def validate_network(cls, value: str) -> str:
        return network(value) if value else value

    @field_validator("src_country", "dst_country")
    @classmethod
    def validate_country(cls, value: str) -> str:
        return country_code(value) if value else ""

    @field_validator("f2b_profile")
    @classmethod
    def validate_f2b_profile(cls, value: str) -> str:
        return profile_id(value) if value else ""

    @field_validator("src_ports", "dst_ports")
    @classmethod
    def validate_ports(cls, value: str) -> str:
        return port_spec(value)

    @field_validator("in_interface", "out_interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        return interface_name(value)

    @model_validator(mode="after")
    def validate_matches(self) -> Self:
        for key in self.negate:
            if not getattr(self, key) or key == "protocol" and self.protocol == "any":
                raise ValueError(f"Negation requires a non-empty {key} match")
        if self.src_address and self.src_list or self.dst_address and self.dst_list:
            raise ValueError("Choose either an address or an address list for each side")
        if (
            self.in_interface
            and self.in_interface_list
            or self.out_interface
            and self.out_interface_list
        ):
            raise ValueError("Choose either an interface or an interface list for each side")
        if (self.src_ports or self.dst_ports) and self.protocol not in ("tcp", "udp"):
            raise ValueError("Ports require the TCP or UDP protocol")
        if "protocol" in self.negate and (self.src_ports or self.dst_ports):
            raise ValueError("Port matches require a positive TCP or UDP protocol")
        return self


class NatRule(RuleMatch):
    chain: Literal["dstnat", "srcnat", "output"] = "dstnat"
    action: Literal["dst-nat", "src-nat", "masquerade", "redirect", "accept"] = "dst-nat"
    to_address: str = Field(default="", max_length=15)
    to_ports: str = Field(default="", max_length=11)

    @field_validator("to_ports")
    @classmethod
    def validate_translation_ports(cls, value: str) -> str:
        return port_spec(value)

    @field_validator("to_address")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if value:
            try:
                return str(ipaddress.IPv4Address(value))
            except ValueError as exc:
                raise ValueError("Translation target must be a single IPv4 address") from exc
        return value

    @model_validator(mode="after")
    def validate_combination(self) -> Self:
        if self.to_ports and self.protocol not in ("tcp", "udp"):
            raise ValueError("Ports require the TCP or UDP protocol")
        if self.to_ports and "protocol" in self.negate:
            raise ValueError("Translation ports require a positive TCP or UDP protocol")
        if self.chain == "srcnat" and self.action not in ("src-nat", "masquerade", "accept"):
            raise ValueError("srcnat supports src-nat, masquerade or accept")
        if self.chain != "srcnat" and self.action not in ("dst-nat", "redirect", "accept"):
            raise ValueError("dstnat and output support dst-nat, redirect or accept")
        if (self.in_interface or self.in_interface_list) and self.chain != "dstnat":
            raise ValueError("Incoming interface is only available in dstnat")
        if (self.out_interface or self.out_interface_list) and self.chain == "dstnat":
            raise ValueError("Outgoing interface is unavailable in dstnat")
        if self.action in ("dst-nat", "src-nat") and not self.to_address:
            raise ValueError("This action requires a translation address")
        if self.action not in ("dst-nat", "src-nat") and self.to_address:
            raise ValueError("This action does not use a translation address")
        if self.action == "accept" and self.to_ports:
            raise ValueError("Accept does not translate ports")
        if "," in self.to_ports:
            raise ValueError("Translation ports must be one port or one range")
        return self


class FilterRule(RuleMatch):
    chain: Literal["input", "forward", "output"] = "forward"
    action: Literal["accept", "drop", "reject"] = "accept"

    @model_validator(mode="after")
    def validate_hook(self) -> Self:
        if self.chain == "input" and (self.out_interface or self.out_interface_list):
            raise ValueError("The input chain does not have an outgoing interface")
        if self.chain == "output" and (self.in_interface or self.in_interface_list):
            raise ValueError("The output chain does not have an incoming interface")
        return self


class Configuration(Model):
    @model_validator(mode="before")
    @classmethod
    def migrate_legacy(cls, value: object) -> object:
        return migrate_legacy_address_lists(value)

    fail2ban: F2BConfiguration = Field(default_factory=F2BConfiguration)
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    scanning: ScanSettings = Field(default_factory=ScanSettings)
    rules: list[NatRule] = Field(default_factory=list, max_length=512)
    filter_rules: list[FilterRule] = Field(default_factory=list, max_length=512)
    address_lists: list[AddressList] = Field(default_factory=list, max_length=128)
    system_lists: list[SystemAddressList] = Field(default_factory=list, max_length=277)
    geoip: GeoIPSettings = Field(default_factory=GeoIPSettings)
    network: NetworkConfiguration = Field(default_factory=NetworkConfiguration)
    web_domain: str = Field(default="", max_length=254)

    @field_validator("web_domain")
    @classmethod
    def validate_web_domain(cls, value: str) -> str:
        if not value:
            return ""
        normalized = domain_name(value)
        if re.fullmatch(r"[0-9.]+", normalized):
            raise ValueError("Enter a DNS hostname without a scheme, port or path")
        return normalized

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if len(self.fail2ban.profiles) > 16:
            raise ValueError("At most 16 manual Fail2ban profiles are allowed")
        if any(
            profile.rule_id or profile.rule_table or profile.scope
            for profile in self.fail2ban.profiles
        ):
            raise ValueError(
                "Rule-managed Fail2ban profiles must be configured in their parent rule"
            )
        lists = {item.name: item for item in self.address_lists}
        systems = resolved_system_lists(self)
        if len({item.name for item in self.system_lists}) != len(self.system_lists):
            raise ValueError("System address list names must be unique")
        interfaces = {item.name: item for item in self.network.interface_lists}
        if len(lists) != len(self.address_lists):
            raise ValueError("Address list names must be unique")
        rules: list[RuleMatch] = [*self.rules, *self.filter_rules]
        ids = [str(item.id) for item in rules] + [str(item.id) for item in self.address_lists]
        if len(set(ids)) != len(ids):
            raise ValueError("Rule and address list identifiers must be unique")
        count = 0
        from app.rule_protection import effective_fail2ban

        profiles = {profile.id for profile in effective_fail2ban(self).profiles}
        for rule in rules:
            if rule.f2b_profile and rule.f2b_profile not in profiles:
                raise ValueError(f"Unknown Fail2ban profile: {rule.f2b_profile}")
            expansion = 1
            for field in ("src_list", "dst_list"):
                ref = getattr(rule, field)
                if ref and ref not in lists and ref not in systems:
                    raise ValueError(f"Unknown address list: {ref}")
                if ref in lists:
                    expansion *= len(
                        address_list_matches(
                            lists[ref].addresses,
                            negate=field in rule.negate,
                        )
                    )
            for ref in (rule.in_interface_list, rule.out_interface_list):
                if ref and ref not in interfaces:
                    raise ValueError(f"Unknown interface list: {ref}")
                if ref:
                    expansion *= len(interfaces[ref].members)
            if expansion > MAX_RULE_EXPANSION:
                raise ValueError(f"Rule '{rule.name}' expands beyond 256 address combinations")
            if rule.enabled:
                count += expansion
        if count > MAX_COMPILED_RULES:
            raise ValueError("Configuration expands beyond 4096 iptables rules")
        return self


class SaveRequest(Model):
    revision: int = Field(ge=0)
    config: Configuration


class RevisionRequest(Model):
    revision: int = Field(ge=0)


class ConfirmRequest(Model):
    token: str = Field(min_length=20, max_length=100)


class LoginRequest(Model):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    username: str = Field(default="admin", min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512, repr=False)
    code: str = Field(default="", max_length=64, repr=False)

    @field_validator("username")
    @classmethod
    def login_username(cls, value: str) -> str:
        # Keep password-only clients compatible with the original administrator login.
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
            raise ValueError("Enter a valid username")
        return value.lower()
