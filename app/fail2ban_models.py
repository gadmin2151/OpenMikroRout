"""Validated, opt-in IPv4 Fail2ban protection; no arbitrary filters or commands."""

import ipaddress
import re
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.link_models import LinkModel, interface_name
from app.system_lists import country_code, kernel_set_name

MAX_BAN_SECONDS = 2_147_483
MAX_INLINE_PROFILES = 64


class RuleProtection(LinkModel):
    """Rule-owned protection settings; endpoint details come from the parent rule."""

    enabled: bool = False
    event_source: Literal["connections", "web", "ssh"] = "connections"
    max_retry: int = Field(default=5, ge=1, le=100)
    find_time: int = Field(default=600, ge=10, le=86400)
    ban_time: int = Field(default=900, ge=1, le=MAX_BAN_SECONDS)


class F2BServiceScope(LinkModel):
    """Resolved endpoint selectors; only generated profiles can carry this scope."""

    chains: list[Literal["input", "forward"]] = Field(default_factory=list, max_length=2)
    sources: list[Annotated[str, Field(max_length=18)]] | None = Field(default=None, max_length=256)
    excluded_source_sets: list[Annotated[str, Field(max_length=27)]] = Field(
        default_factory=list, max_length=2
    )
    destinations: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=256
    )
    destination_sets: list[Annotated[str, Field(max_length=27)]] = Field(
        default_factory=list, max_length=2
    )
    in_interfaces: list[Annotated[str, Field(max_length=15)]] = Field(
        default_factory=list, max_length=64
    )
    out_interfaces: list[Annotated[str, Field(max_length=15)]] = Field(
        default_factory=list, max_length=64
    )

    @field_validator("destinations")
    @classmethod
    def valid_destinations(cls, values: list[str]) -> list[str]:
        return ipv4_networks(values)

    @field_validator("sources")
    @classmethod
    def valid_sources(cls, values: list[str] | None) -> list[str] | None:
        return ipv4_networks(values) if values is not None else None

    @field_validator("destination_sets", "excluded_source_sets")
    @classmethod
    def valid_sets(cls, values: list[str]) -> list[str]:
        for value in values:
            kernel_set_name(value)
        return list(dict.fromkeys(values))

    @field_validator("in_interfaces", "out_interfaces")
    @classmethod
    def valid_interfaces(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(interface_name(value) for value in values))

    @field_validator("chains")
    @classmethod
    def unique_chains(
        cls, values: list[Literal["input", "forward"]]
    ) -> list[Literal["input", "forward"]]:
        return list(dict.fromkeys(values))


def profile_id(value: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,19}", value):
        raise ValueError("Profile ID must contain 1–20 lowercase letters, digits or underscores")
    return value


def ipv4_networks(values: list[str]) -> list[str]:
    return list(dict.fromkeys(str(ipaddress.IPv4Network(value, strict=False)) for value in values))


class F2BProfile(LinkModel):
    id: str = Field(min_length=1, max_length=20)
    name: str = Field(min_length=1, max_length=80)
    service: Literal["web", "ssh", "connections"] = "web"
    enabled: bool = False
    chain: Literal["input", "forward"] = "input"
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=lambda: [8088], min_length=1, max_length=15
    )
    in_interface: str = Field(default="", max_length=15)
    destination: str = Field(default="", max_length=18)
    max_retry: int = Field(default=5, ge=1, le=100)
    find_time: int = Field(default=600, ge=10, le=86400)
    ban_time: int = Field(default=900, ge=1, le=MAX_BAN_SECONDS)
    ignore_addresses: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=128
    )
    include_countries: list[Annotated[str, Field(pattern=r"^[A-Z]{2}$")]] = Field(
        default_factory=list, max_length=64
    )
    exclude_countries: list[Annotated[str, Field(pattern=r"^[A-Z]{2}$")]] = Field(
        default_factory=list, max_length=64
    )
    shared_listener: bool = False
    rule_id: UUID | None = None
    rule_table: Literal["", "nat", "filter"] = ""
    scope: F2BServiceScope | None = None

    _id = field_validator("id")(profile_id)
    _ignore = field_validator("ignore_addresses")(ipv4_networks)

    @field_validator("in_interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        return interface_name(value) if value else ""

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        return str(ipaddress.IPv4Network(value, strict=False)) if value else ""

    @field_validator("include_countries", "exclude_countries")
    @classmethod
    def validate_countries(cls, values: list[str]) -> list[str]:
        return [country_code(value) for value in values]

    @model_validator(mode="after")
    def unique_values(self) -> Self:
        self.ports = list(dict.fromkeys(self.ports))
        self.include_countries = list(dict.fromkeys(self.include_countries))
        self.exclude_countries = list(dict.fromkeys(self.exclude_countries))
        if set(self.include_countries) & set(self.exclude_countries):
            raise ValueError("A country cannot be both included and excluded")
        if self.service == "ssh" and self.chain != "input":
            raise ValueError("SSH protection reads this router's journal and requires input")
        if bool(self.rule_id) != bool(self.rule_table):
            raise ValueError("Managed protection requires both rule ID and table")
        if bool(self.rule_id) != bool(self.scope):
            raise ValueError("Managed protection requires a resolved service scope")
        if self.service == "connections" and not self.rule_id:
            raise ValueError("Connection protection must belong to a NAT or Filter rule")
        return self


def default_profiles() -> list[F2BProfile]:
    return [
        F2BProfile(id="web", name="Web login", enabled=True),
        F2BProfile(id="ssh", name="SSH", service="ssh", ports=[22]),
    ]


class F2BConfiguration(LinkModel):
    enabled: bool = False
    access_mode: Literal["direct", "local_proxy", "external_proxy"] = "direct"
    trusted_proxies: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=16
    )
    profiles: list[F2BProfile] = Field(
        default_factory=default_profiles, max_length=16 + MAX_INLINE_PROFILES
    )

    _proxies = field_validator("trusted_proxies")(ipv4_networks)

    @model_validator(mode="after")
    def validate_protection(self) -> Self:
        if len({item.id for item in self.profiles}) != len(self.profiles):
            raise ValueError("Fail2ban profile identifiers must be unique")
        if sum(item.rule_id is None for item in self.profiles) > 16:
            raise ValueError("At most 16 manual Fail2ban profiles are allowed")
        if sum(item.rule_id is not None for item in self.profiles) > MAX_INLINE_PROFILES:
            raise ValueError(
                f"At most {MAX_INLINE_PROFILES} rule-owned Fail2ban profiles are allowed"
            )
        if any(ipaddress.IPv4Network(value).prefixlen == 0 for value in self.trusted_proxies):
            raise ValueError("A trusted proxy cannot include the entire IPv4 internet")
        if self.enabled and self.access_mode == "local_proxy" and not self.trusted_proxies:
            raise ValueError("Local proxy mode requires explicit trusted proxy addresses")
        if self.enabled and self.access_mode == "external_proxy":
            raise ValueError(
                "An external proxy requires an action on that proxy; local bans are ineffective"
            )
        return self


def client_ipv4(config: F2BConfiguration, peer: str, forwarded_for: str = "") -> str | None:
    """Use socket peer, or ONE proxy address only when peer is explicitly trusted."""
    try:
        address = ipaddress.IPv4Address(peer)
        if config.access_mode == "external_proxy":
            return None
        if config.access_mode == "local_proxy":
            if not any(address in ipaddress.IPv4Network(net) for net in config.trusted_proxies):
                return None
            # Multi-hop chains cannot be safely inferred from an unconfigured trust chain.
            address = ipaddress.IPv4Address(forwarded_for.strip())
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            return None
        return str(address)
    except ipaddress.AddressValueError:
        return None
