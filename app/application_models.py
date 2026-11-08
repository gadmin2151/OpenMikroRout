"""Typed opt-in application policy; no arbitrary classifier or kernel commands."""

import ipaddress
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from app.ipv4 import subnet
from app.link_models import LinkModel, interface_name

CATALOG_VERSION = "seed-2026-11-08"
ApplicationState = Literal["NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"]
AppId = Annotated[str, Field(min_length=1, max_length=80, pattern=r"^app\.[a-z0-9][a-z0-9_.-]*$")]


def default_states() -> list[ApplicationState]:
    return ["NEW", "ESTABLISHED", "RELATED"]


class ApplicationRule(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=80)
    enabled: bool = True
    application_ids: list[AppId] = Field(min_length=1, max_length=64)
    action: Literal["allow", "block"] = "block"
    src_address: str = Field(default="", max_length=18)
    dst_address: str = Field(default="", max_length=18)
    src_list: str = Field(default="", max_length=40)
    dst_list: str = Field(default="", max_length=40)
    in_interface: str = Field(default="", max_length=15)
    out_interface: str = Field(default="", max_length=15)
    in_interface_list: str = Field(default="", max_length=40)
    out_interface_list: str = Field(default="", max_length=40)
    connection_states: list[ApplicationState] = Field(
        default_factory=default_states, min_length=1, max_length=5
    )
    comment: str = Field(default="", max_length=200)

    @field_validator("application_ids", "connection_states")
    @classmethod
    def distinct(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    @field_validator("src_address", "dst_address")
    @classmethod
    def networks(cls, value: str) -> str:
        return subnet(value) if value else ""

    @field_validator("in_interface", "out_interface")
    @classmethod
    def interfaces(cls, value: str) -> str:
        return interface_name(value) if value else ""

    @field_validator("src_list", "dst_list", "in_interface_list", "out_interface_list")
    @classmethod
    def references(cls, value: str) -> str:
        import re

        if value and not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,39}", value):
            raise ValueError("Invalid application scope list name")
        return value

    @model_validator(mode="after")
    def valid_scope(self) -> Self:
        for side in ("src", "dst"):
            if getattr(self, f"{side}_address") and getattr(self, f"{side}_list"):
                raise ValueError("Choose an address or an address list for each application side")
        for side in ("in", "out"):
            if getattr(self, f"{side}_interface") and getattr(self, f"{side}_interface_list"):
                raise ValueError(
                    "Choose an interface or an interface list for each application side"
                )
        if self.action == "allow" and not {"NEW", "ESTABLISHED"} <= set(self.connection_states):
            raise ValueError("Application Allow must include NEW and ESTABLISHED")
        if set(self.connection_states) & {"INVALID", "UNTRACKED"}:
            raise ValueError("Application rules cannot grant or classify INVALID/UNTRACKED flows")
        return self


class ApplicationConfiguration(LinkModel):
    enabled: bool = False
    mode: Literal["observe", "enforce"] = "observe"
    interfaces: list[Annotated[str, Field(max_length=15)]] = Field(
        default_factory=list, max_length=16
    )
    source_networks: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=64
    )
    catalog_version: str = Field(
        default=CATALOG_VERSION,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
    )
    catalog_auto_update: bool = False
    catalog_check_hours: int = Field(default=24, ge=6, le=720)
    rules: list[ApplicationRule] = Field(default_factory=list, max_length=64)
    unknown_policy: Literal["firewall", "block"] = "firewall"
    failure_policy: Literal["block", "firewall"] = "block"
    probe_timeout_ms: int = Field(default=2000, ge=100, le=10000)
    probe_packets: int = Field(default=32, ge=3, le=128)
    probe_bytes: int = Field(default=65536, ge=1024, le=262144)
    max_pending: int = Field(default=512, ge=1, le=2048)
    max_pending_per_client: int = Field(default=32, ge=1, le=128)
    queue_limit: int = Field(default=256, ge=16, le=4096)
    verdict_timeout_ms: int = Field(default=250, ge=10, le=1000)

    @field_validator("interfaces")
    @classmethod
    def valid_interfaces(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(interface_name(value) for value in values))

    @field_validator("source_networks")
    @classmethod
    def valid_sources(cls, values: list[str]) -> list[str]:
        result = []
        for value in values:
            network = ipaddress.IPv4Network(subnet(value))
            if network.prefixlen == 0 or network.is_loopback or network.is_multicast:
                raise ValueError("Applications require explicit non-loopback client networks")
            result.append(str(network))
        return list(dict.fromkeys(result))

    @model_validator(mode="after")
    def bounded_scope(self) -> Self:
        if self.enabled and (not self.interfaces or not self.source_networks):
            raise ValueError(
                "Enable Applications only with explicit interfaces and source networks"
            )
        if self.max_pending_per_client > self.max_pending:
            raise ValueError("The per-client pending limit exceeds the global limit")
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("Application rule identifiers must be unique")
        return self
