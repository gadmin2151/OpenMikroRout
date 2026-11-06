"""Validated, opt-in passive discovery and bounded active scan settings."""

import ipaddress
import re
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from app.ipv4 import endpoint_host
from app.link_models import LinkModel, interface_name

DiscoveryProtocol = Literal["arp", "dhcp", "lldp", "cdp", "mndp"]


def default_protocols() -> list[DiscoveryProtocol]:
    return ["arp", "dhcp", "lldp", "cdp", "mndp"]


def selected_interfaces(values: list[str]) -> list[str]:
    return list(dict.fromkeys(interface_name(value) for value in values))


class DiscoverySettings(LinkModel):
    enabled: bool = False
    interfaces: list[str] = Field(default_factory=list, max_length=32)
    protocols: list[DiscoveryProtocol] = Field(default_factory=default_protocols, max_length=5)
    stale_seconds: int = Field(default=300, ge=30, le=86400)

    _interfaces = field_validator("interfaces")(selected_interfaces)

    @model_validator(mode="after")
    def selected_interfaces(self) -> Self:
        if self.enabled and (not self.interfaces or not self.protocols):
            raise ValueError("Select discovery interfaces and at least one protocol")
        self.protocols = list(dict.fromkeys(self.protocols))
        return self


class ScanSettings(LinkModel):
    enabled: bool = False
    interfaces: list[str] = Field(default_factory=list, max_length=32)
    max_hosts: int = Field(default=256, ge=1, le=1024)
    max_rate: int = Field(default=100, ge=10, le=1000)
    timeout_seconds: int = Field(default=300, ge=10, le=1800)
    history_limit: int = Field(default=50, ge=1, le=100)

    _interfaces = field_validator("interfaces")(selected_interfaces)

    @model_validator(mode="after")
    def selected_interfaces(self) -> Self:
        if self.enabled and not self.interfaces:
            raise ValueError("Select interfaces allowed for active scans")
        return self


class ScanRequest(LinkModel):
    kind: Literal["network", "ports"]
    interface: str = Field(min_length=1, max_length=15)
    target: str = Field(min_length=1, max_length=253)
    profile: Literal["quick", "custom", "full", "udp"] = "quick"
    ports: str = Field(default="", max_length=200)
    service_detection: bool = False

    _interface = field_validator("interface")(interface_name)

    @field_validator("ports")
    @classmethod
    def port_ranges(cls, value: str) -> str:
        if not value:
            return ""
        parts = value.replace(" ", "").split(",")
        if len(parts) > 32:
            raise ValueError("At most 32 port ranges are allowed")
        for part in parts:
            if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", part):
                raise ValueError("Use port numbers or ranges, for example 22,80,443,8000-8010")
            bounds = [int(item) for item in part.split("-")]
            if not (1 <= bounds[0] <= bounds[-1] <= 65535):
                raise ValueError("Port ranges must be ascending, between 1 and 65535")
        return ",".join(parts)

    @model_validator(mode="after")
    def target_and_profile(self) -> Self:
        if self.kind == "network":
            self.target = str(ipaddress.IPv4Network(self.target, strict=False))
            if self.ports or self.service_detection or self.profile != "quick":
                raise ValueError("Network discovery does not run port or service detection")
        else:
            self.target = endpoint_host(self.target)
            if self.profile in ("custom", "udp") and not self.ports:
                raise ValueError("Specify ports for the selected profile")
            if self.profile in ("quick", "full") and self.ports:
                raise ValueError("Ports are selected automatically for this profile")
            if self.profile == "udp":
                count = sum(
                    int(part.split("-")[-1]) - int(part.split("-")[0]) + 1
                    for part in self.ports.split(",")
                )
                if count > 128:
                    raise ValueError("UDP scans are limited to 128 selected ports")
        return self
