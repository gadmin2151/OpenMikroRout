"""Validated topology for application-owned Linux links."""

import re
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ipv4 import endpoint_host, ipv4, subnet
from app.wireguard_keys import public_key

MAX_MANAGED_LINKS = 128
InterfaceName = Annotated[str, Field(min_length=1, max_length=15)]


def interface_name(value: str) -> str:
    """Accept literal device names, never command fragments or iptables wildcards."""
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}", value):
        raise ValueError("Invalid Linux interface name (1–15 letters, digits, _, ., -)")
    if value in ("lo", "all", "default"):
        raise ValueError("This interface name is reserved")
    return value


class LinkModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ManagedLink(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    name: InterfaceName
    enabled: bool = True
    mtu: int = Field(default=1500, ge=576, le=9000)
    comment: str = Field(default="", max_length=200)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return interface_name(value)


class Bridge(ManagedLink):
    members: list[InterfaceName] = Field(default_factory=list, max_length=64)
    stp: bool = True

    @field_validator("members")
    @classmethod
    def validate_members(cls, values: list[str]) -> list[str]:
        result = [interface_name(value) for value in values]
        if len(set(result)) != len(result):
            raise ValueError("Bridge members must be unique")
        return result


class Vlan(ManagedLink):
    parent: InterfaceName
    vlan_id: int = Field(ge=1, le=4094)

    @field_validator("parent")
    @classmethod
    def validate_parent(cls, value: str) -> str:
        return interface_name(value)


class VirtualInterface(ManagedLink):
    kind: Literal["dummy"] = "dummy"


class WireGuardServerAccess(LinkModel):
    """Explicit ingress policy; legacy/manual interfaces retain their existing firewall policy."""

    source_network: str = Field(max_length=18)
    access_networks: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=16
    )
    router_access: bool = False
    wan_interface: str = Field(default="", max_length=15)

    _source = field_validator("source_network")(subnet)
    _wan = field_validator("wan_interface")(lambda value: interface_name(value) if value else "")

    @field_validator("access_networks")
    @classmethod
    def validate_networks(cls, values: list[str]) -> list[str]:
        values = list(dict.fromkeys(subnet(value) for value in values))
        if "0.0.0.0/0" in values:
            raise ValueError("Choose an explicit WAN interface for VPN internet access")
        return values


class WireGuardInterface(ManagedLink):
    name: Annotated[str, Field(min_length=1, max_length=13)]
    mtu: int = Field(default=1420, ge=576, le=9000)
    role: Literal["server", "client", "site-to-site"] = "server"
    listen_port: int = Field(default=51820, ge=0, le=65535)
    private_key_id: UUID
    public_key: str = Field(min_length=44, max_length=44)
    route_allowed_ips: bool = False
    route_sources: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=32
    )
    routing_table: int = Field(default=20000, ge=20000, le=20999)
    kill_switch: bool = True
    client_dns: list[Annotated[str, Field(max_length=15)]] = Field(
        default_factory=list, max_length=8
    )
    client_allowed_ips: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=128
    )
    export_endpoint: str = Field(default="", max_length=253)
    server_access: WireGuardServerAccess | None = None

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return public_key(value)

    @field_validator("route_sources")
    @classmethod
    def validate_route_sources(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(subnet(value) for value in values))

    @field_validator("client_dns")
    @classmethod
    def validate_dns(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(ipv4(value) for value in values))

    @field_validator("client_allowed_ips")
    @classmethod
    def validate_client_routes(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(subnet(value) for value in values))

    @field_validator("export_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return endpoint_host(value)

    @model_validator(mode="after")
    def validate_routing(self) -> Self:
        if self.route_allowed_ips and not self.route_sources:
            raise ValueError("Choose source IPv4 networks for routing through WireGuard")
        if self.server_access is not None and self.role != "server":
            raise ValueError("Server access policy requires a WireGuard server interface")
        return self


class LinkConfiguration(LinkModel):
    bridges: list[Bridge] = Field(default_factory=list, max_length=64)
    vlans: list[Vlan] = Field(default_factory=list, max_length=128)
    virtual_interfaces: list[VirtualInterface] = Field(default_factory=list, max_length=64)
    wireguard_interfaces: list[WireGuardInterface] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_topology(self) -> Self:
        links = [*self.bridges, *self.vlans, *self.virtual_interfaces, *self.wireguard_interfaces]
        if len(links) > MAX_MANAGED_LINKS:
            raise ValueError("At most 128 managed links are supported")
        names = [link.name for link in links]
        if len(set(names)) != len(names):
            raise ValueError("Managed interface names must be unique")
        if len({link.id for link in links}) != len(links):
            raise ValueError("Managed interface identifiers must be unique")
        memberships: dict[str, str] = {}
        wireguard_names = {item.name for item in self.wireguard_interfaces}
        for bridge in self.bridges:
            for member in bridge.members:
                if member in wireguard_names:
                    raise ValueError("WireGuard is a routed interface and cannot be a bridge port")
                if member in memberships:
                    raise ValueError(f"Interface {member} cannot belong to more than one bridge")
                memberships[member] = bridge.name
        if any(item.parent in wireguard_names for item in self.vlans):
            raise ValueError("A VLAN needs an Ethernet parent, not a WireGuard interface")
        tags = [(link.parent, link.vlan_id) for link in self.vlans]
        if len(set(tags)) != len(tags):
            raise ValueError("VLAN identifiers on the same parent must be unique")
        # Both membership and VLAN parenting are topology dependencies. A VLAN of a
        # bridge cannot itself be enslaved back into that bridge.
        dependencies = topology_dependencies(self)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visiting:
                raise ValueError("Interface topology contains a dependency cycle")
            if name in visited:
                return
            visiting.add(name)
            for dependency in dependencies[name]:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)

        for name in dependencies:
            visit(name)
        return self


def planned_interface_names(config: LinkConfiguration) -> set[str]:
    return {
        item.name
        for item in (
            *config.bridges,
            *config.vlans,
            *config.virtual_interfaces,
            *config.wireguard_interfaces,
        )
    }


def topology_dependencies(config: LinkConfiguration) -> dict[str, list[str]]:
    names = planned_interface_names(config)
    result: dict[str, list[str]] = {name: [] for name in names}
    for bridge in config.bridges:
        result[bridge.name] = [name for name in bridge.members if name in names]
    for vlan in config.vlans:
        result[vlan.name] = [vlan.parent] if vlan.parent in names else []
    return result


def ordered_links(config: LinkConfiguration) -> list[ManagedLink]:
    """Dependencies before dependants, with deterministic order for the preview."""
    items = {
        item.name: item
        for item in (
            *config.bridges,
            *config.vlans,
            *config.virtual_interfaces,
            *config.wireguard_interfaces,
        )
    }
    dependencies = topology_dependencies(config)
    result: list[ManagedLink] = []
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        for dependency in dependencies[name]:
            visit(dependency)
        visited.add(name)
        result.append(items[name])

    for name in items:
        visit(name)
    return result
