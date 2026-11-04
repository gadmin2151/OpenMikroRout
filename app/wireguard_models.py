"""Validated, public WireGuard configuration. Secrets are UUID references only."""

import ipaddress
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from app.ipv4 import endpoint_host, ipv4, subnet
from app.link_models import LinkModel, WireGuardInterface, interface_name
from app.wireguard_keys import public_key


class WireGuardPeer(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=64)
    interface: str = Field(min_length=1, max_length=13)
    enabled: bool = True
    public_key: str = Field(min_length=44, max_length=44)
    allowed_ips: list[Annotated[str, Field(max_length=18)]] = Field(min_length=1, max_length=128)
    endpoint_host: str = Field(default="", max_length=253)
    endpoint_port: int = Field(default=51820, ge=1, le=65535)
    persistent_keepalive: int = Field(default=0, ge=0, le=65535)
    preshared_key_id: UUID | None = None
    client_private_key_id: UUID | None = None
    client_address: str = Field(default="", max_length=18)
    client_dns: list[Annotated[str, Field(max_length=15)]] = Field(
        default_factory=list, max_length=8
    )
    client_allowed_ips: list[Annotated[str, Field(max_length=18)]] = Field(
        default_factory=list, max_length=128
    )
    comment: str = Field(default="", max_length=200)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        return interface_name(value)

    @field_validator("public_key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return public_key(value)

    @field_validator("allowed_ips", "client_allowed_ips")
    @classmethod
    def validate_networks(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(subnet(value) for value in values))

    @field_validator("endpoint_host")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return endpoint_host(value)

    @field_validator("client_address")
    @classmethod
    def validate_client_address(cls, value: str) -> str:
        if not value:
            return ""
        try:
            address = ipaddress.IPv4Interface(value)
        except ValueError as exc:
            raise ValueError("Client address must be IPv4 with a prefix") from exc
        ipv4(str(address.ip))
        return str(address)

    @field_validator("client_dns")
    @classmethod
    def validate_dns(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(ipv4(value) for value in values))


def validate_wireguard(interfaces: list[WireGuardInterface], peers: list[WireGuardPeer]) -> None:
    by_name = {item.name: item for item in interfaces}
    ports = [item.listen_port for item in interfaces if item.enabled and item.listen_port]
    if len(set(ports)) != len(ports):
        raise ValueError("Enabled WireGuard interfaces need different nonzero UDP listen ports")
    tables = [item.routing_table for item in interfaces if item.route_allowed_ips]
    if len(set(tables)) != len(tables):
        raise ValueError("WireGuard routing table numbers must be unique")
    sources: list[ipaddress.IPv4Network] = []
    for interface in interfaces:
        if not interface.route_allowed_ips:
            continue
        for prefix in interface.route_sources:
            source = ipaddress.IPv4Network(prefix)
            if source.prefixlen == 0:
                raise ValueError(
                    "Choose specific LAN/source networks; a global host VPN policy is not supported"
                )
            if any(source.overlaps(other) for other in sources):
                raise ValueError("WireGuard source routing networks must not overlap")
            sources.append(source)
    if len(sources) > 128 or sum(len(peer.allowed_ips) for peer in peers) > 1024:
        raise ValueError("WireGuard supports at most 128 routing sources and 1024 allowed prefixes")
    keys: set[tuple[str, str]] = set()
    networks: dict[str, list[ipaddress.IPv4Network]] = {}
    counts: dict[str, int] = {}
    for peer in peers:
        if peer.interface not in by_name:
            raise ValueError(f"WireGuard interface {peer.interface} does not exist")
        if peer.public_key == by_name[peer.interface].public_key:
            raise ValueError("A peer cannot use this router's own public key")
        key = (peer.interface, peer.public_key)
        if key in keys:
            raise ValueError("A peer public key can occur only once on an interface")
        keys.add(key)
        counts[peer.interface] = counts.get(peer.interface, 0) + 1
        if counts[peer.interface] > 128:
            raise ValueError("At most 128 peers per WireGuard interface are supported")
        if peer.enabled:
            ranges = networks.setdefault(peer.interface, [])
            current = []
            for prefix in peer.allowed_ips:
                network = ipaddress.IPv4Network(prefix)
                if any(network.overlaps(other) for other in ranges):
                    raise ValueError("Allowed IP ranges of enabled peers cannot overlap")
                current.append(network)
            ranges.extend(current)
