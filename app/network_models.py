"""Validated IPv4 router settings; independent of API, persistence and host commands."""

import ipaddress
import re
from collections.abc import Sequence
from typing import Annotated, Protocol, Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from app.ipv4 import domain_name, ipv4, subnet
from app.link_models import LinkConfiguration, LinkModel
from app.wireguard_models import WireGuardPeer, validate_wireguard

NAME_PATTERN = r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$"
ADDRESS_LABEL_SUFFIX = ":o"
ROUTE_PROTOCOL = "196"


class _Identified(Protocol):
    id: UUID


def interface_name(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}", value):
        raise ValueError("Enter a Linux interface name, e.g. eth1, br0 or eth0.10")
    return value


class IpAddress(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    enabled: bool = True
    interface: str = Field(min_length=1, max_length=13)
    address: str = Field(min_length=1, max_length=18)
    comment: str = Field(default="", max_length=200)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        return interface_name(value)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        try:
            address = ipaddress.IPv4Interface(value)
        except ValueError as exc:
            raise ValueError("Enter an IPv4 address with prefix, e.g. 192.168.10.1/24") from exc
        ipv4(str(address.ip))
        if address.network.prefixlen < 31 and address.ip in (
            address.network.network_address,
            address.network.broadcast_address,
        ):
            raise ValueError("The router address cannot be the subnet or broadcast address")
        return str(address)


class StaticRoute(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    enabled: bool = True
    destination: str = Field(default="0.0.0.0/0", max_length=18)
    gateway: str = Field(default="", max_length=15)
    interface: str = Field(default="", max_length=15)
    metric: int = Field(default=100, ge=0, le=65535)
    comment: str = Field(default="", max_length=200)

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        return subnet(value)

    @field_validator("gateway")
    @classmethod
    def validate_gateway(cls, value: str) -> str:
        return ipv4(value) if value else value

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        return interface_name(value) if value else value

    @model_validator(mode="after")
    def validate_next_hop(self) -> Self:
        if not self.gateway and not self.interface:
            raise ValueError("A route needs a gateway or an interface")
        return self


class InterfaceList(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=40, pattern=NAME_PATTERN)
    members: list[Annotated[str, Field(max_length=15)]] = Field(min_length=1, max_length=64)
    comment: str = Field(default="", max_length=200)

    @field_validator("members")
    @classmethod
    def validate_members(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(interface_name(value) for value in values))


class DhcpPool(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=40, pattern=NAME_PATTERN)
    start: str = Field(max_length=15)
    end: str = Field(max_length=15)

    @field_validator("start", "end")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return ipv4(value)

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        size = int(ipaddress.IPv4Address(self.end)) - int(ipaddress.IPv4Address(self.start)) + 1
        if not 1 <= size <= 65536:
            raise ValueError("A DHCP pool must be ascending and contain at most 65536 addresses")
        return self


class DhcpServer(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=40, pattern=NAME_PATTERN)
    enabled: bool = True
    interface: str = Field(min_length=1, max_length=13)
    pool: str = Field(min_length=1, max_length=40, pattern=NAME_PATTERN)
    network: str = Field(max_length=18)
    gateway: str = Field(max_length=15)
    dns_servers: list[Annotated[str, Field(max_length=15)]] = Field(
        default_factory=list, max_length=8
    )
    lease_minutes: int = Field(default=720, ge=5, le=10080)
    comment: str = Field(default="", max_length=200)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if value == "lo":
            raise ValueError("DHCP cannot be served on loopback")
        return interface_name(value)

    @field_validator("network")
    @classmethod
    def validate_network(cls, value: str) -> str:
        value = subnet(value)
        if ipaddress.IPv4Network(value).prefixlen > 30:
            raise ValueError("DHCP needs a subnet with usable host addresses (/30 or larger)")
        return value

    @field_validator("gateway")
    @classmethod
    def validate_gateway(cls, value: str) -> str:
        return ipv4(value)

    @field_validator("dns_servers")
    @classmethod
    def validate_dns(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(ipv4(value) for value in values))


class DhcpReservation(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    enabled: bool = True
    server: str = Field(min_length=1, max_length=40, pattern=NAME_PATTERN)
    mac: str = Field(min_length=17, max_length=17)
    address: str = Field(max_length=15)
    hostname: str = Field(default="", max_length=63)
    comment: str = Field(default="", max_length=200)

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", value):
            raise ValueError("Enter a MAC address, e.g. 02:11:22:33:44:55")
        if int(value[:2], 16) & 1 or value.lower() == "00:00:00:00:00:00":
            raise ValueError("A reservation needs a nonzero unicast MAC address")
        return value.lower()

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return ipv4(value)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        if value and not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", value):
            raise ValueError("Use a hostname containing letters, numbers and interior hyphens")
        return value.lower()


class DnsSettings(LinkModel):
    enabled: bool = False
    listen_interfaces: list[Annotated[str, Field(max_length=13)]] = Field(
        default_factory=list, max_length=16
    )
    servers: list[Annotated[str, Field(max_length=15)]] = Field(default_factory=list, max_length=8)
    cache_size: int = Field(default=1000, ge=0, le=10000)
    local_domain: str = Field(default="", max_length=253)

    @field_validator("listen_interfaces")
    @classmethod
    def validate_interfaces(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(interface_name(value) for value in values))

    @field_validator("servers")
    @classmethod
    def validate_servers(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(ipv4(value) for value in values))

    @field_validator("local_domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        value = value.rstrip(".").lower()
        if value and any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in value.split(".")
        ):
            raise ValueError("Enter a DNS domain such as lan.home")
        return value

    @model_validator(mode="after")
    def validate_enabled(self) -> Self:
        if self.enabled and (not self.listen_interfaces or not self.servers):
            raise ValueError("DNS needs explicit listening interfaces and upstream servers")
        return self


class DnsStaticRecord(LinkModel):
    id: UUID = Field(default_factory=uuid4)
    enabled: bool = True
    name: str = Field(min_length=1, max_length=253)
    address: str = Field(min_length=1, max_length=15)
    ttl: int = Field(default=300, ge=0, le=86400)
    comment: str = Field(default="", max_length=200)

    _name = field_validator("name")(domain_name)
    _address = field_validator("address")(ipv4)


class NetworkConfiguration(LinkConfiguration):
    addresses: list[IpAddress] = Field(default_factory=list, max_length=128)
    routes: list[StaticRoute] = Field(default_factory=list, max_length=128)
    interface_lists: list[InterfaceList] = Field(default_factory=list, max_length=128)
    pools: list[DhcpPool] = Field(default_factory=list, max_length=64)
    dhcp_servers: list[DhcpServer] = Field(default_factory=list, max_length=32)
    dhcp_reservations: list[DhcpReservation] = Field(default_factory=list, max_length=512)
    dns: DnsSettings = Field(default_factory=DnsSettings)
    dns_static: list[DnsStaticRecord] = Field(default_factory=list, max_length=512)
    forwarding: bool | None = None
    wireguard_peers: list[WireGuardPeer] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def validate_network_references(self) -> Self:
        collections: list[Sequence[_Identified]] = [
            self.addresses,
            self.routes,
            self.interface_lists,
            self.pools,
            self.dhcp_servers,
            self.dhcp_reservations,
            self.bridges,
            self.vlans,
            self.virtual_interfaces,
            self.wireguard_interfaces,
            self.wireguard_peers,
            self.dns_static,
        ]
        ids = [str(item.id) for collection in collections for item in collection]
        if len(ids) != len(set(ids)):
            raise ValueError("Network object identifiers must be unique")
        validate_wireguard(self.wireguard_interfaces, self.wireguard_peers)
        records = [(item.name, item.address) for item in self.dns_static if item.enabled]
        if len(records) != len(set(records)):
            raise ValueError("Enabled DNS static records must not repeat a name/address pair")
        for collection in (self.interface_lists, self.pools, self.dhcp_servers):
            names = [item.name for item in collection]
            if len(names) != len(set(names)):
                raise ValueError("Interface list, pool and DHCP server names must be unique")
        addresses = [item for item in self.addresses if item.enabled]
        disabled_links = {
            item.name
            for item in (
                *self.bridges,
                *self.vlans,
                *self.virtual_interfaces,
                *self.wireguard_interfaces,
            )
            if not item.enabled
        }
        # A VLAN cannot carry services while any managed VLAN/bridge parent is down.
        # A bridge may still operate with some member ports down, so only VLAN
        # parenting propagates the administrative dependency here.
        for _ in self.vlans:
            descendants = {item.name for item in self.vlans if item.parent in disabled_links}
            if descendants <= disabled_links:
                break
            disabled_links.update(descendants)
        active_services = {item.interface for item in self.dhcp_servers if item.enabled}
        if active_services & {item.name for item in self.wireguard_interfaces}:
            raise ValueError("WireGuard clients use per-peer addresses, not a DHCP server")
        if self.dns.enabled:
            active_services.update(self.dns.listen_interfaces)
        active_services.update(item.interface for item in self.routes if item.enabled)
        if active_services & disabled_links:
            raise ValueError(
                "Enable the managed interface before using it for DHCP, DNS or a route"
            )
        bridge_ports = {name for bridge in self.bridges for name in bridge.members}
        if any(item.interface in bridge_ports for item in addresses):
            raise ValueError("Assign routed IP addresses to the bridge, not its member ports")
        if len({(item.interface, item.address) for item in addresses}) != len(addresses):
            raise ValueError("An address cannot be assigned twice to the same interface")
        routes = [item for item in self.routes if item.enabled]
        if len({(item.destination, item.metric) for item in routes}) != len(routes):
            raise ValueError("Routes to the same destination need different metrics")
        pools = {item.name: item for item in self.pools}
        servers = {item.name: item for item in self.dhcp_servers}
        enabled_servers = [item for item in self.dhcp_servers if item.enabled]
        pool_size = sum(
            int(ipaddress.IPv4Address(pool.end)) - int(ipaddress.IPv4Address(pool.start)) + 1
            for pool in self.pools
            if any(server.pool == pool.name for server in enabled_servers)
        )
        if pool_size > 65536:
            raise ValueError("Enabled DHCP pools may contain at most 65536 addresses in total")
        if len({item.interface for item in enabled_servers}) != len(enabled_servers):
            raise ValueError("Only one enabled DHCP server is supported per interface")
        for server in self.dhcp_servers:
            if server.pool not in pools:
                raise ValueError(f"Unknown DHCP pool: {server.pool}")
            if not server.enabled:
                continue
            net = ipaddress.IPv4Network(server.network)
            pool = pools[server.pool]
            start, end, gateway = (
                ipaddress.IPv4Address(value) for value in (pool.start, pool.end, server.gateway)
            )
            if not all(
                value in net and value not in (net.network_address, net.broadcast_address)
                for value in (start, end, gateway)
            ):
                raise ValueError(f"DHCP pool and gateway must be usable hosts in {server.network}")
            if start <= gateway <= end:
                raise ValueError("A DHCP pool cannot include the gateway address")
            if not any(
                item.interface == server.interface
                and ipaddress.IPv4Interface(item.address).ip == gateway
                and ipaddress.IPv4Interface(item.address).network == net
                for item in addresses
            ):
                raise ValueError(
                    f"Assign gateway {server.gateway}/{net.prefixlen} to "
                    f"{server.interface} in IP Addresses first"
                )
            for item in addresses:
                if start <= ipaddress.IPv4Interface(item.address).ip <= end:
                    raise ValueError("A DHCP pool cannot lease an address assigned to the router")
            if not server.dns_servers and not (
                self.dns.enabled and server.interface in self.dns.listen_interfaces
            ):
                raise ValueError("Set DHCP DNS servers or enable local DNS on the DHCP interface")
        for index, server in enumerate(enabled_servers):
            if any(
                ipaddress.IPv4Network(server.network).overlaps(ipaddress.IPv4Network(other.network))
                for other in enabled_servers[index + 1 :]
            ):
                raise ValueError("Enabled DHCP networks cannot overlap")
        active_reservations = [item for item in self.dhcp_reservations if item.enabled]
        if len({item.mac for item in active_reservations}) != len(active_reservations) or len(
            {item.address for item in active_reservations}
        ) != len(active_reservations):
            raise ValueError("Enabled DHCP reservations need unique MAC and IP addresses")
        for reservation in self.dhcp_reservations:
            if reservation.server not in servers:
                raise ValueError(f"Unknown DHCP server: {reservation.server}")
            server = servers[reservation.server]
            address = ipaddress.IPv4Address(reservation.address)
            net = ipaddress.IPv4Network(server.network)
            if (
                address not in net
                or address in (net.network_address, net.broadcast_address)
                or address == ipaddress.IPv4Address(server.gateway)
            ):
                raise ValueError(
                    "A reservation must be a usable host in its DHCP server network, "
                    "excluding gateway"
                )
            if reservation.enabled and any(
                ipaddress.IPv4Interface(item.address).ip == address for item in addresses
            ):
                raise ValueError("A reservation cannot use an IP assigned to the router")
        if self.dns.enabled:
            listeners = {
                str(ipaddress.IPv4Interface(item.address).ip)
                for item in addresses
                if item.interface in self.dns.listen_interfaces
            }
            for iface in self.dns.listen_interfaces:
                if not any(item.interface == iface for item in addresses):
                    raise ValueError(
                        f"Assign a managed IPv4 address to DNS interface {iface} first"
                    )
            if any(server in listeners for server in self.dns.servers):
                raise ValueError("A DNS upstream cannot point back to the router's DNS listener")
        return self
