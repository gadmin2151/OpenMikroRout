"""WireGuard setup workflows create revisioned drafts, never apply live changes."""

import ipaddress
from typing import Annotated, Any
from uuid import UUID

from pydantic import Field, SecretStr, field_validator

from app.firewall import Conflict, FirewallService
from app.ipv4 import endpoint_host as validate_endpoint_host
from app.ipv4 import ipv4, subnet
from app.link_models import (
    LinkModel,
    WireGuardInterface,
    WireGuardServerAccess,
    interface_name,
    planned_interface_names,
)
from app.models import Configuration, FilterRule, NatRule
from app.network_models import IpAddress
from app.wireguard_keys import KeyKind, public_key
from app.wireguard_models import WireGuardPeer
from app.wireguard_profiles import export_client, export_interface, parse_profile, qr_profile
from app.wireguard_vault import WireGuardVault

Prefixes = list[Annotated[str, Field(max_length=18)]]
DnsServers = list[Annotated[str, Field(max_length=15)]]


class KeyCreate(LinkModel):
    kind: KeyKind = "interface"
    value: SecretStr | None = None


class ServerSetup(LinkModel):
    revision: int = Field(ge=0)
    name: str = Field(default="wg-server", min_length=1, max_length=13)
    address: str = Field(default="10.77.0.1/24", max_length=18)
    listen_port: int = Field(default=51820, ge=1, le=65535)
    endpoint: str = Field(default="", max_length=253)
    mtu: int = Field(default=1420, ge=576, le=9000)
    dns: DnsServers = Field(default_factory=list, max_length=8)
    access_networks: Prefixes = Field(default_factory=list, max_length=16)
    wan_interface: str = Field(default="", max_length=15)
    internet_access: bool = False
    router_access: bool = False

    _name = field_validator("name")(interface_name)
    _endpoint = field_validator("endpoint")(validate_endpoint_host)
    _dns = field_validator("dns")(lambda values: list(dict.fromkeys(ipv4(v) for v in values)))
    _networks = field_validator("access_networks")(
        lambda values: list(dict.fromkeys(subnet(v) for v in values))
    )
    _wan = field_validator("wan_interface")(lambda value: interface_name(value) if value else "")

    @field_validator("address")
    @classmethod
    def validate_server_address(cls, value: str) -> str:
        address = IpAddress(interface="wg", address=value).address
        if not 8 <= ipaddress.IPv4Interface(address).network.prefixlen <= 30:
            raise ValueError("The server wizard needs an IPv4 subnet between /8 and /30")
        return address


class ClientImport(LinkModel):
    revision: int = Field(ge=0)
    name: str = Field(default="wg-client", min_length=1, max_length=13)
    profile: SecretStr
    route_sources: Prefixes = Field(default_factory=list, max_length=32)
    kill_switch: bool = True
    masquerade: bool = True

    _name = field_validator("name")(interface_name)
    _sources = field_validator("route_sources")(
        lambda values: list(dict.fromkeys(subnet(v) for v in values))
    )


class ServerAccessUpdate(LinkModel):
    revision: int = Field(ge=0)
    interface: str = Field(min_length=1, max_length=13)
    policy: WireGuardServerAccess

    _interface = field_validator("interface")(interface_name)


class PeerCreate(LinkModel):
    revision: int = Field(ge=0)
    interface: str = Field(min_length=1, max_length=13)
    name: str = Field(min_length=1, max_length=64)
    public_key: str = Field(default="", max_length=44)
    address: str = Field(default="", max_length=18)
    allowed_ips: Prefixes = Field(default_factory=list, max_length=128)
    client_allowed_ips: Prefixes = Field(default_factory=list, max_length=128)
    client_dns: DnsServers = Field(default_factory=list, max_length=8)
    endpoint_host: str = Field(default="", max_length=253)
    endpoint_port: int = Field(default=51820, ge=1, le=65535)
    keepalive: int = Field(default=0, ge=0, le=65535)
    preshared: bool = True
    preshared_key: SecretStr | None = None

    _interface = field_validator("interface")(interface_name)
    _key = field_validator("public_key")(lambda value: public_key(value) if value else "")
    _address = field_validator("address")(
        lambda value: WireGuardPeer.validate_client_address(value) if value else ""
    )
    _networks = field_validator("allowed_ips", "client_allowed_ips")(
        lambda values: list(dict.fromkeys(subnet(v) for v in values))
    )
    _dns = field_validator("client_dns")(
        lambda values: list(dict.fromkeys(ipv4(v) for v in values))
    )
    _endpoint = field_validator("endpoint_host")(validate_endpoint_host)


def _validated(config: Configuration) -> Configuration:
    # model_copy and list mutation deliberately do not validate intermediate states.
    return Configuration.model_validate(config.model_dump(mode="python"))


class WireGuardService:
    def __init__(self, firewall: FirewallService, vault: WireGuardVault) -> None:
        self.firewall, self.vault = firewall, vault

    @staticmethod
    def table(config: Configuration) -> int:
        occupied = {item.routing_table for item in config.network.wireguard_interfaces}
        return next(table for table in range(20000, 21000) if table not in occupied)

    def check_addresses(self, config: Configuration, name: str, addresses: list[str]) -> None:
        if name in planned_interface_names(config.network):
            raise Conflict("This managed interface name already exists")
        existing = [item.address for item in config.network.addresses if item.enabled]
        if self.firewall.runtime:
            existing.extend(
                row["address"]
                for row in self.firewall.runtime.network.status().get("addresses", [])
            )
        for value in addresses:
            proposed = ipaddress.IPv4Interface(value).network
            if any(
                proposed.overlaps(ipaddress.IPv4Interface(current).network) for current in existing
            ):
                raise Conflict(
                    "The VPN address/subnet overlaps an existing router network; "
                    "choose another subnet"
                )

    def server(self, body: ServerSetup) -> dict[str, Any]:
        with self.firewall.lock:
            self.firewall.check_revision(body.revision)
            if body.internet_access and not body.wan_interface:
                raise Conflict("Choose an explicit WAN interface for VPN internet access")
            config = self.firewall.config().model_copy(deep=True)
            self.check_addresses(config, body.name, [body.address])
            key = self.vault.create("interface")
            interface = WireGuardInterface(
                name=body.name,
                private_key_id=key.id,
                public_key=key.public_key,
                listen_port=body.listen_port,
                mtu=body.mtu,
                role="server",
                client_dns=body.dns,
                export_endpoint=body.endpoint,
                routing_table=self.table(config),
                server_access=WireGuardServerAccess(
                    source_network=str(ipaddress.IPv4Interface(body.address).network),
                    access_networks=body.access_networks,
                    router_access=body.router_access,
                    wan_interface=body.wan_interface if body.internet_access else "",
                ),
                client_allowed_ips=["0.0.0.0/0"]
                if body.internet_access
                else list(
                    dict.fromkeys(
                        [
                            str(ipaddress.IPv4Interface(body.address).network),
                            *body.access_networks,
                        ]
                    )
                ),
            )
            config.network.wireguard_interfaces.append(interface)
            config.network.addresses.append(IpAddress(interface=body.name, address=body.address))
            vpn = str(ipaddress.IPv4Interface(body.address).network)
            rules = [
                FilterRule(
                    name=f"{body.name}: WireGuard UDP",
                    chain="input",
                    protocol="udp",
                    dst_ports=str(body.listen_port),
                    in_interface=body.wan_interface,
                    comment="WireGuard setup: encrypted transport",
                )
            ]
            for destination in body.access_networks:
                if destination == "0.0.0.0/0":
                    raise Conflict("Use the Internet access option for a default route")
                rules.append(
                    FilterRule(
                        name=f"{body.name}: VPN to {destination}",
                        chain="forward",
                        protocol="any",
                        in_interface=body.name,
                        src_address=vpn,
                        dst_address=destination,
                    )
                )
            if body.internet_access:
                rules.append(
                    FilterRule(
                        name=f"{body.name}: VPN to WAN",
                        chain="forward",
                        protocol="any",
                        in_interface=body.name,
                        out_interface=body.wan_interface,
                        src_address=vpn,
                    )
                )
                config.rules.insert(
                    0,
                    NatRule(
                        name=f"{body.name}: VPN internet",
                        chain="srcnat",
                        action="masquerade",
                        protocol="any",
                        src_address=vpn,
                        out_interface=body.wan_interface,
                    ),
                )
            if body.access_networks or body.internet_access:
                rules.append(
                    FilterRule(
                        name=f"{body.name}: VPN replies",
                        chain="forward",
                        protocol="any",
                        out_interface=body.name,
                        dst_address=vpn,
                        connection_states=["ESTABLISHED", "RELATED"],
                    )
                )
                config.network.forwarding = True
            if body.router_access:
                rules.append(
                    FilterRule(
                        name=f"{body.name}: VPN to router",
                        chain="input",
                        protocol="any",
                        in_interface=body.name,
                        src_address=vpn,
                    )
                )
            config.filter_rules[0:0] = rules
            return self.firewall.save(_validated(config), body.revision)

    def server_access(self, body: ServerAccessUpdate) -> dict[str, Any]:
        """Opt a legacy server into an explicit policy through the normal draft transaction."""
        with self.firewall.lock:
            self.firewall.check_revision(body.revision)
            config = self.firewall.config().model_copy(deep=True)
            interface = next(
                (
                    item
                    for item in config.network.wireguard_interfaces
                    if item.name == body.interface
                ),
                None,
            )
            if interface is None or interface.role != "server":
                raise Conflict("Choose an existing WireGuard server interface")
            interface.server_access = body.policy
            return self.firewall.save(_validated(config), body.revision)

    def import_client(self, body: ClientImport) -> dict[str, Any]:
        with self.firewall.lock:
            self.firewall.check_revision(body.revision)
            profile = parse_profile(body.profile)
            if not profile.addresses:
                raise Conflict("Client import needs at least one IPv4 Address in the profile")
            config = self.firewall.config().model_copy(deep=True)
            self.check_addresses(config, body.name, profile.addresses)
            key = self.vault.create("interface", profile.private_key)
            config.network.wireguard_interfaces.append(
                WireGuardInterface(
                    name=body.name,
                    private_key_id=key.id,
                    public_key=key.public_key,
                    listen_port=profile.listen_port,
                    mtu=profile.mtu,
                    role="client",
                    client_dns=profile.dns,
                    route_sources=body.route_sources,
                    route_allowed_ips=bool(body.route_sources),
                    routing_table=self.table(config),
                    kill_switch=body.kill_switch,
                )
            )
            config.network.addresses.extend(
                IpAddress(interface=body.name, address=address) for address in profile.addresses
            )
            for index, imported in enumerate(profile.peers, 1):
                psk = (
                    self.vault.create("preshared", imported.preshared_key)
                    if imported.preshared_key
                    else None
                )
                config.network.wireguard_peers.append(
                    WireGuardPeer(
                        name=f"{body.name}-peer-{index}",
                        interface=body.name,
                        public_key=imported.public_key,
                        allowed_ips=imported.allowed_ips,
                        endpoint_host=imported.endpoint_host,
                        endpoint_port=imported.endpoint_port,
                        persistent_keepalive=imported.persistent_keepalive,
                        preshared_key_id=psk.id if psk else None,
                    )
                )
            if body.route_sources:
                config.network.forwarding = True
                rules = [
                    FilterRule(
                        name=f"{body.name}: tunnel replies",
                        chain="forward",
                        protocol="any",
                        in_interface=body.name,
                        connection_states=["ESTABLISHED", "RELATED"],
                    )
                ]
                for source in body.route_sources:
                    rules.append(
                        FilterRule(
                            name=f"{body.name}: {source} to VPN",
                            chain="forward",
                            protocol="any",
                            src_address=source,
                            out_interface=body.name,
                        )
                    )
                    if body.masquerade:
                        config.rules.insert(
                            0,
                            NatRule(
                                name=f"{body.name}: VPN masquerade",
                                chain="srcnat",
                                action="masquerade",
                                protocol="any",
                                src_address=source,
                                out_interface=body.name,
                            ),
                        )
                config.filter_rules[0:0] = rules
            return self.firewall.save(_validated(config), body.revision)

    @staticmethod
    def next_address(config: Configuration, interface: str) -> str:
        local = next(
            (
                ipaddress.IPv4Interface(item.address)
                for item in config.network.addresses
                if item.interface == interface and item.enabled
            ),
            None,
        )
        if local is None or local.network.prefixlen > 30:
            raise Conflict("Assign a VPN subnet (/30 or larger) to this interface first")
        occupied = [
            ipaddress.IPv4Network(prefix)
            for peer in config.network.wireguard_peers
            if peer.interface == interface
            for prefix in peer.allowed_ips
        ]
        for index, address in enumerate(local.network.hosts()):
            if index >= 65536:
                break
            if address != local.ip and not any(address in net for net in occupied):
                return f"{address}/32"
        raise Conflict("No free client address found; enter an explicit IPv4 address")

    def peer(self, body: PeerCreate) -> dict[str, Any]:
        with self.firewall.lock:
            self.firewall.check_revision(body.revision)
            config = self.firewall.config().model_copy(deep=True)
            interface = next(
                (
                    item
                    for item in config.network.wireguard_interfaces
                    if item.name == body.interface
                ),
                None,
            )
            if interface is None:
                raise Conflict("Choose an existing WireGuard interface")
            generated = self.vault.create("peer-client") if not body.public_key else None
            address = body.address or (
                self.next_address(config, body.interface) if generated else ""
            )
            allowed = body.allowed_ips or (
                [str(ipaddress.IPv4Interface(address).ip) + "/32"] if address else []
            )
            if not allowed:
                raise Conflict("Enter this peer's allowed IPv4 addresses or networks")
            if generated and not address:
                raise Conflict("Generated client profiles require a client address")
            if generated:
                client_ip = ipaddress.IPv4Interface(address).ip
                local = [
                    ipaddress.IPv4Interface(item.address)
                    for item in config.network.addresses
                    if item.interface == interface.name and item.enabled
                ]
                if not any(
                    client_ip in item.network
                    and client_ip
                    not in (item.network.network_address, item.network.broadcast_address, item.ip)
                    for item in local
                ):
                    raise Conflict(
                        "Choose a usable client address in this WireGuard interface's VPN subnet"
                    )
                if any(
                    client_ip == ipaddress.IPv4Interface(item.address).ip
                    for item in config.network.addresses
                    if item.enabled
                ):
                    raise Conflict("A client cannot use an IPv4 address assigned to the router")
            # A generated client is one device; routed site-to-site peers use external keys.
            if generated and str(ipaddress.IPv4Interface(address).ip) + "/32" not in allowed:
                raise Conflict("Allowed IPs must include the generated client's /32 address")
            psk = (
                self.vault.create("preshared", body.preshared_key)
                if body.preshared_key or body.preshared and generated
                else None
            )
            config.network.wireguard_peers.append(
                WireGuardPeer(
                    name=body.name,
                    interface=body.interface,
                    public_key=generated.public_key if generated else body.public_key,
                    allowed_ips=allowed,
                    endpoint_host=body.endpoint_host,
                    endpoint_port=body.endpoint_port,
                    persistent_keepalive=body.keepalive,
                    preshared_key_id=psk.id if psk else None,
                    client_private_key_id=generated.id if generated else None,
                    client_address=address,
                    client_dns=body.client_dns or interface.client_dns,
                    client_allowed_ips=body.client_allowed_ips
                    or interface.client_allowed_ips
                    or [
                        str(ipaddress.IPv4Interface(item.address).network)
                        for item in config.network.addresses
                        if item.interface == interface.name and item.enabled
                    ],
                )
            )
            return self.firewall.save(_validated(config), body.revision)

    def export(self, object_id: UUID, client: bool, endpoint: str = "") -> dict[str, str]:
        with self.firewall.lock:
            config = self.firewall.config().network
            if client:
                peer = next((item for item in config.wireguard_peers if item.id == object_id), None)
                if peer is None:
                    raise Conflict("WireGuard peer not found")
                interface = next(
                    item for item in config.wireguard_interfaces if item.name == peer.interface
                )
                profile = export_client(interface, peer, self.vault, endpoint)
                filename = f"{interface.name}-{peer.id.hex[:8]}.conf"
            else:
                selected = next(
                    (item for item in config.wireguard_interfaces if item.id == object_id), None
                )
                if selected is None:
                    raise Conflict("WireGuard interface not found")
                interface = selected
                profile = export_interface(
                    interface, config.wireguard_peers, config.addresses, self.vault
                )
                filename = f"{interface.name}.conf"
            return {
                "configuration": profile,
                "qr_data_url": qr_profile(profile),
                "filename": filename,
            }
