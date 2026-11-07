"""Cross-revision constraints for deleting app-created network interfaces."""

from app.models import Configuration


def link_names(config: Configuration) -> set[str]:
    return {
        item.name
        for item in (
            *config.network.bridges,
            *config.network.vlans,
            *config.network.virtual_interfaces,
            *config.network.wireguard_interfaces,
        )
    }


def interface_references(config: Configuration, name: str) -> list[str]:
    references: list[str] = []
    network = config.network
    for peer in network.wireguard_peers:
        if peer.interface == name:
            references.append(f"WireGuard peer {peer.name}")
    for interface in network.wireguard_interfaces:
        if interface.server_access and interface.server_access.wan_interface == name:
            references.append(f"WireGuard server access {interface.name}")
    for address in network.addresses:
        if address.interface == name:
            references.append(f"IP address {address.address}")
    for route in network.routes:
        if route.interface == name:
            references.append(f"route {route.destination}")
    for server in network.dhcp_servers:
        if server.interface == name:
            references.append(f"DHCP server {server.name}")
    if name in network.dns.listen_interfaces:
        references.append("DNS listener")
    for bridge in network.bridges:
        if name in bridge.members:
            references.append(f"bridge {bridge.name}")
    for vlan in network.vlans:
        if vlan.parent == name:
            references.append(f"VLAN {vlan.name}")
    for interface_list in network.interface_lists:
        if name in interface_list.members:
            references.append(f"interface list {interface_list.name}")
    for rule in (*config.rules, *config.filter_rules):
        if rule.in_interface == name or rule.out_interface == name:
            references.append(f"firewall rule {rule.name}")
    return references


def validate_link_removals(previous: Configuration, target: Configuration) -> None:
    for name in sorted(link_names(previous) - link_names(target)):
        references = interface_references(target, name)
        if references:
            raise ValueError(
                f"Cannot delete managed interface '{name}': still referenced by "
                + ", ".join(references[:5])
                + ". Remove or reassign these settings first."
            )
