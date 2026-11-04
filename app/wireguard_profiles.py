"""Bounded wg/wg-quick profiles without hooks, scripts or implicit host changes."""

import base64
import io
import ipaddress
from dataclasses import dataclass, field

import qrcode  # type: ignore[import-untyped]
import qrcode.image.svg  # type: ignore[import-untyped]
from pydantic import SecretStr
from qrcode.exceptions import DataOverflowError  # type: ignore[import-untyped]

from app.ipv4 import endpoint_host, ipv4, subnet
from app.link_models import WireGuardInterface
from app.network_models import IpAddress
from app.wireguard_keys import key_bytes, public_key
from app.wireguard_models import WireGuardPeer
from app.wireguard_vault import WireGuardVault

MAX_PROFILE_BYTES = 65536
MAX_PROFILE_LINES = 4096
INTERFACE_FIELDS = {"privatekey", "address", "listenport", "mtu", "dns", "table"}
PEER_FIELDS = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}


@dataclass
class ImportedPeer:
    public_key: str
    allowed_ips: list[str]
    preshared_key: SecretStr | None = field(default=None, repr=False)
    endpoint_host: str = ""
    endpoint_port: int = 51820
    persistent_keepalive: int = 0


@dataclass
class ImportedProfile:
    private_key: SecretStr = field(repr=False)
    addresses: list[str]
    peers: list[ImportedPeer]
    listen_port: int = 0
    mtu: int = 1420
    dns: list[str] = field(default_factory=list)
    automatic_routes: bool = True


def _number(value: str, name: str, minimum: int, maximum: int) -> int:
    if not value.isascii() or not value.isdecimal() or not minimum <= int(value) <= maximum:
        raise ValueError(f"Invalid WireGuard {name}")
    return int(value)


def _list(value: str, maximum: int) -> list[str]:
    result = [part.strip() for part in value.split(",")]
    if not result or any(not part for part in result) or len(result) > maximum:
        raise ValueError("Invalid or oversized WireGuard address list")
    if any(":" in part for part in result):
        raise ValueError("This release supports IPv4 only; remove IPv6 entries from the profile")
    return result


def _address(value: str) -> str:
    try:
        address = ipaddress.IPv4Interface(value)
        ipv4(str(address.ip))
    except ValueError as exc:
        raise ValueError("WireGuard Address must contain IPv4 addresses with prefixes") from exc
    return str(address)


def parse_profile(value: SecretStr) -> ImportedProfile:
    text = value.get_secret_value()
    if len(text.encode()) > MAX_PROFILE_BYTES or len(text.splitlines()) > MAX_PROFILE_LINES:
        raise ValueError("WireGuard profile exceeds its size limit")
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    section: dict[str, str] | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower() == "[interface]":
            if section is not None:
                raise ValueError("A WireGuard profile must have one Interface section first")
            section = interface
            continue
        if line.lower() == "[peer]":
            if section is None or len(peers) >= 128:
                raise ValueError("WireGuard peers need an Interface section and a maximum of 128")
            section = {}
            peers.append(section)
            continue
        if section is None or "=" not in line:
            raise ValueError(f"Invalid WireGuard syntax at line {line_number}")
        name, data = (part.strip() for part in line.split("=", 1))
        name = name.lower()
        allowed = INTERFACE_FIELDS if section is interface else PEER_FIELDS
        if name not in allowed:
            raise ValueError(
                f"Unsupported WireGuard option at line {line_number}; "
                "hooks and commands are not imported"
            )
        if name in section or not data or len(data) > 4096:
            raise ValueError(
                f"Duplicate, empty or oversized WireGuard option at line {line_number}"
            )
        section[name] = data
    if not interface.get("privatekey") or not peers:
        raise ValueError("WireGuard import needs a private key and at least one peer")
    key_bytes(interface["privatekey"])
    addresses = (
        [_address(part) for part in _list(interface["address"], 32)]
        if "address" in interface
        else []
    )
    table = interface.get("table", "auto").lower()
    if table not in ("auto", "off"):
        raise ValueError("Custom Table values are not imported; choose routing in OpenMikroRout")
    result = ImportedProfile(
        private_key=SecretStr(interface["privatekey"]),
        addresses=addresses,
        peers=[],
        listen_port=_number(interface.get("listenport", "0"), "ListenPort", 0, 65535),
        mtu=_number(interface.get("mtu", "1420"), "MTU", 576, 9000),
        dns=[ipv4(part) for part in _list(interface["dns"], 8)] if "dns" in interface else [],
        automatic_routes=table == "auto",
    )
    for raw in peers:
        if not raw.get("publickey") or not raw.get("allowedips"):
            raise ValueError("Each imported peer needs PublicKey and AllowedIPs")
        peer = ImportedPeer(
            public_key=public_key(raw["publickey"]),
            allowed_ips=list(dict.fromkeys(subnet(part) for part in _list(raw["allowedips"], 128))),
            persistent_keepalive=_number(
                raw.get("persistentkeepalive", "0"), "PersistentKeepalive", 0, 65535
            ),
        )
        if "presharedkey" in raw:
            key_bytes(raw["presharedkey"])
            peer.preshared_key = SecretStr(raw["presharedkey"])
        if "endpoint" in raw:
            parts = raw["endpoint"].rsplit(":", 1)
            if len(parts) != 2 or ":" in parts[0]:
                raise ValueError(
                    "Endpoint must be an IPv4 address or DNS hostname followed by :port"
                )
            peer.endpoint_host = endpoint_host(parts[0])
            peer.endpoint_port = _number(parts[1], "Endpoint port", 1, 65535)
            if not peer.endpoint_host:
                raise ValueError("WireGuard endpoint hostname cannot be empty")
        result.peers.append(peer)
    return result


def qr_profile(profile: str) -> str:
    try:
        image = qrcode.make(profile, image_factory=qrcode.image.svg.SvgPathImage)
    except DataOverflowError:
        return ""
    stream = io.BytesIO()
    image.save(stream)
    return "data:image/svg+xml;base64," + base64.b64encode(stream.getvalue()).decode()


def kernel_profile(
    interface: WireGuardInterface,
    peers: list[WireGuardPeer],
    vault: WireGuardVault,
    endpoints: dict[str, str],
    *,
    fwmark: int = 0,
) -> str:
    lines = [
        "[Interface]",
        "PrivateKey = " + vault.secret(interface.private_key_id, "interface"),
        f"ListenPort = {interface.listen_port}",
        f"FwMark = {fwmark}",
    ]
    for peer in peers:
        if not peer.enabled or peer.interface != interface.name:
            continue
        lines += ["", "[Peer]", f"PublicKey = {peer.public_key}"]
        if peer.preshared_key_id:
            lines.append("PresharedKey = " + vault.secret(peer.preshared_key_id, "preshared"))
        lines.append("AllowedIPs = " + ", ".join(peer.allowed_ips))
        lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
        if peer.endpoint_host:
            lines.append(f"Endpoint = {endpoints[peer.endpoint_host]}:{peer.endpoint_port}")
    return "\n".join(lines) + "\n"


def export_interface(
    interface: WireGuardInterface,
    peers: list[WireGuardPeer],
    addresses: list[IpAddress],
    vault: WireGuardVault,
) -> str:
    lines = [
        "# Router routes and firewall rules are managed separately.",
        "[Interface]",
        "PrivateKey = " + vault.secret(interface.private_key_id, "interface"),
        f"ListenPort = {interface.listen_port}",
        f"MTU = {interface.mtu}",
        "Table = off",
    ]
    local_addresses = [
        item.address for item in addresses if item.interface == interface.name and item.enabled
    ]
    if local_addresses:
        lines.append("Address = " + ", ".join(local_addresses))
    if interface.client_dns:
        lines.append("DNS = " + ", ".join(interface.client_dns))
    for peer in peers:
        if not peer.enabled or peer.interface != interface.name:
            continue
        lines += ["", "[Peer]", f"PublicKey = {peer.public_key}"]
        if peer.preshared_key_id:
            lines.append("PresharedKey = " + vault.secret(peer.preshared_key_id, "preshared"))
        lines.append("AllowedIPs = " + ", ".join(peer.allowed_ips))
        if peer.endpoint_host:
            lines.append(f"Endpoint = {peer.endpoint_host}:{peer.endpoint_port}")
        lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
    return "\n".join(lines) + "\n"


def export_client(
    interface: WireGuardInterface, peer: WireGuardPeer, vault: WireGuardVault, endpoint: str = ""
) -> str:
    if not peer.client_private_key_id or not peer.client_address or not peer.client_allowed_ips:
        raise ValueError(
            "This peer has no generated client profile; its private key stays on its device"
        )
    host = endpoint_host(endpoint or interface.export_endpoint)
    if not host or not interface.listen_port:
        raise ValueError(
            "Set the server's public endpoint and a fixed listen port before exporting"
        )
    if vault.metadata(peer.client_private_key_id, "peer-client").public_key != peer.public_key:
        raise ValueError("Client private key does not match this peer")
    lines = [
        "[Interface]",
        "PrivateKey = " + vault.secret(peer.client_private_key_id, "peer-client"),
        f"Address = {peer.client_address}",
        f"MTU = {interface.mtu}",
    ]
    if peer.client_dns:
        lines.append("DNS = " + ", ".join(peer.client_dns))
    lines += ["", "[Peer]", f"PublicKey = {interface.public_key}"]
    if peer.preshared_key_id:
        lines.append("PresharedKey = " + vault.secret(peer.preshared_key_id, "preshared"))
    lines += [
        f"Endpoint = {host}:{interface.listen_port}",
        "AllowedIPs = " + ", ".join(peer.client_allowed_ips),
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"
