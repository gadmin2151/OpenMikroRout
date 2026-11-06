"""Bounded decoders for untrusted neighbor advertisements; never execute their text."""

import ipaddress
import json
import struct
from typing import Any

from app.link_models import interface_name
from app.telemetry import valid_address, valid_mac

MAX_NEIGHBORS = 4096
MAX_MESSAGE = 16384


def clean_text(value: object, limit: int = 253) -> str:
    return "".join(char for char in str(value) if char.isprintable())[:limit]


def parse_mndp(data: bytes, interface: str, sender: str) -> dict[str, Any] | None:
    """MNDP's four-byte header and bounded network-order TLVs (uptime is LE)."""
    interface_name(interface)
    if not 8 <= len(data) <= MAX_MESSAGE:
        return None
    fields: dict[str, Any] = {}
    addresses: set[str] = set()
    names = {5: "hostname", 7: "version", 8: "platform", 12: "model", 16: "remote_port"}
    cursor, count = 4, 0
    while cursor < len(data):
        if len(data) - cursor < 4 or count >= 64:
            return None
        kind, size = struct.unpack_from("!HH", data, cursor)
        cursor += 4
        if size > len(data) - cursor:
            return None
        value = data[cursor : cursor + size]
        cursor += size
        count += 1
        if kind == 1 and size == 6:
            fields["mac"] = valid_mac(value.hex(":")) or ""
        elif kind == 17 and size == 4:
            if address := valid_address(str(ipaddress.IPv4Address(value))):
                addresses.add(address)
        elif kind == 10 and size == 4:
            fields["uptime_seconds"] = int.from_bytes(value, "little")
        elif kind in names:
            fields[names[kind]] = clean_text(value.decode("utf-8", errors="replace"))
    if not fields.get("mac"):
        return None
    if address := valid_address(sender):
        addresses.add(address)
    return {"interface": interface, "source": "mndp", "addresses": sorted(addresses), **fields}


def _rows(value: object) -> list[dict[str, Any]]:
    return (
        [row for row in value[:MAX_NEIGHBORS] if isinstance(row, dict)]
        if isinstance(value, list)
        else []
    )


def _value(value: object) -> str:
    rows = _rows(value)
    return clean_text(rows[0].get("value", "")) if rows else ""


def parse_lldp(text: str, interfaces: set[str]) -> list[dict[str, Any]]:
    """Decode lldpcli's stable json0 format; retains source and local segment."""
    if len(text) > 4 * 1024 * 1024:
        raise ValueError("Neighbor output exceeds its limit")
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid LLDP/CDP response") from exc
    if not isinstance(document, dict):
        raise ValueError("Invalid LLDP/CDP response")
    result: list[dict[str, Any]] = []
    for group in _rows(document.get("lldp")):
        for item in _rows(group.get("interface")):
            interface = item.get("name")
            source = str(item.get("via", "LLDP")).lower()
            if (
                not isinstance(interface, str)
                or interface not in interfaces
                or source not in ("lldp", "cdp")
            ):
                continue
            chassis_rows = _rows(item.get("chassis"))
            port_rows = _rows(item.get("port"))
            if not chassis_rows:
                continue
            chassis = chassis_rows[0]
            port = port_rows[0] if port_rows else {}
            ident = _value(chassis.get("id"))
            mac = valid_mac(ident) or ""
            addresses = [
                address
                for row in _rows(chassis.get("mgmt-ip"))
                if (address := valid_address(str(row.get("value", ""))))
            ]
            if not ident and not addresses:
                continue
            capabilities = [
                clean_text(row.get("type", ""), 64)
                for row in _rows(chassis.get("capability"))[:32]
                if row.get("enabled") is True
            ]
            try:
                ttl = min(86400, max(1, int(_value(port.get("ttl")) or "120")))
            except ValueError:
                ttl = 120
            result.append(
                {
                    "interface": interface,
                    "source": source,
                    "mac": mac,
                    "addresses": sorted(set(addresses)),
                    "hostname": _value(chassis.get("name")),
                    "description": _value(chassis.get("descr")),
                    "chassis_id": ident,
                    "remote_port": _value(port.get("id")),
                    "port_description": _value(port.get("descr")),
                    "capabilities": capabilities,
                    "ttl": ttl,
                }
            )
            if len(result) >= MAX_NEIGHBORS:
                return result
    return result


def parse_arp(text: str, interfaces: set[str]) -> list[dict[str, Any]]:
    if len(text) > 4 * 1024 * 1024:
        raise ValueError("ARP output exceeds its limit")
    try:
        rows = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid ARP response") from exc
    result = []
    for row in _rows(rows):
        interface = row.get("dev")
        state = row.get("state", [])
        if isinstance(state, str):
            state = state.split(",")
        if (
            not isinstance(interface, str)
            or interface not in interfaces
            or not isinstance(state, list)
        ):
            continue
        if any(value in ("FAILED", "INCOMPLETE", "NONE") for value in state):
            continue
        mac, address = valid_mac(str(row.get("lladdr", ""))), valid_address(str(row.get("dst", "")))
        if mac and address:
            result.append(
                {"interface": interface, "source": "arp", "mac": mac, "addresses": [address]}
            )
    return result
