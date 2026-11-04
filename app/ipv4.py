"""Literal IPv4 and DNS values shared by router configuration models."""

import ipaddress
import re


def ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address") from exc
    if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
        raise ValueError("Use a unicast IPv4 address")
    return str(address)


def subnet(value: str) -> str:
    try:
        return str(ipaddress.IPv4Network(value, strict=False))
    except ValueError as exc:
        raise ValueError("Enter an IPv4 subnet, e.g. 192.168.10.0/24") from exc


def domain_name(value: str) -> str:
    value = value.rstrip(".").lower()
    if (
        not value
        or len(value) > 253
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in value.split(".")
        )
    ):
        raise ValueError("Enter a DNS hostname, e.g. vpn.example.com")
    return value


def endpoint_host(value: str) -> str:
    if not value:
        return ""
    if re.fullmatch(r"[0-9.]+", value):
        return ipv4(value)
    return domain_name(value)
