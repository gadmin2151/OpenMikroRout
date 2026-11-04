"""Canonical WireGuard keys; private material never belongs in router configuration."""

import base64
import secrets
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

KeyKind = Literal["interface", "peer-client", "preshared"]


def key_bytes(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Enter a base64 WireGuard key containing 32 bytes") from exc
    if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != value:
        raise ValueError("Enter a canonical, nonzero 32-byte WireGuard key")
    return raw


def public_key(value: str) -> str:
    key_bytes(value)
    return value


def generate_key(kind: KeyKind) -> tuple[str, str]:
    if kind == "preshared":
        return base64.b64encode(secrets.token_bytes(32)).decode(), ""
    key = X25519PrivateKey.generate()
    return (
        base64.b64encode(key.private_bytes_raw()).decode(),
        base64.b64encode(key.public_key().public_bytes_raw()).decode(),
    )


def derive_public(value: str) -> str:
    return base64.b64encode(
        X25519PrivateKey.from_private_bytes(key_bytes(value)).public_key().public_bytes_raw()
    ).decode()
