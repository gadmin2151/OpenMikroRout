"""RFC 6238 codes and authenticated encryption for per-user authenticator keys."""

import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import struct
from pathlib import Path
from urllib.parse import quote, urlencode

import qrcode  # type: ignore[import-untyped]
import qrcode.image.svg  # type: ignore[import-untyped]
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, SecretStr

STEP_SECONDS = 30
ENROLLMENT_SECONDS = 600
RECOVERY_COUNT = 8


class CredentialProof(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=1, max_length=512)
    code: SecretStr = Field(default_factory=lambda: SecretStr(""), max_length=64)


class TotpStatus(BaseModel):
    enabled: bool
    recovery_codes_remaining: int


class TotpEnrollment(BaseModel):
    secret: str = Field(repr=False)
    provisioning_uri: str = Field(repr=False)
    qr_data_url: str = Field(repr=False)
    expires_at: float


class TotpRecovery(BaseModel):
    enabled: bool = True
    recovery_codes: list[str] = Field(repr=False)


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code_at(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=False)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFF_FFFF
    return str(value % (10**digits)).zfill(digits)


def matching_counter(secret: str, code: str, now: float, last: int = -1) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int(now // STEP_SECONDS)
    for counter in (current, current - 1, current + 1):
        if counter >= 0 and counter > last and hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None


def recovery_digest(user_id: str, code: str) -> str:
    normalized = code.replace("-", "").replace(" ", "").lower()
    return hashlib.sha256((user_id + ":" + normalized).encode()).hexdigest()


def new_recovery_codes() -> list[str]:
    result = []
    for _ in range(RECOVERY_COUNT):
        raw = secrets.token_hex(16)
        result.append("-".join(raw[index : index + 8] for index in range(0, 32, 8)))
    return result


def enrollment(secret: str, username: str, expires_at: float) -> TotpEnrollment:
    issuer = "OpenMikroRout"
    uri = (
        "otpauth://totp/"
        + quote(issuer + ":" + username, safe="")
        + "?"
        + urlencode(
            {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": 6, "period": 30}
        )
    )
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, border=4)
    output = io.BytesIO()
    image.save(output)
    data_url = "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()
    return TotpEnrollment(
        secret=secret, provisioning_uri=uri, qr_data_url=data_url, expires_at=expires_at
    )


class TotpVault:
    def __init__(self, path: Path, *, required: bool = False) -> None:
        if not path.exists() and required:
            raise RuntimeError("TOTP encryption key is missing; restore it from the private backup")
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(AESGCM.generate_key(bit_length=256))
                stream.flush()
                os.fsync(stream.fileno())
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise RuntimeError("TOTP encryption key must be a private regular file (0600)")
        key = path.read_bytes()
        if len(key) != 32:
            raise RuntimeError("Invalid TOTP encryption key; restore the private backup")
        self.cipher = AESGCM(key)

    def encrypt(self, user_id: str, purpose: str, secret: str) -> str:
        nonce = secrets.token_bytes(12)
        payload = self.cipher.encrypt(nonce, secret.encode(), (user_id + ":" + purpose).encode())
        return base64.b64encode(nonce + payload).decode()

    def decrypt(self, user_id: str, purpose: str, encoded: str) -> str:
        try:
            raw = base64.b64decode(encoded, validate=True)
            return self.cipher.decrypt(
                raw[:12], raw[12:], (user_id + ":" + purpose).encode()
            ).decode()
        except (ValueError, InvalidTag, UnicodeError) as exc:
            raise RuntimeError(
                "Cannot decrypt authenticator settings; restore the private backup"
            ) from exc
