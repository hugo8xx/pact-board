"""The board's Ed25519 signing keys: one active key signs, older keys keep verifying.

Mandates used to carry an HMAC under ``PACT_SIGNING_KEY``, which only the board could check.
An Ed25519 signature can be checked by anyone holding the public key, which the board publishes
at ``/.well-known/pact-keys.json``: that is what lets a credential exported from the ledger be
verified elsewhere.

``PACT_BOARD_KEYS`` holds the keyring as ``kid=<base64url 32-byte seed>`` entries separated by
commas, newest first. The first entry signs; every entry verifies, so rotating is: put a new key
first, keep the old one until the mandates it signed have expired, then drop it. Without
``PACT_BOARD_KEYS`` the board derives one key from ``PACT_SIGNING_KEY`` (kid ``derived-1``), so an
existing deployment keeps working with no new secret.
"""

import base64
import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .crypto import signing_key

PREFIX = "ed25519"
DERIVED_KID = "derived-1"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class Keyring:
    """``keys`` maps kid to private key; ``active`` is the kid that signs."""

    keys: dict[str, Ed25519PrivateKey]
    active: str

    def sign(self, payload: str) -> str:
        """``ed25519:<kid>:<base64url signature>`` over the payload's UTF-8 bytes."""
        signature = self.keys[self.active].sign(payload.encode())
        return f"{PREFIX}:{self.active}:{b64url(signature)}"

    def verify(self, payload: str, signature: str) -> bool:
        parts = signature.split(":")
        if len(parts) != 3 or parts[0] != PREFIX or parts[1] not in self.keys:
            return False
        try:
            self.keys[parts[1]].public_key().verify(b64url_decode(parts[2]), payload.encode())
        except (InvalidSignature, ValueError):
            return False
        return True

    def jwks(self) -> dict[str, Any]:
        """The public half of every key, as a JWK Set (RFC 8037 OKP keys)."""
        return {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": kid,
                    "use": "sig",
                    "alg": "EdDSA",
                    "x": b64url(public_bytes(k.public_key())),
                }
                for kid, k in self.keys.items()
            ]
        }


def parse(spec: str) -> Keyring:
    keys: dict[str, Ed25519PrivateKey] = {}
    for entry in (e.strip() for e in spec.split(",")):
        if not entry:
            continue
        kid, sep, seed = entry.partition("=")
        if not sep or not kid or ":" in kid:
            raise RuntimeError("PACT_BOARD_KEYS entries look like kid=<base64url seed>; a kid has no ':'")
        try:
            raw = b64url_decode(seed)
        except ValueError as err:
            raise RuntimeError(f"PACT_BOARD_KEYS key {kid} is not base64url") from err
        if len(raw) != 32:
            raise RuntimeError(f"PACT_BOARD_KEYS key {kid} must be a 32-byte seed")
        if kid in keys:
            raise RuntimeError(f"PACT_BOARD_KEYS lists {kid} twice")
        keys[kid] = Ed25519PrivateKey.from_private_bytes(raw)
    if not keys:
        raise RuntimeError("PACT_BOARD_KEYS has no keys")
    return Keyring(keys=keys, active=next(iter(keys)))


def derived() -> Keyring:
    seed = hashlib.sha256(b"pact-board-ed25519/" + signing_key().encode()).digest()
    return Keyring(keys={DERIVED_KID: Ed25519PrivateKey.from_private_bytes(seed)}, active=DERIVED_KID)


@lru_cache(maxsize=4)
def _cached(spec: str, legacy: str) -> Keyring:
    return parse(spec) if spec else derived()


def keyring() -> Keyring:
    """The keyring for this process, rebuilt when the environment changes (tests rotate keys)."""
    return _cached(os.environ.get("PACT_BOARD_KEYS", ""), os.environ.get("PACT_SIGNING_KEY", ""))


def new_seed() -> str:
    """A fresh key seed for PACT_BOARD_KEYS (``pact-admin key-new``)."""
    return b64url(os.urandom(32))


def public_key_from_text(text: str) -> bytes:
    """An agent's public key as base64url of the raw 32 bytes."""
    try:
        raw = b64url_decode(text.strip())
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as err:
        raise ValueError("an Ed25519 public key is base64url of its 32 raw bytes") from err
    return raw
