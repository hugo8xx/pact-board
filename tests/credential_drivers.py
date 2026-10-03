"""Per-format test drivers: how an outside verifier checks a credential the board exported.

The conformance suite (``test_credential_conformance.py``) runs every case against every driver,
so it only sees this surface. A new format gets a driver here and must pass the whole suite.
"""

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tenuo import Authorizer, SignedRevocationList, SigningKey, decode_warrant_stack_base64
from tenuo.mcp import MCPVerifier
from tenuo.meta import argument_json
from tenuo_core import sign_meta

from pact.credentials import biscuit as biscuit_fmt
from pact.credentials import tenuo as tenuo_fmt


class Driver(Protocol):
    name: str
    field: str
    """The key of the encoded credential in ``pact_claim``'s ``credential``."""
    supports_pop: bool
    """Whether a verifier can prove the caller holds the agent's key."""
    content_type: str
    """Media type of the published revocation list."""
    ids_per_leaf_link: int
    """How many revocation ids one export records for the claimed ledger link."""
    format_cls: type

    def verify(
        self,
        credential: Mapping[str, Any],
        tool: str,
        args: Mapping[str, Any],
        *,
        trusted_jwks: Mapping[str, Any],
        revocations: bytes | None,
        holder_key: Ed25519PrivateKey | None = None,
    ) -> bool: ...

    def listed(self, revocations: bytes, trusted_jwks: Mapping[str, Any]) -> tuple[set[str], int]:
        """The ids on a published list and its version, after checking the board's signature."""
        ...

    def revocation_ids(self, credential: Mapping[str, Any]) -> list[str]: ...


def _seed(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes_raw()


@dataclass(frozen=True)
class TenuoDriver:
    name: str = "tenuo"
    field: str = "warrant_stack"
    supports_pop: bool = True
    content_type: str = "application/octet-stream"
    ids_per_leaf_link: int = 2  # the board-held warrant for the link and the agent's leaf
    format_cls: type = tenuo_fmt.TenuoFormat

    def verify(
        self,
        credential: Mapping[str, Any],
        tool: str,
        args: Mapping[str, Any],
        *,
        trusted_jwks: Mapping[str, Any],
        revocations: bytes | None,
        holder_key: Ed25519PrivateKey | None = None,
    ) -> bool:
        if holder_key is None:
            raise ValueError("a Tenuo call is signed by the holder: pass holder_key")
        auth = Authorizer(trusted_roots=tenuo_fmt.trusted_roots_from_jwks(trusted_jwks))
        if revocations is not None:
            auth.set_revocation_list(SignedRevocationList.from_bytes(revocations))
        stack = credential[self.field]
        key = SigningKey.from_bytes(_seed(holder_key))
        meta = {"tenuo": sign_meta(decode_warrant_stack_base64(stack), key, tool, argument_json(dict(args)), int(time.time()))}
        return bool(MCPVerifier(authorizer=auth).verify(tool, dict(args), meta=meta).allowed)

    def listed(self, revocations: bytes, trusted_jwks: Mapping[str, Any]) -> tuple[set[str], int]:
        srl = SignedRevocationList.from_bytes(revocations)
        errors = []
        for root in tenuo_fmt.trusted_roots_from_jwks(trusted_jwks):
            try:
                srl.verify(root)
                return set(srl.revoked_ids), int(srl.version)
            except Exception as err:  # signed by another trusted key
                errors.append(err)
        raise ValueError(f"revocation list not signed by a trusted key: {errors}")

    def revocation_ids(self, credential: Mapping[str, Any]) -> list[str]:
        return tenuo_fmt.TenuoFormat().revocation_ids(credential[self.field].encode())


@dataclass(frozen=True)
class BiscuitDriver:
    name: str = "biscuit"
    field: str = biscuit_fmt.CLAIM_FIELD
    supports_pop: bool = False  # Biscuit tokens are bearer tokens: see pact.credentials.biscuit
    content_type: str = "application/json"
    ids_per_leaf_link: int = 1  # one block per ledger link
    format_cls: type = biscuit_fmt.BiscuitFormat

    def verify(
        self,
        credential: Mapping[str, Any],
        tool: str,
        args: Mapping[str, Any],
        *,
        trusted_jwks: Mapping[str, Any],
        revocations: bytes | None,
        holder_key: Ed25519PrivateKey | None = None,  # ignored: no proof of possession
    ) -> bool:
        revoked: set[str] = set()
        if revocations is not None:
            revoked, _ = self.listed(revocations, trusted_jwks)
        return biscuit_fmt.authorize(
            credential[self.field],
            tool,
            args,
            trusted=biscuit_fmt.trusted_keys_from_jwks(trusted_jwks),
            revoked=sorted(revoked),
        )

    def listed(self, revocations: bytes, trusted_jwks: Mapping[str, Any]) -> tuple[set[str], int]:
        body = biscuit_fmt.verify_revocation_list(revocations, trusted_jwks)
        return set(body["revoked"]), int(body["version"])

    def revocation_ids(self, credential: Mapping[str, Any]) -> list[str]:
        return biscuit_fmt.BiscuitFormat().revocation_ids(credential[self.field].encode())


DRIVERS: dict[str, Driver] = {"tenuo": TenuoDriver(), "biscuit": BiscuitDriver()}
