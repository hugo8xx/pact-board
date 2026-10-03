"""Credential adapters: the ledger exported as, or imported from, standard delegation credentials.

The ``mandates`` table stays the source of truth. Human-rooted chains, cumulative limits,
DEFER/resume and revoke-on-close live there because no credential format provides them. An
adapter only translates:

- ``mint`` turns a verified chain into a credential a verifier outside the board can check on its
  own. The board signs every link it issues and the agent holds only the leaf (owner decision
  2026-10-02: Tenuo wants the parent's holder to sign each child, which the ledger cannot do).
- ``ingest`` checks a credential issued by an outside key and returns what a mandate needs. It is
  accepted only when that key maps to a registered human (``TrustedRoot``).
- ``revocation_ids`` and ``revocation_list`` let a revoke on the board reach outside verifiers.

Adapters raise ``PactError`` with the codes agents already know (``scope_exceeded``,
``chain_broken``, …), so swapping the format changes nothing an agent sees. Formats register
themselves; the board looks them up by name, so a deployment picks one by configuration.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from ..db import Conn
from ..errors import PactError
from ..keys import Keyring
from ..mandates import Chain, Limits


@dataclass(frozen=True)
class Exported:
    format: str
    external_id: str
    credential: bytes


@dataclass(frozen=True)
class TrustedRoot:
    """An outside signing key (base64url of its raw public key) and the human it stands for."""

    principal: str
    human: str


@dataclass(frozen=True)
class Imported:
    format: str
    external_id: str
    credential: bytes
    issuer_principal: str
    human: str
    holder_key: str | None
    scope: list[str]
    limits: Limits
    expires_at: datetime


class CredentialFormat(Protocol):
    name: str

    def mint(self, chain: Chain, *, keyring: Keyring, holder_keys: Mapping[str, bytes]) -> Exported:
        """Export ``chain`` (root first). ``holder_keys`` maps agent id to its Ed25519 public key;
        an agent without one cannot hold an exported credential."""
        ...

    def ingest(self, credential: bytes, *, trusted_roots: Sequence[TrustedRoot]) -> Imported:
        """Verify an outside credential and translate it. Refuse with ``chain_broken`` when its root
        is not a trusted root, and with ``scope_exceeded`` when it widens along the way."""
        ...

    def revocation_ids(self, credential: bytes) -> list[str]:
        """Ids that, once revoked, make this credential and everything derived from it fail."""
        ...

    def revocation_list(self, revoked: Sequence[str], *, keyring: Keyring, version: int) -> bytes:
        """A signed list of revoked ids for outside verifiers. ``version`` only ever grows."""
        ...


_FORMATS: dict[str, CredentialFormat] = {}


def register(fmt: CredentialFormat) -> None:
    _FORMATS[fmt.name] = fmt


def get(name: str) -> CredentialFormat:
    fmt = _FORMATS.get(name)
    if fmt is None:
        known = ", ".join(sorted(_FORMATS)) or "none"
        raise PactError("invalid_request", f"credential format {name!r} is not available (available: {known})")
    return fmt


def names() -> list[str]:
    return sorted(_FORMATS)


async def holder_keys(conn: Conn, agent_ids: Sequence[str]) -> dict[str, bytes]:
    """The newest live public key of each agent that has one."""
    cur = await conn.execute(
        """SELECT DISTINCT ON (agent_id) agent_id, public_key FROM agent_keys
           WHERE agent_id = ANY(%s) AND revoked_at IS NULL ORDER BY agent_id, created_at DESC""",
        (list(agent_ids),),
    )
    return {r["agent_id"]: bytes(r["public_key"]) for r in await cur.fetchall()}


async def store_export(conn: Conn, mandate_id: str, exported: Exported) -> None:
    """Record on the mandate that it now also exists as an outside credential."""
    await conn.execute(
        "UPDATE mandates SET exported_as = %s, external_id = %s, credential = %s WHERE id = %s AND format = 'pact'",
        (exported.format, exported.external_id, exported.credential, mandate_id),
    )
