"""Tenuo export: a verified ledger chain as a stack of Tenuo warrants a verifier checks offline.

Shape of an export for a chain of N ledger links (root first): N warrants held by the board, one
per link, then one leaf warrant for the last link held by the agent's registered key. The board
signs every warrant, so it never needs an agent's private key; the agent signs each call with its
own key (proof of possession). Because the root warrant is always board-held, the leaf is always a
grant and can be made terminal when the ledger link has no delegations left.

Mapping per link:

- ``action@project:P`` → ``capability(action, project=Exact(P))``; one action on several
  projects → ``OneOf``. Wildcard actions (``*``, ``task.*``) and scopes without a project cannot be
  exported: Tenuo tool names do not glob, and a capability without a project would be cross-project.
- each limit ``k`` → ``k=Range.max_value(v)``, a per-call ceiling. A link without its own value for
  ``k`` inherits the tightest ancestor's, because Tenuo refuses a child that drops a constraint.
  Cumulative usage stays in the ledger only.
- ``task_id=Wildcard()`` so outside tools can name the task. That is the only free-form argument:
  Tenuo denies unknown arguments, and every constrained argument must be present on each call
  (project, task_id and each limit key).
- TTL = seconds until the link expires, at most Tenuo's 90 days; a child never outlives its parent.
"""

import os
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from tenuo import (
    MAX_WARRANT_TTL_SECS,
    Exact,
    OneOf,
    PublicKey,
    Range,
    SigningKey,
    SrlBuilder,
    Warrant,
    Wildcard,
    decode_warrant_stack_base64,
    encode_warrant_stack,
)

from ..errors import PactError
from ..keys import Keyring, b64url_decode, public_bytes
from ..mandates import Chain, Limits, Mandate
from ..scope import parse_board_scope
from . import Exported, Imported, TrustedRoot

NAME = "tenuo"
FREE_ARGS = ("task_id",)
"""Arguments any value may take. Everything else a verifier's tool receives must be constrained."""


def signing_key(keyring: Keyring) -> SigningKey:
    """The board's active Ed25519 key as a Tenuo key (same 32-byte seed)."""
    return SigningKey.from_bytes(keyring.keys[keyring.active].private_bytes_raw())


def trusted_roots(keyring: Keyring) -> list[PublicKey]:
    """Every key in the keyring, so a credential minted before a rotation keeps verifying."""
    return [PublicKey.from_bytes(public_bytes(k.public_key())) for k in keyring.keys.values()]


def trusted_roots_from_jwks(jwks: Mapping[str, Any]) -> list[PublicKey]:
    """Trusted roots from the board's ``/.well-known/pact-keys.json``."""
    return [PublicKey.from_bytes(b64url_decode(k["x"])) for k in jwks.get("keys", []) if k.get("crv") == "Ed25519"]


def unexportable(scope: Sequence[str]) -> list[str]:
    out = []
    for s in scope:
        parsed = parse_board_scope(s)
        if parsed is None or "*" in parsed.action:
            out.append(s)
    return out


def capabilities(scope: Sequence[str], limits: Limits) -> dict[str, dict[str, Any]]:
    by_action: dict[str, list[str]] = {}
    for s in scope:
        parsed = parse_board_scope(s)
        assert parsed is not None  # checked by unexportable()
        projects = by_action.setdefault(parsed.action, [])
        if parsed.project not in projects:
            projects.append(parsed.project)
    caps: dict[str, dict[str, Any]] = {}
    for action, projects in by_action.items():
        cons: dict[str, Any] = {"project": Exact(projects[0]) if len(projects) == 1 else OneOf(sorted(projects))}
        cons.update({arg: Wildcard() for arg in FREE_ARGS})
        cons.update({k: Range.max_value(float(v)) for k, v in sorted(limits.items())})
        caps[action] = cons
    return caps


def effective_limits(links: Sequence[Mandate]) -> list[Limits]:
    """Each link's per-call ceilings: its own, tightened by every ancestor's."""
    out: list[Limits] = []
    current: Limits = {}
    for m in links:
        current = {**current, **{k: min(v, current.get(k, v)) for k, v in m.limits.items()}}
        out.append(dict(current))
    return out


def ttl(expires_at: datetime, now: datetime) -> int:
    return max(1, min(int(MAX_WARRANT_TTL_SECS), int((expires_at - now).total_seconds())))


def leaf_ttl_cap() -> int:
    """``PACT_EXPORT_TTL_HOURS`` (default 24): the longest an exported leaf lives. A root mandate
    can run for weeks and is not revoked when a task closes, so an agent's outside credential is
    kept short and simply re-issued on its next claim."""
    return max(60, int(float(os.environ.get("PACT_EXPORT_TTL_HOURS", "24")) * 3600))


class TenuoFormat:
    name = NAME

    def mint(self, chain: Chain, *, keyring: Keyring, holder_keys: Mapping[str, bytes]) -> Exported:
        leaf = chain.leaf
        key = holder_keys.get(leaf.holder)
        if key is None:
            raise PactError("invalid_request", f"agent {leaf.holder} has no registered public key to hold a credential")
        bad = sorted({s for m in chain.links for s in unexportable(m.scope)})
        if bad:
            raise PactError("invalid_request", f"these scopes cannot be exported as Tenuo warrants: {', '.join(bad)}", leaf.id)
        board = signing_key(keyring)
        now = datetime.now(UTC)
        limits = effective_limits(chain.links)
        warrants: list[Warrant] = []
        for m, lim in zip(chain.links, limits, strict=True):
            caps = capabilities(m.scope, lim)
            if not warrants:
                mb = Warrant.mint_builder()
                for tool, cons in caps.items():
                    mb = mb.capability(tool, **cons)
                warrants.append(mb.holder(board.public_key).ttl(ttl(m.expires_at, now)).mint(board))
            else:
                warrants.append(self._grant(warrants[-1], caps, board.public_key, ttl(m.expires_at, now), board, False))
        warrants.append(
            self._grant(
                warrants[-1],
                capabilities(leaf.scope, limits[-1]),
                PublicKey.from_bytes(key),
                min(ttl(leaf.expires_at, now), leaf_ttl_cap()),
                board,
                leaf.delegations_left == 0,
            )
        )
        ids = [w.id for w in warrants]
        mandate_ids = [*chain.ids, leaf.id]
        return Exported(
            format=NAME,
            external_id=ids[-1],
            credential=encode_warrant_stack(warrants).encode(),
            links=tuple(zip(mandate_ids, ids, strict=True)),
        )

    @staticmethod
    def _grant(
        parent: Warrant, caps: dict[str, dict[str, Any]], holder: PublicKey, seconds: int, board: SigningKey, terminal: bool
    ) -> Warrant:
        gb = parent.grant_builder()
        for tool, cons in caps.items():
            gb = gb.capability(tool, **cons)
        gb = gb.holder(holder).ttl(seconds)
        if terminal:
            gb = gb.terminal()
        return gb.grant(board)

    def ingest(self, credential: bytes, *, trusted_roots: Sequence[TrustedRoot]) -> Imported:
        raise PactError("invalid_request", "importing Tenuo warrants comes in phase 2")

    def revocation_ids(self, credential: bytes) -> list[str]:
        return [w.id for w in decode_warrant_stack_base64(credential.decode())]

    def revocation_list(self, revoked: Sequence[str], *, keyring: Keyring, version: int) -> bytes:
        builder = SrlBuilder()
        for warrant_id in revoked:
            builder = builder.revoke(warrant_id)
        return bytes(builder.version(version).build(signing_key(keyring)).to_bytes())


def warrant_stack(exported: Exported) -> str:
    """The base64 warrant stack an agent puts in ``_meta.tenuo.warrant``."""
    return exported.credential.decode()
