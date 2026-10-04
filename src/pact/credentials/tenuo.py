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

Import (``ingest``) runs the mapping backwards on the leaf of a stack whose root was signed by a
trusted root: each tool's ``project`` (``Exact`` or ``OneOf``) gives ``tool@project:P`` scopes,
each ``Range.max_value`` a limit (the tightest across tools, since a ledger limit covers every
tool), ``task_id`` may only be ``Wildcard``. Anything the ledger cannot hold is refused rather than
dropped, because dropping a constraint would widen the authority the issuer granted.
"""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from tenuo import (
    MAX_WARRANT_TTL_SECS,
    Authorizer,
    Exact,
    OneOf,
    PublicKey,
    Range,
    SigningKey,
    SrlBuilder,
    TenuoError,
    Warrant,
    Wildcard,
    decode_warrant_stack_base64,
    encode_warrant_stack,
)

from ..errors import PactError
from ..keys import Keyring, b64url, b64url_decode, public_bytes
from ..mandates import Chain, Limits
from ..scope import parse_board_scope
from . import Exported, Imported, TrustedRoot
from .shapes import effective_limits, leaf_ttl_cap, unexportable

NAME = "tenuo"
FREE_ARGS = ("task_id",)
"""Arguments any value may take. Everything else a verifier's tool receives must be constrained."""
IMPORT_DELEGATIONS = 2
"""Delegations an imported, non-terminal warrant grants on the board: the same as a fresh
registration, and never more than the warrant's own remaining Tenuo depth."""


def signing_key(keyring: Keyring) -> SigningKey:
    """The board's active Ed25519 key as a Tenuo key (same 32-byte seed)."""
    return SigningKey.from_bytes(keyring.keys[keyring.active].private_bytes_raw())


def trusted_roots(keyring: Keyring) -> list[PublicKey]:
    """Every key in the keyring, so a credential minted before a rotation keeps verifying."""
    return [PublicKey.from_bytes(public_bytes(k.public_key())) for k in keyring.keys.values()]


def trusted_roots_from_jwks(jwks: Mapping[str, Any]) -> list[PublicKey]:
    """Trusted roots from the board's ``/.well-known/pact-keys.json``."""
    return [PublicKey.from_bytes(b64url_decode(k["x"])) for k in jwks.get("keys", []) if k.get("crv") == "Ed25519"]


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


def ttl(expires_at: datetime, now: datetime) -> int:
    return max(1, min(int(MAX_WARRANT_TTL_SECS), int((expires_at - now).total_seconds())))


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
        """Verify a warrant stack against ``trusted_roots`` only and map its leaf to a mandate."""
        try:
            chain = decode_warrant_stack_base64(credential.decode().strip())
        except (TenuoError, ValueError) as err:
            if "signature" in str(err):  # decoding checks each warrant's signature
                raise PactError("chain_broken", f"the warrant stack does not verify: {err}") from None
            raise PactError("invalid_request", f"not a Tenuo warrant stack: {err}") from None
        if not chain:
            raise PactError("invalid_request", "the warrant stack is empty")
        humans = {}
        for root in trusted_roots:
            try:
                humans[b64url_decode(root.principal)] = root.human
            except ValueError:
                continue
        roots = [PublicKey.from_bytes(k) for k in humans]
        issuer = chain[0].issuer.to_bytes()
        if issuer not in humans:
            raise PactError("chain_broken", f"the warrant stack is rooted at {b64url(issuer)}, which is not a trusted root")
        try:
            Authorizer(trusted_roots=roots).verify_chain(chain)
        except TenuoError as err:
            raise PactError("chain_broken", f"the warrant stack does not verify: {err}") from None
        expired = [w.id for w in chain if w.is_expired()]
        if expired:  # verify_chain checks signatures and linkage, not expiry
            raise PactError("chain_broken", f"warrant {expired[0]} in the stack has expired")
        leaf = chain[-1]
        if str(leaf.warrant_type) != "WarrantType.Execution":
            raise PactError("invalid_request", f"warrant {leaf.id} is a {leaf.warrant_type} warrant, not an execution warrant")
        if leaf.requires_multisig():
            raise PactError("invalid_request", f"warrant {leaf.id} needs outside approvals, which the board cannot check")
        scope, limits = to_ledger(leaf.capabilities)
        delegations = 0 if leaf.is_terminal() else max(0, min(IMPORT_DELEGATIONS, leaf.max_depth - leaf.depth))
        return Imported(
            format=NAME,
            external_id=leaf.id,
            credential=credential.strip(),
            issuer_principal=b64url(issuer),
            human=humans[issuer],
            holder_key=b64url(leaf.authorized_holder.to_bytes()),
            scope=scope,
            limits=limits,
            expires_at=datetime.fromisoformat(leaf.expires_at()).astimezone(UTC),
            delegations=delegations,
        )

    def revocation_ids(self, credential: bytes) -> list[str]:
        return [w.id for w in decode_warrant_stack_base64(credential.decode())]

    def revocation_list(self, revoked: Sequence[str], *, keyring: Keyring, version: int) -> bytes:
        builder = SrlBuilder()
        for warrant_id in revoked:
            builder = builder.revoke(warrant_id)
        return bytes(builder.version(version).build(signing_key(keyring)).to_bytes())


def _projects(tool: str, constraint: Any) -> list[str]:
    if isinstance(constraint, Exact) and isinstance(constraint.value, str):
        return [constraint.value]
    if isinstance(constraint, OneOf) and constraint.values and all(isinstance(v, str) for v in constraint.values):
        return list(constraint.values)
    raise PactError("invalid_request", f"{tool}: project must be Exact or OneOf project ids, not {constraint!r}")


def to_ledger(caps: Mapping[str, Mapping[str, Any]]) -> tuple[list[str], Limits]:
    """A leaf warrant's capabilities as ledger scope and limits; ``invalid_request`` for anything else."""
    if not caps:
        raise PactError("invalid_request", "the warrant grants no tools")
    scope: list[str] = []
    limits: Limits = {}
    for tool, cons in caps.items():
        if "*" in tool:
            raise PactError("invalid_request", f"tool {tool!r} is a wildcard; an imported warrant names each tool")
        if "project" not in cons:
            raise PactError("invalid_request", f"tool {tool} has no project constraint, so it would reach every project")
        for p in _projects(tool, cons["project"]):
            s = f"{tool}@project:{p}"
            if parse_board_scope(s) is None:
                raise PactError("invalid_request", f"{tool} on project {p!r} is not a board scope")
            if s not in scope:
                scope.append(s)
        for key, c in cons.items():
            if key == "project":
                continue
            if key in FREE_ARGS and isinstance(c, Wildcard):
                continue
            if isinstance(c, Range) and c.min is None and c.max is not None and key not in FREE_ARGS:
                limits[key] = min(float(c.max), limits.get(key, float(c.max)))
                continue
            raise PactError("invalid_request", f"{tool}.{key}={c!r} has no ledger equivalent (only Range.max_value limits)")
    return sorted(scope), limits


def warrant_stack(exported: Exported) -> str:
    """The base64 warrant stack an agent puts in ``_meta.tenuo.warrant``."""
    return exported.credential.decode()
