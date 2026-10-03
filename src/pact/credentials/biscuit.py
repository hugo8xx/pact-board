"""Biscuit export: a verified ledger chain as one Biscuit token a verifier checks offline.

The second adapter, kept to the same shape as Tenuo so a deployment can switch formats with
``PACT_EXPORT_FORMAT`` alone. A chain of N ledger links (root first) becomes a token of N blocks:
the authority block for the root link, signed with the board's active Ed25519 key, then one
attenuation block per later link. Biscuit gives every block its own revocation id, and a token's
ids include those of the blocks it was derived from, so revoking any ledger link finds the block
minted for it (``Exported.links``) and every token that contains that block fails.

Mapping per link, in Datalog:

- ``action@project:P`` → ``right(P, action)`` in the authority block, and in every block
  ``check if tool(a), project(p) or …`` listing the link's own scope, so a later block can only
  narrow. Wildcard actions and scopes without a project cannot be exported, as with Tenuo.
- each limit ``k`` → ``check if arg(k, $v), $v <= max``, a per-call ceiling the call must pass
  (the argument must be present). A link inherits the tightest ancestor's value for a key it does
  not set. Biscuit Datalog has integers only, so limits and arguments are in millionths
  (``MICRO``): ``cost_usd = 5.0`` is ``arg("cost_usd", 5000000)``.
- expiry → ``check if time($t), $t <= <expires_at>``; the last block is capped at
  ``PACT_EXPORT_TTL_HOURS`` like Tenuo's leaf.
- the last block also lists the arguments a call may carry besides ``project``: ``task_id`` and
  the limit keys (``reject if arg($k, $v), !{...}.contains($k)``), matching Tenuo's refusal of
  unknown arguments. Unlike Tenuo, ``task_id`` may be left out.
- holder → ``holder("<base64url agent key>")`` in the last block. **Biscuit has no proof of
  possession**: the token is a bearer token, and a verifier cannot prove that the caller holds the
  agent's key. Anyone who obtains the token can use it until it expires or is revoked. The fact is
  there so a verifier that authenticates its caller some other way (mTLS, a signed request) can
  compare keys; Tenuo is the format to pick when that matters.

Widening: the board refuses a child that widens before anything is minted (``scope_exceeded``).
Inside a token, a block appended later that adds facts such as ``right("web", "task.admin")`` is
not an error but has no effect: an authorizer trusts facts from the authority block and itself
only, and checks from every block must still pass.

Revocation: Biscuit defines no revocation list format, so the board publishes its own: canonical
JSON ``{"format": "biscuit", "issued_at": …, "revoked": [hex ids], "version": n}`` signed with the
board keyring (``ed25519:<kid>:<sig>``), served as ``{"payload": <that JSON text>, "signature": …}``.
``verify_revocation_list`` checks it against the board's JWKS.
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from biscuit_auth import (
    Algorithm,
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BiscuitValidationError,
    BlockBuilder,
    Fact,
    PrivateKey,
    PublicKey,
    UnverifiedBiscuit,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..errors import PactError
from ..keys import PREFIX, Keyring, b64url, b64url_decode, public_bytes
from ..mandates import Chain, Limits
from ..scope import parse_board_scope
from . import Exported, Imported, TrustedRoot
from .tenuo import effective_limits, leaf_ttl_cap, unexportable

NAME = "biscuit"
MICRO = 1_000_000
"""Biscuit integers carry limits and numeric arguments in millionths."""
FREE_ARGS = ("task_id",)
AUTHORIZER_MAX_TIME = timedelta(milliseconds=50)
CLAIM_FIELD = "biscuit"
"""The key under which ``pact_claim`` hands the agent its token (base64url)."""


def micros(value: float) -> int:
    return round(float(value) * MICRO)


def root_key_id(public_key: bytes) -> int:
    """A Biscuit root key id (u32) derived from the public key, so a verifier holding the board's
    JWKS picks the right key after a rotation without a lookup table."""
    return int.from_bytes(hashlib.sha256(public_key).digest()[:4], "big")


def private_key(keyring: Keyring) -> PrivateKey:
    """The board's active Ed25519 key as a Biscuit key (same 32-byte seed)."""
    seed = keyring.keys[keyring.active].private_bytes_raw()
    # biscuit-python 0.4's stubs predate the algorithm argument the runtime requires.
    return PrivateKey.from_bytes(seed, Algorithm.Ed25519)  # type: ignore[call-arg, attr-defined]


def public_key(raw: bytes) -> PublicKey:
    return PublicKey.from_bytes(raw, Algorithm.Ed25519)  # type: ignore[call-arg, attr-defined]


def trusted_keys(keyring: Keyring) -> list[bytes]:
    return [public_bytes(k.public_key()) for k in keyring.keys.values()]


def trusted_keys_from_jwks(jwks: Mapping[str, Any]) -> list[bytes]:
    """Trusted root keys from the board's ``/.well-known/pact-keys.json``."""
    return [b64url_decode(k["x"]) for k in jwks.get("keys", []) if k.get("crv") == "Ed25519"]


def _scope_pairs(scope: Sequence[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for s in scope:
        parsed = parse_board_scope(s)
        assert parsed is not None  # checked by unexportable()
        if (parsed.project, parsed.action) not in pairs:
            pairs.append((parsed.project, parsed.action))
    return pairs


def _block_code(
    scope: Sequence[str], limits: Limits, expires_at: datetime, *, authority: bool, last: bool
) -> tuple[str, dict[str, Any]]:
    lines: list[str] = []
    params: dict[str, Any] = {"exp": expires_at}
    pairs = _scope_pairs(scope)
    if not pairs:
        raise PactError("invalid_request", "a mandate with an empty scope cannot be exported as a Biscuit token")
    alts = []
    for i, (project, action) in enumerate(pairs):
        params[f"p{i}"], params[f"a{i}"] = project, action
        if authority:
            lines.append(f"right({{p{i}}}, {{a{i}}});")
        alts.append(f"tool({{a{i}}}), project({{p{i}}})")
    lines.append(f"check if {' or '.join(alts)};")
    for i, (k, v) in enumerate(sorted(limits.items())):
        params[f"k{i}"], params[f"v{i}"] = k, micros(v)
        lines.append(f"check if arg({{k{i}}}, $v), $v <= {{v{i}}};")
    lines.append("check if time($t), $t <= {exp};")
    if last:
        allowed = [*FREE_ARGS, *sorted(limits)]
        params["args"] = set(allowed)
        lines.append("reject if arg($k, $v), !{args}.contains($k);")
    return "\n".join(lines), params


class BiscuitFormat:
    name = NAME
    revocation_list_type = "application/json"

    def mint(self, chain: Chain, *, keyring: Keyring, holder_keys: Mapping[str, bytes]) -> Exported:
        leaf = chain.leaf
        key = holder_keys.get(leaf.holder)
        if key is None:
            raise PactError("invalid_request", f"agent {leaf.holder} has no registered public key to hold a credential")
        bad = sorted({s for m in chain.links for s in unexportable(m.scope)})
        if bad:
            raise PactError("invalid_request", f"these scopes cannot be exported as Biscuit tokens: {', '.join(bad)}", leaf.id)
        now = datetime.now(UTC)
        cap = now + timedelta(seconds=leaf_ttl_cap())
        limits = effective_limits(chain.links)
        board_public = public_bytes(keyring.keys[keyring.active].public_key())
        token: Biscuit | None = None
        for i, (m, lim) in enumerate(zip(chain.links, limits, strict=True)):
            last = i == len(chain.links) - 1
            expires = min(m.expires_at, cap) if last else m.expires_at
            code, params = _block_code(m.scope, lim, expires, authority=token is None, last=last)
            code = "mandate({mid});\n" + code
            params["mid"] = m.id
            if last:
                code = "holder({holder});\n" + code
                params["holder"] = b64url(key)
            if token is None:
                builder = BiscuitBuilder(code, params)
                builder.set_root_key_id(root_key_id(board_public))
                token = builder.build(private_key(keyring))
            else:
                token = token.append(BlockBuilder(code, params))
        assert token is not None
        ids = list(token.revocation_ids)
        return Exported(
            format=NAME,
            external_id=ids[-1],
            credential=token.to_base64().encode(),
            links=tuple(zip(chain.ids, ids, strict=True)),
            field=CLAIM_FIELD,
        )

    def ingest(self, credential: bytes, *, trusted_roots: Sequence[TrustedRoot]) -> Imported:
        raise PactError("invalid_request", "importing Biscuit tokens is not supported yet")

    def revocation_ids(self, credential: bytes) -> list[str]:
        return list(UnverifiedBiscuit.from_base64(credential.decode()).revocation_ids)

    def revocation_list(self, revoked: Sequence[str], *, keyring: Keyring, version: int) -> bytes:
        payload = canonical(
            {
                "format": NAME,
                "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "revoked": list(revoked),
                "version": version,
            }
        )
        return canonical({"payload": payload, "signature": keyring.sign(payload)}).encode()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ── verifier side: what a tool server outside the board runs ──────────────────────────────


def verify_revocation_list(document: bytes, jwks: Mapping[str, Any]) -> dict[str, Any]:
    """The payload of a board-signed Biscuit revocation list, after checking its signature against
    the board's JWKS. Raises ``ValueError`` when it is not signed by a key in ``jwks``."""
    outer = json.loads(document)
    payload, signature = outer["payload"], outer["signature"]
    parts = signature.split(":")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise ValueError("not an ed25519 board signature")
    keys = {k.get("kid"): k for k in jwks.get("keys", []) if k.get("crv") == "Ed25519"}
    jwk = keys.get(parts[1])
    if jwk is None:
        raise ValueError(f"revocation list signed by unknown key {parts[1]!r}")
    try:
        Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"])).verify(b64url_decode(parts[2]), payload.encode())
    except (InvalidSignature, ValueError) as err:
        raise ValueError("revocation list signature does not verify") from err
    body: dict[str, Any] = json.loads(payload)
    if body.get("format") != NAME:
        raise ValueError("not a Biscuit revocation list")
    return body


def parse_token(credential: str | bytes, trusted: Sequence[bytes]) -> Biscuit:
    """Deserialize and check a token's signatures against the board's trusted root keys.
    Raises when no trusted key signed it."""
    text = credential.decode() if isinstance(credential, bytes) else credential
    by_id = {root_key_id(k): k for k in trusted}
    kid = UnverifiedBiscuit.from_base64(text).root_key_id()
    candidates = [by_id[kid]] if kid in by_id else list(trusted)
    for key in candidates:
        try:
            return Biscuit.from_base64(text, public_key(key))
        except BiscuitValidationError:  # one error for every failure, a wrong key included
            continue
    raise ValueError("token is not signed by a trusted board key")


def authorizer_for(tool: str, args: Mapping[str, Any], now: datetime | None = None) -> AuthorizerBuilder:
    """The authorizer a verifier builds for one call: ``tool(...)``, ``project(...)`` from
    ``args["project"]``, ``arg(k, v)`` for every other argument (numbers in millionths), the time,
    and the policy that the authority block must grant the tool on the project."""
    builder = AuthorizerBuilder(
        "tool({tool}); time({now}); allow if tool($t), project($p), right($p, $t); deny if true;",
        {"tool": tool, "now": now or datetime.now(UTC)},
    )
    # Biscuit's default 1 ms evaluation budget fails closed under load; these tokens are small.
    limits = builder.limits()  # type: ignore[attr-defined]  # missing from the 0.4 stubs
    limits.max_time = AUTHORIZER_MAX_TIME
    builder.set_limits(limits)  # type: ignore[attr-defined]
    for k, v in args.items():
        if k == "project":
            builder.add_fact(Fact("project({p})", {"p": str(v)}))
        elif isinstance(v, bool) or not isinstance(v, int | float):
            builder.add_fact(Fact("arg({k}, {v})", {"k": k, "v": str(v)}))
        else:
            builder.add_fact(Fact("arg({k}, {v})", {"k": k, "v": micros(v)}))
    return builder


def authorize(
    credential: str | bytes,
    tool: str,
    args: Mapping[str, Any],
    *,
    trusted: Sequence[bytes],
    revoked: Sequence[str] = (),
    now: datetime | None = None,
) -> bool:
    """A complete offline check: board signature, revocation (any block revoked fails the token),
    then scope, limits and expiry. No proof of possession: Biscuit cannot provide one."""
    try:
        token = parse_token(credential, trusted)
    except Exception:
        return False
    if set(token.revocation_ids) & set(revoked):
        return False
    try:
        authorizer_for(tool, args, now).build(token).authorize()
    except Exception:  # AuthorizationError: a check or the policy failed
        return False
    return True
