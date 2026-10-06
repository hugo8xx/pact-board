"""Mandates: issuing, verifying the whole chain, aggregate limits, revocation."""

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from psycopg.types.json import Jsonb

from .crypto import canonical_json, hmac_equals, hmac_hex, iso, signing_key
from .db import Conn, fetchall, fetchone
from .errors import PactError
from .keys import b64url, b64url_decode, keyring
from .scope import uncovered

MAX_DEPTH = 5
"""Longest allowed chain below the human root. Deeper chains are refused, never cached around."""

Limits = dict[str, float]


@dataclass(frozen=True)
class Mandate:
    id: str
    parent_id: str | None
    issuer_kind: Literal["human", "agent"]
    issuer: str
    holder: str
    scope: list[str]
    limits: Limits
    delegations_left: int
    depth: int
    expires_at: datetime
    revoked_at: datetime | None
    signature: str
    format: str = "pact"
    """Where this link came from: ``pact`` for one the board issued, else the credential format it was imported from."""
    external_id: str | None = None
    issuer_principal: str | None = None
    """For an imported link: base64url of the outside key (a trusted root) that issued the credential."""

    @classmethod
    def from_row(cls, r: dict[str, Any]) -> "Mandate":
        return cls(
            id=str(r["id"]),
            parent_id=str(r["parent_id"]) if r["parent_id"] else None,
            issuer_kind=r["issuer_kind"],
            issuer=r["issuer"],
            holder=r["holder"],
            scope=list(r["scope"]),
            limits={k: float(v) for k, v in (r["limits"] or {}).items()},
            delegations_left=r["delegations_left"],
            depth=r["depth"],
            expires_at=r["expires_at"],
            revoked_at=r["revoked_at"],
            signature=r["signature"],
            format=r.get("format") or "pact",
            external_id=r.get("external_id"),
            issuer_principal=r.get("issuer_principal"),
        )


@dataclass(frozen=True)
class Chain:
    """A verified chain, root first. ``leaf`` is the mandate the caller presented."""

    links: list[Mandate]

    @property
    def leaf(self) -> Mandate:
        return self.links[-1]

    @property
    def ids(self) -> list[str]:
        return [m.id for m in self.links]


_COLUMNS = (
    "id, parent_id, issuer_kind, issuer, holder, scope, limits, delegations_left, depth, expires_at, revoked_at, signature, "
    "format, external_id, issuer_principal"
)


def _payload(
    *,
    id: str,
    parent_id: str | None,
    issuer_kind: str,
    issuer: str,
    holder: str,
    scope: list[str],
    limits: Limits,
    delegations_left: int,
    depth: int,
    expires_at: datetime,
    imported: tuple[str, str | None, str | None] | None = None,
) -> str:
    """The canonical bytes a mandate's signature covers: every field but revoked_at and the signature.

    ``imported`` is (format, external_id, issuer_principal) of a link imported from an outside
    credential. It is signed too, so the trusted root a link answers to cannot be swapped in the
    database; board-issued links leave it out and keep their payload unchanged."""
    extra = {}
    if imported is not None:
        extra = {"format": imported[0], "external_id": imported[1], "issuer_principal": imported[2]}
    return canonical_json(
        {
            **extra,
            "id": id,
            "parent_id": parent_id,
            "issuer_kind": issuer_kind,
            "issuer": issuer,
            "holder": holder,
            "scope": scope,
            "limits": limits,
            "delegations_left": delegations_left,
            "depth": depth,
            "expires_at": iso(expires_at),
        }
    )


def payload_of(m: Mandate) -> str:
    return _payload(
        id=m.id,
        parent_id=m.parent_id,
        issuer_kind=m.issuer_kind,
        issuer=m.issuer,
        holder=m.holder,
        scope=m.scope,
        limits=m.limits,
        delegations_left=m.delegations_left,
        depth=m.depth,
        expires_at=m.expires_at,
        imported=None if m.format == "pact" else (m.format, m.external_id, m.issuer_principal),
    )


def signature_valid(m: Mandate) -> bool:
    """Ed25519 under any key in the board's keyring; mandates issued before Ed25519 carry an
    HMAC under PACT_SIGNING_KEY and keep verifying that way until they expire."""
    payload = payload_of(m)
    if m.signature.startswith("ed25519:"):
        return keyring().verify(payload, m.signature)
    return hmac_equals(m.signature, hmac_hex(signing_key(), payload))


async def _insert(
    conn: Conn,
    *,
    parent_id: str | None,
    issuer_kind: Literal["human", "agent"],
    issuer: str,
    holder: str,
    scope: list[str],
    limits: Limits,
    delegations_left: int,
    depth: int,
    expires_at: datetime,
    imported: "ImportedLink | None" = None,
) -> Mandate:
    # Postgres keeps microseconds; trim nothing, but pin the zone so the signature round-trips.
    expires_at = expires_at.astimezone(UTC)
    fmt = imported.format if imported else "pact"
    m = Mandate(
        id=str(uuid4()),
        parent_id=parent_id,
        issuer_kind=issuer_kind,
        issuer=issuer,
        holder=holder,
        scope=scope,
        limits=limits,
        delegations_left=delegations_left,
        depth=depth,
        expires_at=expires_at,
        revoked_at=None,
        signature="",
        format=fmt,
        external_id=imported.external_id if imported else None,
        issuer_principal=imported.issuer_principal if imported else None,
    )
    sig = keyring().sign(payload_of(m))
    await conn.execute(
        """INSERT INTO mandates (id, parent_id, issuer_kind, issuer, holder, scope, limits, delegations_left, depth,
                                 expires_at, signature, format, external_id, credential, issuer_principal)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            m.id,
            parent_id,
            issuer_kind,
            issuer,
            holder,
            scope,
            Jsonb(limits),
            delegations_left,
            depth,
            expires_at,
            sig,
            fmt,
            m.external_id,
            imported.credential if imported else None,
            m.issuer_principal,
        ),
    )
    return Mandate(**{**m.__dict__, "signature": sig})


@dataclass(frozen=True)
class ImportedLink:
    """Where a root mandate came from when it was imported from an outside credential."""

    format: str
    external_id: str
    credential: bytes
    issuer_principal: str


async def issue_root(
    conn: Conn,
    *,
    human: str,
    holder: str,
    scope: list[str],
    limits: Limits,
    delegations: int,
    expires_at: datetime,
    imported: ImportedLink | None = None,
) -> Mandate:
    """A root mandate issued by ``human``. With ``imported``, the root of an outside credential
    whose trusted root stands for ``human``; the board still signs the row, so every link is
    checked the same way."""
    if not 0 <= delegations <= MAX_DEPTH:
        raise PactError("invalid_request", f"delegations must be between 0 and {MAX_DEPTH}")
    return await _insert(
        conn,
        parent_id=None,
        issuer_kind="human",
        issuer=human,
        holder=holder,
        scope=scope,
        limits=limits,
        delegations_left=delegations,
        depth=0,
        expires_at=expires_at,
        imported=imported,
    )


async def issue_child(
    conn: Conn,
    chain: Chain,
    *,
    holder: str,
    scope: list[str],
    limits: Limits | None = None,
    expires_at: datetime | None = None,
) -> Mandate:
    """Issue a child of a verified chain. Authority only shrinks: a subset of the scope, no
    higher limit, one fewer delegation, no later expiry."""
    parent = chain.leaf
    if parent.delegations_left < 1 or parent.depth + 1 > MAX_DEPTH:
        raise PactError("delegation_exhausted", f"mandate {parent.id} has no delegations left", parent.id)
    wider = uncovered(scope, parent.scope)
    if wider:
        raise PactError("scope_exceeded", f"child scope is wider than mandate {parent.id}: {', '.join(wider)}", parent.id)
    limits = dict(limits or {})
    for key, value in limits.items():
        ceiling = parent.limits.get(key)
        if ceiling is not None and value > ceiling:
            raise PactError("limit_exceeded", f"child limit {key}={value} is above {ceiling} on mandate {parent.id}", parent.id)
    expiry = expires_at if expires_at and expires_at < parent.expires_at else parent.expires_at
    return await _insert(
        conn,
        parent_id=parent.id,
        issuer_kind="agent",
        issuer=parent.holder,
        holder=holder,
        scope=scope,
        limits=limits,
        delegations_left=parent.delegations_left - 1,
        depth=parent.depth + 1,
        expires_at=expiry,
    )


async def verify_chain(conn: Conn, leaf_id: str, holder: str, now: datetime | None = None) -> Chain:
    """Walk the chain from ``leaf_id`` to its root and check every link, on every call.

    Never cached: a mandate can be revoked between two calls.
    """
    now = now or datetime.now(UTC)
    rows = (
        await fetchall(
            conn,
            f"""WITH RECURSIVE chain AS (
              SELECT m.*, 0 AS lvl FROM mandates m WHERE m.id = %(leaf)s
              UNION ALL
              SELECT p.*, c.lvl + 1 FROM mandates p JOIN chain c ON p.id = c.parent_id WHERE c.lvl <= %(max)s
            )
            SELECT {_COLUMNS},
                   (c.issuer_kind = 'human' AND EXISTS (SELECT 1 FROM humans h WHERE h.id = c.issuer)) AS issuer_is_human,
                   (SELECT h.org_id FROM humans h WHERE h.id = c.issuer AND c.issuer_kind = 'human') AS issuer_org,
                   (SELECT a.org_id FROM agents a WHERE a.id = c.holder) AS holder_org
            FROM chain c ORDER BY c.lvl DESC""",
            {"leaf": leaf_id, "max": MAX_DEPTH},
        )
        if _is_uuid(leaf_id)
        else []
    )
    if not rows:
        raise PactError("chain_broken", f"mandate {leaf_id} does not exist", leaf_id)

    links = [Mandate.from_row(r) for r in rows]
    root = links[0]
    if len(links) > MAX_DEPTH + 1 or root.parent_id is not None:
        raise PactError("chain_broken", f"chain of {leaf_id} is deeper than {MAX_DEPTH} links or has no root", root.id)
    if not rows[0]["issuer_is_human"]:
        raise PactError("chain_broken", f"root mandate {root.id} was not issued by a registered human", root.id)
    # Authority never crosses organizations: the person at the root and every holder below share one.
    orgs = {rows[0]["issuer_org"], *(r["holder_org"] for r in rows)}
    if len(orgs) != 1:
        raise PactError("chain_broken", f"chain of {leaf_id} crosses organizations", root.id)

    for i, m in enumerate(links):
        if not signature_valid(m):
            raise PactError("chain_broken", f"signature of mandate {m.id} does not match its contents", m.id)
        if i == 0:
            if m.depth != 0:
                raise PactError("chain_broken", f"root mandate {m.id} has depth {m.depth}", m.id)
            continue
        p = links[i - 1]
        problem = (
            "is not linked to its parent"
            if m.parent_id != p.id
            else f"was issued by {m.issuer}, not by the parent's holder {p.holder}"
            if m.issuer_kind != "agent" or m.issuer != p.holder
            else "has the wrong depth"
            if m.depth != p.depth + 1
            else "has a wider scope than its parent"
            if uncovered(m.scope, p.scope)
            else "has a higher limit than its parent"
            if any(k in p.limits and v > p.limits[k] for k, v in m.limits.items())
            else "does not have fewer delegations than its parent"
            if m.delegations_left >= p.delegations_left
            else "expires after its parent"
            if m.expires_at > p.expires_at
            else None
        )
        if problem:
            raise PactError("chain_broken", f"mandate {m.id} {problem}", m.id)

    for m in links:
        if m.revoked_at:
            raise PactError("mandate_revoked", f"mandate {m.id} in the chain was revoked", m.id)
    await _check_trusted_roots(conn, links)
    for m in links:
        if m.expires_at <= now:
            raise PactError("mandate_expired", f"mandate {m.id} in the chain expired at {iso(m.expires_at)}", m.id)

    leaf = links[-1]
    if leaf.holder != holder:
        raise PactError("chain_broken", f"mandate {leaf.id} is held by {leaf.holder}, not by the caller {holder}", leaf.id)
    return Chain(links)


async def _check_trusted_roots(conn: Conn, links: list[Mandate]) -> None:
    """A link imported from an outside credential lives only while its issuing key is still a
    trusted root standing for the human the link names as issuer, and only if it was imported
    during the key's current activation: re-adding a revoked key never revives what came before."""
    imported = [m for m in links if m.format != "pact" and m.issuer_principal]
    if not imported:
        return
    principals = []
    for m in imported:
        try:
            principals.append(b64url_decode(m.issuer_principal or ""))
        except ValueError:
            raise PactError("chain_broken", f"mandate {m.id} names an unreadable issuer key", m.id) from None
    live = {
        (r["mandate_id"], b64url(bytes(r["principal"])), r["human"])
        for r in await fetchall(
            conn,
            """SELECT m.id::text AS mandate_id, r.principal, r.human
               FROM trusted_roots r JOIN mandates m ON m.id = ANY(%s::uuid[]) AND m.created_at >= r.active_since
               JOIN agents a ON a.id = m.holder AND a.org_id = r.org_id
               WHERE r.principal = ANY(%s) AND r.revoked_at IS NULL""",
            ([m.id for m in imported], principals),
        )
    }
    for m in imported:
        if (m.id, m.issuer_principal, m.issuer) not in live:
            raise PactError(
                "mandate_revoked", f"mandate {m.id} was imported under key {m.issuer_principal}, no longer a trusted root", m.id
            )


def check_amounts(amounts: Limits | None, what: str) -> Limits:
    """Amounts an agent hands in to be counted against limits: finite and never negative, so a
    report cannot hand budget back."""
    out: Limits = {}
    for key, value in (amounts or {}).items():
        if not isinstance(value, int | float) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
            raise PactError("invalid_request", f"{what} {key}={value!r} must be a number of at least 0")
        out[key] = float(value)
    return out


async def remaining_limits(conn: Conn, chain: Chain) -> Limits:
    """What is left of every limit in the chain: for each key, the smallest ``ceiling - used``
    over the links that limit it, never below 0. A key no link limits is unlimited and absent."""
    used = {
        (str(r["mandate_id"]), r["limit_key"]): float(r["used"])
        for r in await fetchall(
            conn, "SELECT mandate_id, limit_key, used FROM limit_usage WHERE mandate_id = ANY(%s::uuid[])", (chain.ids,)
        )
    }
    left: Limits = {}
    for m in chain.links:
        for key, ceiling in m.limits.items():
            room = max(ceiling - used.get((m.id, key), 0.0), 0.0)
            left[key] = min(left.get(key, room), room)
    return left


async def consume_limits(conn: Conn, chain: Chain, consumption: Limits, *, strict: bool = True) -> list[str]:
    """Add ``consumption`` to every mandate in the chain that limits that key.

    Usage is a running total, so children split from one parent share its ceiling. Rows are
    locked root first, so concurrent callers on one tree take locks in the same order.

    ``strict`` refuses with ``limit_exceeded`` before going over a ceiling. Without it the amount
    is recorded anyway — for usage that already happened, like the turns a finished run took — and
    the keys that went over come back so the caller can stop spending.
    """
    over: list[str] = []
    for m in chain.links:
        for key, amount in consumption.items():
            ceiling = m.limits.get(key)
            if ceiling is None or amount == 0:
                continue
            await conn.execute(
                "INSERT INTO limit_usage (mandate_id, limit_key) VALUES (%s, %s) ON CONFLICT DO NOTHING", (m.id, key)
            )
            row = await fetchone(
                conn, "SELECT used FROM limit_usage WHERE mandate_id = %s AND limit_key = %s FOR UPDATE", (m.id, key)
            )
            used = float(row["used"]) if row else 0.0
            if used + amount > ceiling:
                if strict:
                    raise PactError(
                        "limit_exceeded",
                        f"{key}: {used:g} used + {amount:g} requested is above {ceiling:g} on mandate {m.id}",
                        m.id,
                    )
                if key not in over:
                    over.append(key)
            await conn.execute(
                "UPDATE limit_usage SET used = used + %s WHERE mandate_id = %s AND limit_key = %s", (amount, m.id, key)
            )
    return over


async def get_mandate(conn: Conn, mandate_id: str) -> Mandate | None:
    if not _is_uuid(mandate_id):
        return None
    row = await fetchone(conn, f"SELECT {_COLUMNS} FROM mandates WHERE id = %s", (mandate_id,))
    return Mandate.from_row(row) if row else None


async def _subtree(conn: Conn, mandate_id: str) -> list[dict[str, Any]]:
    """The mandate and everything delegated under it, with depth below it (0 for itself)."""
    return await fetchall(
        conn,
        """WITH RECURSIVE sub AS (
             SELECT id, holder, revoked_at, 0 AS below FROM mandates WHERE id = %s
             UNION ALL
             SELECT m.id, m.holder, m.revoked_at, s.below + 1 FROM mandates m JOIN sub s ON m.parent_id = s.id
           ) SELECT id::text, holder, revoked_at, below FROM sub ORDER BY below""",
        (mandate_id,),
    )


_OPEN_UNDER = """status IN ('submitted', 'working', 'input_required', 'auth_required')
             AND (mandate_id = ANY(%(ids)s::uuid[]) OR assignee_mandate_id = ANY(%(ids)s::uuid[])
                  OR delegated_mandate_id = ANY(%(ids)s::uuid[]))"""


async def revoke_impact(conn: Conn, mandate_id: str) -> dict[str, Any]:
    """What revoking a mandate would do, without doing it: the live mandates below it, the open
    tasks that would be canceled, and the agents that lose authority."""
    subtree = [m for m in await _subtree(conn, mandate_id) if m["revoked_at"] is None]
    tasks = await fetchall(
        conn,
        f"""SELECT id::text, title, status, assignee FROM tasks WHERE {_OPEN_UNDER} ORDER BY created_at""",
        {"ids": [m["id"] for m in subtree]},
    )
    return {
        "mandate_id": mandate_id,
        "descendants": [{"id": m["id"], "holder": m["holder"], "depth": m["below"]} for m in subtree if m["below"]],
        "tasks": tasks,
        "agents": sorted({m["holder"] for m in subtree}),
    }


async def revoke_subtree(conn: Conn, mandate_id: str) -> dict[str, Any]:
    """Revoke a mandate. Descendants die with it (the chain check sees the revoked ancestor),
    and every open task hanging under it stops."""
    await conn.execute("UPDATE mandates SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL", (mandate_id,))
    subtree = [m["id"] for m in await _subtree(conn, mandate_id)]
    await _revoke_exported(conn, subtree)
    stopped = await fetchall(
        conn,
        f"""UPDATE tasks SET status = 'canceled', assignee = NULL, assignee_mandate_id = NULL,
                  result = jsonb_build_object('reason', 'mandate_revoked', 'mandate_id', %(id)s::text)
           WHERE {_OPEN_UNDER}
           RETURNING id, project_id""",
        {"id": mandate_id, "ids": subtree},
    )
    return {
        "descendant_mandates": len(subtree) - 1,
        "tasks_stopped": len(stopped),
        "stopped": [(str(r["id"]), r["project_id"]) for r in stopped],
    }


async def _revoke_exported(conn: Conn, mandate_ids: list[str]) -> None:
    """Put every outside id minted for these links on the published revocation list, in the
    revoke's own transaction, and bump the list's version for each format that gained ids."""
    added = await fetchall(
        conn,
        """INSERT INTO credential_revocations (external_id, format, expires_at)
           SELECT l.external_id, l.format, m.expires_at FROM credential_links l JOIN mandates m ON m.id = l.mandate_id
           WHERE l.mandate_id = ANY(%s::uuid[])
           ON CONFLICT (external_id) DO NOTHING
           RETURNING format""",
        (mandate_ids,),
    )
    for fmt in sorted({r["format"] for r in added}):
        await conn.execute(
            """INSERT INTO credential_revocation_version (format, version) VALUES (%s, 1)
               ON CONFLICT (format) DO UPDATE SET version = credential_revocation_version.version + 1""",
            (fmt,),
        )


def _is_uuid(value: str) -> bool:
    import re

    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value))
