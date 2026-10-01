"""Mandates: issuing, verifying the whole chain, aggregate limits, revocation."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from psycopg.types.json import Jsonb

from .crypto import canonical_json, hmac_equals, hmac_hex, iso, signing_key
from .db import Conn, fetchall, fetchone
from .errors import PactError
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


_COLUMNS = "id, parent_id, issuer_kind, issuer, holder, scope, limits, delegations_left, depth, expires_at, revoked_at, signature"


def _signature(
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
) -> str:
    return hmac_hex(
        signing_key(),
        canonical_json(
            {
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
        ),
    )


def _signature_of(m: Mandate) -> str:
    return _signature(
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
    )


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
) -> Mandate:
    # Postgres keeps microseconds; trim nothing, but pin the zone so the signature round-trips.
    expires_at = expires_at.astimezone(UTC)
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
    )
    sig = _signature_of(m)
    await conn.execute(
        """INSERT INTO mandates (id, parent_id, issuer_kind, issuer, holder, scope, limits, delegations_left, depth,
                                 expires_at, signature)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (m.id, parent_id, issuer_kind, issuer, holder, scope, Jsonb(limits), delegations_left, depth, expires_at, sig),
    )
    return Mandate(**{**m.__dict__, "signature": sig})


async def issue_root(
    conn: Conn, *, human: str, holder: str, scope: list[str], limits: Limits, delegations: int, expires_at: datetime
) -> Mandate:
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
                   (c.issuer_kind = 'human' AND EXISTS (SELECT 1 FROM humans h WHERE h.id = c.issuer)) AS issuer_is_human
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

    for i, m in enumerate(links):
        if not hmac_equals(m.signature, _signature_of(m)):
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
    for m in links:
        if m.expires_at <= now:
            raise PactError("mandate_expired", f"mandate {m.id} in the chain expired at {iso(m.expires_at)}", m.id)

    leaf = links[-1]
    if leaf.holder != holder:
        raise PactError("chain_broken", f"mandate {leaf.id} is held by {leaf.holder}, not by the caller {holder}", leaf.id)
    return Chain(links)


async def consume_limits(conn: Conn, chain: Chain, consumption: Limits) -> None:
    """Add ``consumption`` to every mandate in the chain that limits that key.

    Usage is a running total, so children split from one parent share its ceiling. Rows are
    locked root first, so concurrent callers on one tree take locks in the same order.
    """
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
                raise PactError(
                    "limit_exceeded", f"{key}: {used:g} used + {amount:g} requested is above {ceiling:g} on mandate {m.id}", m.id
                )
            await conn.execute(
                "UPDATE limit_usage SET used = used + %s WHERE mandate_id = %s AND limit_key = %s", (amount, m.id, key)
            )


async def get_mandate(conn: Conn, mandate_id: str) -> Mandate | None:
    if not _is_uuid(mandate_id):
        return None
    row = await fetchone(conn, f"SELECT {_COLUMNS} FROM mandates WHERE id = %s", (mandate_id,))
    return Mandate.from_row(row) if row else None


async def revoke_subtree(conn: Conn, mandate_id: str) -> dict[str, Any]:
    """Revoke a mandate. Descendants die with it (the chain check sees the revoked ancestor),
    and every open task hanging under it stops."""
    await conn.execute("UPDATE mandates SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL", (mandate_id,))
    subtree = [
        str(r["id"])
        for r in await fetchall(
            conn,
            """WITH RECURSIVE sub AS (
                 SELECT id FROM mandates WHERE id = %s
                 UNION ALL
                 SELECT m.id FROM mandates m JOIN sub s ON m.parent_id = s.id
               ) SELECT id FROM sub""",
            (mandate_id,),
        )
    ]
    stopped = await fetchall(
        conn,
        """UPDATE tasks SET status = 'canceled', assignee = NULL, assignee_mandate_id = NULL,
                  result = jsonb_build_object('reason', 'mandate_revoked', 'mandate_id', %(id)s::text)
           WHERE status IN ('submitted', 'working', 'input_required', 'auth_required')
             AND (mandate_id = ANY(%(ids)s::uuid[]) OR assignee_mandate_id = ANY(%(ids)s::uuid[])
                  OR delegated_mandate_id = ANY(%(ids)s::uuid[]))
           RETURNING id, project_id""",
        {"id": mandate_id, "ids": subtree},
    )
    return {
        "descendant_mandates": len(subtree) - 1,
        "tasks_stopped": len(stopped),
        "stopped": [(str(r["id"]), r["project_id"]) for r in stopped],
    }


def _is_uuid(value: str) -> bool:
    import re

    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value))
