"""Entries: the append-only log, one hash chain per project."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from psycopg.types.json import Jsonb

from .crypto import canonical_json, iso, sha256
from .db import Conn, fetchall, fetchone
from .redact import redact

SYSTEM_CHAIN = "_system"
DEFAULT_ORG = "default"
"""The organization a single-organization board's data moved into (migration 019)."""
GENESIS = "0" * 64


@dataclass
class EntryInput:
    project_id: str | None
    task_id: str | None
    agent_id: str | None
    actor: str
    """``agent:<id>``, ``human:<id>`` or ``system``."""
    mandate_chain: list[str]
    action: str
    payload: Any
    outcome: str
    """``ok`` or an error code."""
    org_id: str | None = None
    """The organization, when neither the project nor the agent says it (a person's own action)."""


def _entry_hash(fields: dict[str, Any]) -> str:
    return sha256(canonical_json(fields))


async def _place(conn: Conn, e: EntryInput) -> tuple[str, str | None]:
    """The organization and project an entry is filed under. The actor decides the organization (its
    agent's, else the one given, else the project's); a project of another organization is dropped,
    so a refused call that names someone else's project lands in the caller's own log, not theirs."""
    org: str | None = None
    if e.agent_id:
        row = await fetchone(conn, "SELECT org_id FROM agents WHERE id = %s", (e.agent_id,))
        org = str(row["org_id"]) if row else None
    org = org or e.org_id
    project_id = e.project_id
    if project_id:
        row = await fetchone(conn, "SELECT org_id FROM projects WHERE id = %s", (project_id,))
        project_org = str(row["org_id"]) if row else None
        if org is None:
            org = project_org
        elif project_org != org:
            project_id = None
    return org or DEFAULT_ORG, project_id


async def append_entry(conn: Conn, e: EntryInput) -> tuple[int, str]:
    """Append one entry to its project's chain.

    The payload is redacted and stored apart (so it can be erased on request); only its hash
    enters the chain. Chains are per project, so projects never queue behind each other.
    """
    org, project_id = await _place(conn, e)
    # A task of a project that was dropped belongs to another organization too.
    task_id = e.task_id if project_id or not e.project_id else None
    if project_id:
        chain_key = project_id
    else:
        row = await fetchone(conn, "SELECT system_chain FROM orgs WHERE id = %s", (org,))
        chain_key = row["system_chain"] if row else SYSTEM_CHAIN
    content = redact(e.payload)
    payload_hash = sha256(canonical_json(content))
    payload_id = str(uuid4())
    await conn.execute("INSERT INTO payloads (id, content) VALUES (%s, %s)", (payload_id, Jsonb(content)))

    await conn.execute(
        "INSERT INTO entry_chain_heads (chain_key, last_hash) VALUES (%s, %s) ON CONFLICT DO NOTHING", (chain_key, GENESIS)
    )
    head = await fetchone(conn, "SELECT last_hash FROM entry_chain_heads WHERE chain_key = %s FOR UPDATE", (chain_key,))
    prev_hash = head["last_hash"] if head else GENESIS

    at = datetime.now(UTC)
    fields = {
        "chain_key": chain_key,
        "project_id": project_id,
        "task_id": task_id,
        "agent_id": e.agent_id,
        "actor": e.actor,
        "mandate_chain": e.mandate_chain,
        "action": e.action,
        "payload_hash": payload_hash,
        "outcome": e.outcome,
        "at": iso(at),
        "prev_hash": prev_hash,
    }
    entry_hash = _entry_hash(fields)
    row = await fetchone(
        conn,
        """INSERT INTO entries (chain_key, project_id, task_id, agent_id, actor, mandate_chain, action, payload_hash,
                                payload_ref, outcome, at, prev_hash, hash, org_id)
           VALUES (%s, %s, %s, %s, %s, %s::uuid[], %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (
            chain_key,
            project_id,
            task_id,
            e.agent_id,
            e.actor,
            e.mandate_chain,
            e.action,
            payload_hash,
            payload_id,
            e.outcome,
            at,
            prev_hash,
            entry_hash,
            org,
        ),
    )
    await conn.execute("UPDATE entry_chain_heads SET last_hash = %s WHERE chain_key = %s", (entry_hash, chain_key))
    assert row is not None
    return row["id"], entry_hash


@dataclass
class ChainVerdict:
    chain_key: str
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None


async def verify_entry_chain(conn: Conn, chain_key: str) -> ChainVerdict:
    """Recompute a chain from genesis. Erased payloads are skipped; their hash still links the chain."""
    rows = await fetchall(
        conn,
        """SELECT e.*, p.content, p.erased_at FROM entries e LEFT JOIN payloads p ON p.id = e.payload_ref
           WHERE e.chain_key = %s ORDER BY e.id""",
        (chain_key,),
    )
    prev = GENESIS
    for r in rows:

        def fail(reason: str, r: Any = r) -> ChainVerdict:
            return ChainVerdict(chain_key, False, len(rows), r["id"], reason)

        if r["prev_hash"] != prev:
            return fail("prev_hash does not match the previous entry")
        recomputed = _entry_hash(
            {
                "chain_key": r["chain_key"],
                "project_id": r["project_id"],
                "task_id": str(r["task_id"]) if r["task_id"] else None,
                "agent_id": r["agent_id"],
                "actor": r["actor"],
                "mandate_chain": [str(x) for x in r["mandate_chain"]],
                "action": r["action"],
                "payload_hash": r["payload_hash"],
                "outcome": r["outcome"],
                "at": iso(r["at"]),
                "prev_hash": r["prev_hash"],
            }
        )
        if recomputed != r["hash"]:
            return fail("entry contents do not match its hash")
        if r["erased_at"] is None and sha256(canonical_json(r["content"])) != r["payload_hash"]:
            return fail("payload does not match payload_hash")
        prev = r["hash"]
    head = await fetchone(conn, "SELECT last_hash FROM entry_chain_heads WHERE chain_key = %s", (chain_key,))
    if rows and (head is None or head["last_hash"] != prev):
        return ChainVerdict(chain_key, False, len(rows), None, "chain head does not match the last entry (entries missing?)")
    return ChainVerdict(chain_key, True, len(rows))


async def erase_payload(conn: Conn, entry_id: int) -> bool:
    """PDPA erasure: drop the payload. The entry and its hash stay, so the chain still verifies."""
    cur = await conn.execute(
        """UPDATE payloads SET content = NULL, erased_at = now()
           WHERE id = (SELECT payload_ref FROM entries WHERE id = %s) AND erased_at IS NULL""",
        (entry_id,),
    )
    return cur.rowcount > 0
