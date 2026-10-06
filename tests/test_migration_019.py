"""Migration 019 moves a single-organization board into the organization 'default' without
changing anything a person or agent sees, and keeps every existing log chain verifiable."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import psycopg
import pytest

from pact.admin import Admin
from pact.db import create_pool, fetchall, fetchone, migrate, transaction
from pact.entries import verify_entry_chain

pytestmark = pytest.mark.anyio

SCHEMA = "migration_019"


@pytest.fixture
async def old_board() -> AsyncIterator[object]:
    """A board in its own schema, migrated up to 018 (the release before organizations)."""
    url = os.environ["DATABASE_URL"]
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE; CREATE SCHEMA {SCHEMA}")
    sep = "&" if "?" in url else "?"
    pool = create_pool(f"{url}{sep}options=-csearch_path%3D{SCHEMA}")
    await pool.open()
    await migrate(pool, upto="018_human_disabled.sql")
    yield pool
    await pool.close()
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {SCHEMA} CASCADE")


async def _old_entry(conn: object, chain_key: str, project_id: str | None, action: str) -> None:
    """Append an entry the way the release before organizations did (no org_id column yet)."""
    from uuid import uuid4

    from psycopg.types.json import Jsonb

    from pact.crypto import canonical_json, iso, sha256
    from pact.entries import GENESIS, _entry_hash

    c = conn  # type: ignore[assignment]
    head = await fetchone(c, "SELECT last_hash FROM entry_chain_heads WHERE chain_key = %s", (chain_key,))  # type: ignore[arg-type]
    prev = head["last_hash"] if head else GENESIS
    payload, pid, at = {"x": 1}, str(uuid4()), datetime.now(UTC)
    phash = sha256(canonical_json(payload))
    fields = {
        "chain_key": chain_key,
        "project_id": project_id,
        "task_id": None,
        "agent_id": None,
        "actor": "human:boss",
        "mandate_chain": [],
        "action": action,
        "payload_hash": phash,
        "outcome": "ok",
        "at": iso(at),
        "prev_hash": prev,
    }
    h = _entry_hash(fields)
    await c.execute("INSERT INTO payloads (id, content) VALUES (%s, %s)", (pid, Jsonb(payload)))  # type: ignore[attr-defined]
    await c.execute(  # type: ignore[attr-defined]
        """INSERT INTO entries (chain_key, project_id, actor, action, payload_hash, payload_ref, outcome, at, prev_hash, hash)
           VALUES (%s, %s, 'human:boss', %s, %s, %s, 'ok', %s, %s, %s)""",
        (chain_key, project_id, action, phash, pid, at, prev, h),
    )
    await c.execute(  # type: ignore[attr-defined]
        """INSERT INTO entry_chain_heads (chain_key, last_hash) VALUES (%s, %s)
           ON CONFLICT (chain_key) DO UPDATE SET last_hash = EXCLUDED.last_hash""",
        (chain_key, h),
    )


async def test_an_existing_board_moves_into_the_default_organization(old_board: object) -> None:
    pool = old_board
    async with transaction(pool) as conn:  # type: ignore[arg-type]
        # The data the previous release left behind, written the way it wrote it.
        await conn.execute("INSERT INTO humans (id, name, role) VALUES ('boss', 'Boss', 'owner')")
        await conn.execute("INSERT INTO projects (id, name, created_by) VALUES ('web', 'Web', 'boss')")
        await conn.execute(
            "INSERT INTO agent_roles (id, name, client, actions) VALUES ('reviewer', 'Reviewer', 'code', '{task.read}')"
        )
        await conn.execute("INSERT INTO agents (id, owner, client, role_id) VALUES ('code-web', 'boss', 'code', 'reviewer')")
        await conn.execute("INSERT INTO agent_projects (agent_id, project_id) VALUES ('code-web', 'web')")
        for chain, project in (("_system", None), ("web", "web"), ("web", "web"), ("_system", None)):
            await _old_entry(conn, chain, project, "test.action")

    assert await migrate(pool) == ["019_orgs.sql"]  # type: ignore[arg-type]

    async with transaction(pool) as conn:  # type: ignore[arg-type]
        org = await fetchone(conn, "SELECT id, name, halted, system_chain FROM orgs")
        assert org == {"id": "default", "name": "Default organization", "halted": False, "system_chain": "_system"}
        for table in ("humans", "projects", "agents", "agent_roles", "approval_actions", "entries", "agent_projects"):
            rows = await fetchall(conn, f"SELECT DISTINCT org_id FROM {table}")
            assert [r["org_id"] for r in rows] == ["default"], table
        for chain in ("_system", "web"):
            assert (await verify_entry_chain(conn, chain)).ok, chain
        assert (await fetchone(conn, "SELECT role_id FROM agents WHERE id = 'code-web'")) == {"role_id": "reviewer"}
        templates = await fetchall(conn, "SELECT id FROM role_templates ORDER BY position")
        assert [t["id"] for t in templates] == ["chat", "code", "gemini", "runner", "worker", "secretary", "design", "cowork"]
    # The new release keeps writing to the same chains, and they still verify.
    admin = Admin(pool)  # type: ignore[arg-type]
    await admin.set_halted(False, by="boss")
    await admin.save_role("reviewer", {"name": "Reviewer 2", "client": "code", "actions": ["task.read"]}, by="boss")
    assert all(v["ok"] for v in await admin.verify_log("default"))


async def test_an_agent_cannot_join_a_project_of_another_organization(old_board: object) -> None:
    pool = old_board
    await migrate(pool)  # type: ignore[arg-type]
    admin = Admin(pool)  # type: ignore[arg-type]
    await admin.add_human("boss", "Boss", "owner")
    await admin.add_project("web", "Web", by="boss")
    await admin.register_agent("code-web", by="boss", client="code", projects=["web"])
    async with transaction(pool) as conn:  # type: ignore[arg-type]
        await conn.execute("INSERT INTO orgs (id, name, system_chain) VALUES ('rival', 'Rival', '_system:rival')")
        await conn.execute("INSERT INTO projects (id, name, created_by, org_id) VALUES ('rival-web', 'R', 'boss', 'rival')")
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        async with transaction(pool) as conn:  # type: ignore[arg-type]
            await conn.execute("INSERT INTO agent_projects (agent_id, project_id) VALUES ('code-web', 'rival-web')")
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        async with transaction(pool) as conn:  # type: ignore[arg-type]
            # A role of another organization cannot be given to an agent.
            await conn.execute(
                """INSERT INTO agent_roles (org_id, id, name, client, actions)
                   VALUES ('rival', 'spy', 'Spy', 'code', '{task.read}')"""
            )
            await conn.execute("UPDATE agents SET role_id = 'spy' WHERE id = 'code-web'")
