"""Migration 019 moves a single-organization board into the organization 'default' without
changing anything a person or agent sees, and keeps every existing log chain verifiable."""

import os
from collections.abc import AsyncIterator

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


async def test_an_existing_board_moves_into_the_default_organization(old_board: object) -> None:
    pool = old_board
    admin = Admin(pool)  # type: ignore[arg-type]
    await admin.add_human("boss", "Boss", "owner")
    await admin.add_project("web", "Web", by="boss")
    out = await admin.register_agent("code-web", by="boss", client="code", projects=["web"])
    await admin.set_halted(False, by="boss")  # an entry on the _system chain
    async with transaction(pool) as conn:  # type: ignore[arg-type]
        # The way the previous release stored a role (before roles had an organization).
        await conn.execute(
            "INSERT INTO agent_roles (id, name, client, actions) VALUES ('reviewer', 'Reviewer', 'code', '{task.read}')"
        )
        await conn.execute("UPDATE agents SET role_id = 'reviewer' WHERE id = 'code-web'")

    assert await migrate(pool) == ["019_orgs.sql"]  # type: ignore[arg-type]

    async with transaction(pool) as conn:  # type: ignore[arg-type]
        org = await fetchone(conn, "SELECT id, name, halted, system_chain FROM orgs")
        assert org == {"id": "default", "name": "Default organization", "halted": False, "system_chain": "_system"}
        for table in ("humans", "projects", "agents", "agent_roles", "approval_actions", "entries", "agent_projects"):
            rows = await fetchall(conn, f"SELECT DISTINCT org_id FROM {table}")
            assert [r["org_id"] for r in rows] == ["default"], table
        # Every chain written before the migration still verifies.
        chains = await fetchall(conn, "SELECT chain_key FROM entry_chain_heads")
        assert {c["chain_key"] for c in chains} >= {"_system", "web"}
        for c in chains:
            assert (await verify_entry_chain(conn, c["chain_key"])).ok, c["chain_key"]
        # Roles keep working: the agent's role, a new role, and the shipped templates for new orgs.
        assert (await fetchone(conn, "SELECT role_id FROM agents WHERE id = 'code-web'")) == {"role_id": "reviewer"}
        templates = await fetchall(conn, "SELECT id FROM role_templates ORDER BY position")
        assert [t["id"] for t in templates] == ["chat", "code", "gemini", "runner", "worker", "secretary", "design", "cowork"]
    await admin.save_role("reviewer", {"name": "Reviewer 2", "client": "code", "actions": ["task.read"]}, by="boss")
    assert out["root_mandate_id"]


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
