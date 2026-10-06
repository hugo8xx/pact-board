"""Everything a person sets up in the Admin UI can be changed later: people, an agent's role,
projects and owner, and an open task's text. What cannot change (ids, an agent's client) is
refused with a reason."""

from typing import Any

import pytest

from pact.board import Agent, agent_projects, get_agent
from pact.db import fetchone, transaction
from pact.errors import PactError

from .conftest import World

pytestmark = pytest.mark.anyio


async def refused(coro: Any, code: str) -> PactError:
    with pytest.raises(PactError) as info:
        await coro
    assert info.value.code == code, f"expected {code}, got {info.value.code}: {info.value.message}"
    return info.value


async def human(w: World, human_id: str) -> dict[str, Any]:
    async with transaction(w.pool) as conn:
        row = await fetchone(conn, "SELECT * FROM humans WHERE id = %s", (human_id,))
    assert row
    return dict(row)


async def agent_of(w: World, agent_id: str) -> Agent:
    async with transaction(w.pool) as conn:
        agent = await get_agent(conn, agent_id)
    assert agent
    return agent


async def scope_of(w: World, agent_id: str) -> list[str]:
    async with transaction(w.pool) as conn:
        row = await fetchone(
            conn, "SELECT m.scope FROM agents a JOIN mandates m ON m.id = a.root_mandate_id WHERE a.id = %s", (agent_id,)
        )
    assert row
    return sorted(row["scope"])


# ── people ────────────────────────────────────────────────────────────────────


async def test_a_person_is_edited_and_a_new_email_unpins_their_sign_in(world: World) -> None:
    await world.admin.add_human("vic", "Vic", "viewer", by="boss", email="vic@example.com")
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE humans SET auth_issuer = 'https://id.example', auth_sub = 's1' WHERE id = 'vic'")
    await world.admin.update_human("vic", by="boss", name="Victoria", role="approver")
    row = await human(world, "vic")
    assert row["name"] == "Victoria" and row["role"] == "approver" and row["auth_sub"] == "s1"  # same email: still pinned
    await world.admin.update_human("vic", by="boss", email="victoria@example.com")
    row = await human(world, "vic")
    assert row["email"] == "victoria@example.com" and row["auth_sub"] is None and row["auth_issuer"] is None
    await refused(world.admin.update_human("vic", by="boss", role="king"), "invalid_request")  # type: ignore[arg-type]
    await refused(world.admin.update_human("vic", by="boss", name="  "), "invalid_request")
    await refused(world.admin.update_human("nobody", by="boss", name="X"), "not_found")
    await refused(world.admin.update_human("boss", by="vic", name="X"), "forbidden")  # only an owner edits people


async def test_a_disabled_person_can_do_nothing_until_enabled(world: World) -> None:
    await world.project("web")
    await world.admin.add_human("ann", "Ann", "approver", by="boss")
    await world.admin.update_human("ann", by="boss", disabled=True)
    assert (await human(world, "ann"))["disabled_at"] is not None
    await refused(world.admin.hire("chat", "web", by="ann"), "forbidden")
    await world.admin.update_human("ann", by="boss", disabled=False)
    assert (await human(world, "ann"))["disabled_at"] is None
    assert (await world.admin.hire("chat", "web", by="ann"))["agent_id"] == "chat-web"


async def test_the_board_keeps_one_active_owner(world: World) -> None:
    await refused(world.admin.update_human("boss", by="boss", role="approver"), "invalid_request")
    await refused(world.admin.update_human("boss", by="boss", disabled=True), "invalid_request")
    await world.admin.add_human("eve", "Eve", "owner", by="boss")
    await world.admin.update_human("boss", by="eve", role="approver")
    assert (await human(world, "boss"))["role"] == "approver"


# ── agents ────────────────────────────────────────────────────────────────────


async def test_an_agent_moves_to_other_projects_with_a_fresh_mandate(world: World) -> None:
    await world.project("web")
    await world.project("app")
    await world.admin.hire("gemini", "web", by="boss", agent_id="gemini-web")
    before = await scope_of(world, "gemini-web")
    out = await world.admin.update_agent("gemini-web", by="boss", projects=["web", "app"])
    assert out["projects"] == ["app", "web"] and out["revoked_mandates"] == 1
    after = await scope_of(world, "gemini-web")
    assert "task.work@project:app" in after and "task.work@project:web" in after and after != before
    async with transaction(world.pool) as conn:
        assert {p.id for p in await agent_projects(conn, "gemini-web")} == {"web", "app"}


async def test_project_rules_still_hold_when_moving(world: World) -> None:
    await world.project("web")
    await world.project("app")
    await world.admin.hire("code", "web", by="boss")
    await refused(world.admin.update_agent("code-web", by="boss", projects=["web", "app"]), "invalid_request")
    await refused(world.admin.update_agent("code-web", by="boss", projects=["nowhere"]), "not_found")
    await refused(world.admin.update_agent("code-web", by="boss", projects=[]), "project_required")
    await world.agent("old-web", "code", ["web"])  # registered by hand, no role
    await refused(world.admin.update_agent("old-web", by="boss", projects=["app"]), "invalid_request")


async def test_an_agent_changes_owner_and_nothing_else(world: World) -> None:
    await world.project("web")
    await world.admin.add_human("ann", "Ann", "approver", by="boss")
    await world.admin.hire("code", "web", by="boss")
    before = await scope_of(world, "code-web")
    out = await world.admin.update_agent("code-web", by="boss", owner="ann")
    assert out["owner"] == "ann" and "mandate_id" not in out and await scope_of(world, "code-web") == before
    assert (await agent_of(world, "code-web")).owner == "ann"
    await world.admin.add_human("bob", "Bob", "approver", by="boss")
    await world.admin.update_human("bob", by="boss", disabled=True)
    await refused(world.admin.update_agent("code-web", by="boss", owner="bob"), "not_found")
    await refused(world.admin.update_agent("code-web", by="boss", owner="ghost"), "not_found")


# ── tasks ─────────────────────────────────────────────────────────────────────


async def test_an_open_task_is_corrected_and_a_closed_one_is_not(world: World) -> None:
    await world.project("web")
    await world.admin.hire("code", "web", by="boss")
    agent = await agent_of(world, "code-web")
    async with transaction(world.pool) as conn:
        m = await fetchone(conn, "SELECT root_mandate_id FROM agents WHERE id = 'code-web'")
    assert m
    task = await world.board.post(agent, project_id="web", title="fix teh bug", body="old", mandate_id=str(m["root_mandate_id"]))
    tid = task["task_id"]
    await world.admin.edit_task(tid, by="boss", title="fix the bug", body="details")
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT title, body FROM tasks WHERE id = %s", (tid,))
    assert row and row["title"] == "fix the bug" and row["body"] == "details"
    await refused(world.admin.edit_task(tid, by="boss", title=" "), "invalid_request")
    await world.admin.add_human("vic", "Vic", "viewer", by="boss")
    await refused(world.admin.edit_task(tid, by="vic", title="x"), "forbidden")
    await world.admin.cancel_task(tid, by="boss")
    await refused(world.admin.edit_task(tid, by="boss", title="too late"), "invalid_request")
