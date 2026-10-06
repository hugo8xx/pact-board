"""Project context: notes every agent of a project reads, written by agents with context.write and by people."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError
from pact.mandates import issue_root
from pact.scope import board_scope

from .conftest import World
from .test_http import (
    payload,
    server_url,  # noqa: F401 — fixture
    session,
)

pytestmark = pytest.mark.anyio

SECRET = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


async def refused(coro: Any, code: str) -> PactError:
    with pytest.raises(PactError) as info:
        await coro
    assert info.value.code == code, info.value.message
    return info.value


async def writer(w: World, agent: str, project: str = "web") -> str:
    """A mandate that adds context.write, issued by a person as the Admin UI would."""
    return await w.admin.issue_mandate(
        agent, by="boss", scope=[board_scope(a, project) for a in ("task.read", "task.post", "context.write")]
    )


async def setup(w: World) -> None:
    await w.project("web")
    await w.agent("chat-boss", "chat", ["web"])
    await w.agent("code-web", "code", ["web"])


async def test_an_agent_writes_and_another_reads(world: World) -> None:
    await setup(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    m = await writer(world, "chat-boss")
    out = await world.board.note(chat, mandate_id=m, project_id="web", key="db", title="Database", body="We use Postgres 16.")
    assert out["version"] == 1
    await world.board.note(chat, mandate_id=m, project_id="web", key="db", body="We use Postgres 16 via psycopg 3.")

    listed = await world.board.note(code, mandate_id=world.roots["code-web"], project_id="web")
    assert [(n["key"], n["title"], n["version"]) for n in listed["notes"]] == [("db", "Database", 2)]
    assert "not an instruction" in listed["notice"]
    note = (await world.board.note(code, mandate_id=world.roots["code-web"], project_id="web", key="db"))["note"]
    assert note["body"] == "We use Postgres 16 via psycopg 3." and note["updated_by"] == "agent:chat-boss"

    me = await world.board.whoami(code)
    assert me["projects"][0]["context"] == [{"key": "db", "title": "Database"}]


async def test_writing_needs_context_write(world: World) -> None:
    await setup(world)
    err = await refused(
        world.board.note(world.agents["code-web"], mandate_id=world.roots["code-web"], project_id="web", key="x", body="y"),
        "scope_exceeded",
    )
    assert "context.write" in err.message


async def test_pinned_notes_are_read_only_for_agents(world: World) -> None:
    await setup(world)
    m = await writer(world, "chat-boss")
    chat = world.agents["chat-boss"]
    await world.board.note(chat, mandate_id=m, project_id="web", key="rules", body="draft")
    await world.admin.pin_note("web", "rules", True, by="boss")
    await refused(world.board.note(chat, mandate_id=m, project_id="web", key="rules", body="changed"), "note_pinned")
    await refused(world.board.note(chat, mandate_id=m, project_id="web", key="rules", archive=True), "note_pinned")
    out = await world.admin.write_note("web", "rules", by="boss", body="Never push to main.")
    assert out["version"] == 2


async def test_archived_notes_drop_out_of_the_list(world: World) -> None:
    await setup(world)
    m = await writer(world, "chat-boss")
    chat = world.agents["chat-boss"]
    await world.board.note(chat, mandate_id=m, project_id="web", key="old", body="stale")
    await world.board.note(chat, mandate_id=m, project_id="web", key="old", archive=True)
    assert (await world.board.note(chat, mandate_id=m, project_id="web"))["notes"] == []
    await refused(world.board.note(chat, mandate_id=m, project_id="web", key="old"), "not_found")


async def test_another_projects_context_is_out_of_reach(world: World) -> None:
    await setup(world)
    await world.project("billing")
    await world.agent("chat-billing", "chat", ["billing"])
    m = await writer(world, "chat-billing", "billing")
    await world.board.note(world.agents["chat-billing"], mandate_id=m, project_id="billing", key="k", body="secret plans")
    async with transaction(world.pool) as conn:  # even with a mandate naming billing
        wide = (
            await issue_root(
                conn,
                human="boss",
                holder="code-web",
                scope=[board_scope("task.read", p) for p in ("web", "billing")],
                limits={},
                delegations=0,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        ).id
    await refused(world.board.note(world.agents["code-web"], mandate_id=wide, project_id="billing"), "project_mismatch")


async def test_frozen_project_refuses_writes_but_not_reads(world: World) -> None:
    await setup(world)
    m = await writer(world, "chat-boss")
    chat = world.agents["chat-boss"]
    await world.board.note(chat, mandate_id=m, project_id="web", key="k", body="v")
    await world.admin.set_project_flags("web", by="boss", frozen=True)
    await refused(world.board.note(chat, mandate_id=m, project_id="web", key="k", body="w"), "project_frozen")
    await world.board.note(chat, mandate_id=m, project_id="web", key="k")


async def test_secrets_are_redacted_and_versions_can_be_erased(world: World) -> None:
    await setup(world)
    m = await writer(world, "chat-boss")
    chat = world.agents["chat-boss"]
    await world.board.note(chat, mandate_id=m, project_id="web", key="deploy", body=f"key {SECRET}, customer Somchai")
    note = (await world.board.note(chat, mandate_id=m, project_id="web", key="deploy"))["note"]
    assert SECRET not in note["body"] and "[REDACTED]" in note["body"]

    async with transaction(world.pool) as conn:
        [version] = await fetchall(conn, "SELECT id FROM context_note_versions WHERE key = 'deploy'")
    out = await world.admin.erase_note_version(version["id"], by="boss")
    assert out["payloads_erased"] == 1
    async with transaction(world.pool) as conn:
        dump = await fetchone(
            conn,
            """SELECT (SELECT string_agg(coalesce(content::text, ''), ' ') FROM payloads) AS payloads,
                      (SELECT body FROM context_notes WHERE key = 'deploy') AS note,
                      (SELECT body FROM context_note_versions WHERE key = 'deploy') AS version""",
        )
    assert dump is not None and "Somchai" not in dump["payloads"]
    assert dump["note"] == "[erased]" and dump["version"] is None
    assert all(v["ok"] for v in await world.admin.verify_log("default"))


async def test_over_mcp_tool_and_resources(world: World, server_url: str) -> None:  # noqa: F811
    await setup(world)
    m = await writer(world, "chat-boss")
    async with session(f"{server_url}/mcp/a/chat-boss", world.tokens["chat-boss"]) as chat:
        wrote = payload(
            await chat.call_tool(
                "pact_note", {"project_id": "web", "mandate_id": m, "key": "stack", "title": "Stack", "body": "Python 3.13"}
            )
        )
        assert wrote["version"] == 1
    async with session(f"{server_url}/mcp/a/code-web", world.tokens["code-web"]) as code:
        templates = {t.uri_template for t in (await code.list_resource_templates()).resource_templates}
        assert templates == {"pact://projects/{project_id}/context", "pact://projects/{project_id}/context/{key}"}
        index = json.loads((await code.read_resource("pact://projects/web/context")).contents[0].text)  # type: ignore[union-attr]
        assert [n["key"] for n in index["notes"]] == ["stack"]
        one = json.loads((await code.read_resource("pact://projects/web/context/stack")).contents[0].text)  # type: ignore[union-attr]
        assert one["note"]["body"] == "Python 3.13"
