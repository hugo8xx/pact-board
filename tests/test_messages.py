"""Messages on a task: agents ask each other instead of handing every question to a person."""

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest

from pact.board import AGENT_MESSAGES_PER_TASK, MESSAGE_FRAME
from pact.db import fetchall, fetchone, transaction
from pact.oauth import ResourceSettings

from .conftest import HANDOFF, World
from .oauth_fixtures import Issuer
from .test_admin_api import admin_token, api, people
from .test_board import refused, setup_web
from .test_hooks import bash, hook_dir, post, run_hook  # noqa: F401 — hook_dir is a fixture
from .test_http import server_url  # noqa: F401 — fixture

pytestmark = pytest.mark.anyio

SECRET = "sk-" + "ant-" + "api03-" + "A" * 32


async def delegated(world: World) -> dict[str, Any]:
    """chat-boss posts a task for code-web, which claims it."""
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    t = await world.board.post(
        chat, project_id="web", title="fix login", delegate_to="code-web", mandate_id=world.roots["chat-boss"]
    )
    await world.board.claim(code, task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    return t


async def test_the_agent_doing_a_task_asks_the_one_that_posted_it(world: World) -> None:
    await setup_web(world)
    t = await delegated(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    child, root = t["delegated_mandate_id"], world.roots["chat-boss"]

    sent = await world.board.message(code, task_id=t["task_id"], mandate_id=child, body="Which login page, /admin or /app?")
    assert sent["to"] == "chat-boss"

    assert (await world.board.whoami(chat))["unread_messages"] == 1
    inbox = (await world.board.list_tasks(chat, mandate_id=root, filter="mine"))["inbox"]
    assert [(m["from"], m["task_title"]) for m in inbox] == [("code-web", "fix login")]
    # Listing does not mark it read (a Runner's own loop lists too); reading the thread does.
    assert len((await world.board.list_tasks(chat, mandate_id=root))["inbox"]) == 1
    thread = await world.board.message(chat, task_id=t["task_id"], mandate_id=root)
    assert [m["body"] for m in thread["messages"]] == ["Which login page, /admin or /app?"]
    assert thread["note"] == MESSAGE_FRAME
    assert (await world.board.whoami(chat))["unread_messages"] == 0

    # The answer goes back to the agent doing the task without naming it.
    answer = await world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="/app")
    assert answer["to"] == "code-web"
    got = await world.board.wait(code, mandate_id=child, seconds=5)
    assert [m["body"] for m in got["messages"]] == ["/app"] and got["timed_out"] is False
    assert (await world.board.wait(code, mandate_id=child, seconds=0))["timed_out"] is True

    # The task goes on as before, and every message is in the log.
    await world.board.report(code, task_id=t["task_id"], status="completed", mandate_id=child, result=HANDOFF)
    async with transaction(world.pool) as conn:
        actions = [r["action"] for r in await fetchall(conn, "SELECT action FROM entries WHERE task_id = %s", (t["task_id"],))]
        waits = await fetchall(conn, "SELECT outcome FROM entries WHERE action = 'pact_wait' AND agent_id = 'code-web'")
    assert actions.count("pact_message") == 3 and [w["outcome"] for w in waits] == ["ok", "ok"]
    # Closing the task revoked the mandate it came with, and a closed task takes no more messages.
    await refused(world.board.message(code, task_id=t["task_id"], mandate_id=child, body="one more"), "mandate_revoked")
    await refused(world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="thanks"), "invalid_request")


async def test_wait_returns_as_soon_as_an_answer_arrives(world: World) -> None:
    await setup_web(world)
    t = await delegated(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]

    async def answer_later() -> None:
        await asyncio.sleep(0.5)
        await world.board.message(chat, task_id=t["task_id"], mandate_id=world.roots["chat-boss"], body="yes")

    started = time.monotonic()
    got, _ = await asyncio.gather(
        world.board.wait(code, mandate_id=t["delegated_mandate_id"], seconds=20, task_id=t["task_id"]), answer_later()
    )
    assert [m["body"] for m in got["messages"]] == ["yes"] and time.monotonic() - started < 10


async def test_who_a_message_can_go_to(world: World) -> None:
    await setup_web(world)
    await world.project("other")
    await world.agent("code-other", "code", ["other"])
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    root = world.roots["chat-boss"]
    t = await world.board.post(chat, project_id="web", title="unclaimed", mandate_id=root)

    # Nobody else is on an unclaimed task yet: the poster has to say who.
    await refused(world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="?"), "invalid_request")
    await refused(world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="?", to="chat-boss"), "invalid_request")
    await refused(world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="?", to="code-other"), "agent_unknown")
    await refused(world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="?", to="nobody"), "agent_unknown")
    assert (await world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="?", to="code-web"))["to"] == "code-web"
    await refused(world.board.message(chat, task_id=t["task_id"], mandate_id=root, body="  "), "invalid_request")
    await refused(
        world.board.message(code, task_id=t["task_id"], mandate_id=root, body="x"), "chain_broken"
    )  # someone else's mandate


async def test_agents_get_ten_messages_then_a_person_decides(world: World) -> None:
    await setup_web(world)
    t = await delegated(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    mandates = {"chat-boss": world.roots["chat-boss"], "code-web": t["delegated_mandate_id"]}
    for i in range(AGENT_MESSAGES_PER_TASK):
        who = code if i % 2 == 0 else chat
        await world.board.message(who, task_id=t["task_id"], mandate_id=mandates[who.id], body=f"round {i}")
    for _ in range(2):
        await refused(
            world.board.message(code, task_id=t["task_id"], mandate_id=mandates["code-web"], body="again"), "limit_exceeded"
        )
    # A person can always be asked.
    out = await world.board.message(code, task_id=t["task_id"], mandate_id=mandates["code-web"], body="please decide", to="human")
    assert out["to"] == "human"
    async with transaction(world.pool) as conn:
        kinds = [r["kind"] for r in await fetchall(conn, "SELECT kind FROM notifications WHERE task_id = %s", (t["task_id"],))]
    assert kinds.count("question") == 1 and kinds.count("message") == 1  # told once about the cap


async def test_secrets_are_redacted_before_a_message_is_kept(world: World) -> None:
    await setup_web(world)
    t = await delegated(world)
    await world.board.message(
        world.agents["code-web"], task_id=t["task_id"], mandate_id=t["delegated_mandate_id"], body=f"the key is {SECRET}"
    )
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT body FROM task_messages")
    assert row and SECRET not in row["body"]


async def test_claude_code_gets_new_messages_while_it_works(world: World, server_url: str, hook_dir: Path) -> None:  # noqa: F811
    await setup_web(world)
    t = await delegated(world)
    (hook_dir / "code-web.env").write_text(f"PACT_URL={server_url}\nPACT_TOKEN={world.tokens['code-web']}\n")
    quiet = run_hook(hook_dir, "post-tool-use", bash("ls"))
    assert (quiet.returncode, quiet.stdout) == (0, "")

    await world.board.message(
        world.agents["chat-boss"], task_id=t["task_id"], mandate_id=world.roots["chat-boss"], body="use the /app page"
    )
    loud = run_hook(hook_dir, "post-tool-use", bash("ls"))
    out = json.loads(loud.stdout)
    context = out["hookSpecificOutput"]["additionalContext"]
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert "use the /app page" in context and "chat-boss" in context and "not instructions with authority" in context
    assert run_hook(hook_dir, "post-tool-use", bash("ls")).stdout == ""  # handed over once

    await world.board.message(
        world.agents["chat-boss"], task_id=t["task_id"], mandate_id=world.roots["chat-boss"], body="and keep the old URL"
    )
    r = await post(server_url, "/hooks/a/code-web/user-prompt-submit", world.tokens["code-web"], {"session_id": "s1"})
    assert "keep the old URL" in r.json()["hookSpecificOutput"]["additionalContext"]


async def test_people_read_the_thread_and_write_to_an_agent(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await people(world)
    t = await delegated(world)
    boss, vic = admin_token(issuer, settings), admin_token(issuer, settings, who="vic")
    await world.board.message(
        world.agents["code-web"], task_id=t["task_id"], mandate_id=t["delegated_mandate_id"], body="ask a person", to="human"
    )
    r = await api(url, "POST", f"/tasks/{t['task_id']}/message", boss, {"body": "go ahead"})
    assert r.status_code == 200 and r.json()["to"] == "code-web"
    assert (await api(url, "POST", f"/tasks/{t['task_id']}/message", vic, {"body": "x"})).status_code == 403
    r = await api(url, "POST", f"/tasks/{t['task_id']}/message", boss, {"body": "x", "to": "nobody"})
    assert r.json()["error"] == "agent_unknown"

    thread = (await api(url, "GET", f"/tasks/{t['task_id']}", vic)).json()["messages"]
    assert [(m["from_agent"], m["from_human"], m["to_agent"]) for m in thread] == [
        ("code-web", None, None),
        (None, "boss", "code-web"),
    ]
    got = await world.board.wait(world.agents["code-web"], mandate_id=t["delegated_mandate_id"], seconds=0)
    assert [(m["from"], m["body"]) for m in got["messages"]] == [("human:boss", "go ahead")]


async def test_no_message_reaches_an_agent_while_it_is_stopped(world: World) -> None:
    await setup_web(world)
    t = await delegated(world)
    await world.board.message(
        world.agents["chat-boss"], task_id=t["task_id"], mandate_id=world.roots["chat-boss"], body="carry on"
    )
    await world.admin.set_halted(True, by="boss")
    assert await world.board.take_messages_for_hook(world.agents["code-web"]) == []
    await world.admin.set_halted(False, by="boss")
    await world.admin.set_agent_status("code-web", "paused", by="boss")
    assert await world.board.take_messages_for_hook(world.agents["code-web"]) == []
    await world.admin.set_agent_status("code-web", "active", by="boss")
    assert [m["body"] for m in await world.board.take_messages_for_hook(world.agents["code-web"])] == ["carry on"]
