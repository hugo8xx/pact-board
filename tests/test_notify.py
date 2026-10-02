"""Notifications: written with the event, delivered to Slack by a separate sender."""

from typing import Any

import httpx
import pytest

from pact.db import fetchall, transaction
from pact.errors import PactError
from pact.notify import SlackSender, slack_message

from .conftest import HANDOFF, World

pytestmark = pytest.mark.anyio


async def setup(w: World) -> None:
    await w.project("web")
    await w.agent("chat-boss", "chat", ["web"])
    await w.agent("code-web", "code", ["web"])


async def rows(w: World) -> list[dict[str, Any]]:
    async with transaction(w.pool) as conn:
        return [
            dict(r)
            for r in await fetchall(
                conn, "SELECT kind, task_id::text AS task_id, agent_id, title, detail, sent_at FROM notifications ORDER BY id"
            )
        ]


async def delegated(w: World, title: str = "job", **kw: Any) -> tuple[str, str]:
    t = await w.board.post(
        w.agents["chat-boss"], project_id="web", title=title, mandate_id=w.roots["chat-boss"], delegate_to="code-web", **kw
    )
    await w.board.claim(w.agents["code-web"], task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    return t["task_id"], t["delegated_mandate_id"]


async def test_a_task_waiting_for_approval_notifies(world: World) -> None:
    await setup(world)
    t = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="ship it", action="deploy.web", mandate_id=world.roots["chat-boss"]
    )
    [row] = await rows(world)
    assert row["kind"] == "approval_needed" and row["task_id"] == t["task_id"] and row["detail"] == "deploy.web"


async def test_plain_posts_do_not_notify(world: World) -> None:
    await setup(world)
    await world.board.post(world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"])
    assert await rows(world) == []


async def test_defer_and_questions_notify_with_redacted_short_text(world: World) -> None:
    await setup(world)
    code = world.agents["code-web"]
    task_id, child = await delegated(world, title="rotate sk-ant-abcdefghijklmnopqrstuvwxyz key")
    await world.board.report(
        code, task_id=task_id, status="input_required", mandate_id=child, result="Which region?\nmore lines " + "x" * 500
    )
    [question] = await rows(world)
    assert question["kind"] == "question"
    assert "sk-ant" not in question["title"] and "[REDACTED]" in question["title"]
    assert question["detail"] == "Which region?"  # first line only, never the whole result

    other, child2 = await delegated(world, title="needs prod")
    await world.board.defer(code, task_id=other, reason="needs deploy." + "y" * 400, mandate_id=child2)
    deferred = (await rows(world))[-1]
    assert deferred["kind"] == "deferred" and len(deferred["detail"]) <= 300


async def test_closing_a_top_level_task_notifies_but_subtasks_do_not(world: World) -> None:
    await setup(world)
    await world.agent("code-b", "code", ["web"])
    code = world.agents["code-web"]
    task_id, child = await delegated(
        world, child_scope=["task.work@project:web", "task.read@project:web", "task.post@project:web"]
    )
    sub = await world.board.post(
        code, project_id="web", title="sub", mandate_id=child, delegate_to="code-b", parent_task_id=task_id
    )
    await world.board.claim(world.agents["code-b"], task_id=sub["task_id"], mandate_id=sub["delegated_mandate_id"])
    await world.board.report(
        world.agents["code-b"], task_id=sub["task_id"], status="completed", mandate_id=sub["delegated_mandate_id"], result=HANDOFF
    )
    assert await rows(world) == []
    await world.board.report(code, task_id=task_id, status="completed", mandate_id=child, result=HANDOFF)
    [row] = await rows(world)
    assert row["kind"] == "task_closed" and row["detail"] == "completed" and row["agent_id"] == "code-web"


async def test_a_refused_call_leaves_no_notification(world: World) -> None:
    await setup(world)
    task_id, child = await delegated(world)
    with pytest.raises(PactError):
        await world.board.report(world.agents["code-web"], task_id=task_id, status="completed", mandate_id=child, result="done")
    assert await rows(world) == []


def test_slack_message_links_the_task_and_escapes_control_characters() -> None:
    msg = slack_message(
        {"kind": "deferred", "project_id": "web", "task_id": "t1", "agent_id": "code-web", "title": "a <b> & c", "detail": "x>y"},
        "https://admin.example/",
    )
    assert msg["text"].startswith("*ส่งกลับให้คนตัดสิน* · web · <https://admin.example/tasks/t1|a &lt;b&gt; &amp; c>")
    assert "> x&gt;y" in msg["text"]


async def test_sender_delivers_once_and_backs_off_on_failure(world: World) -> None:
    await setup(world)
    await world.board.post(
        world.agents["chat-boss"], project_id="web", title="ship", action="deploy.web", mandate_id=world.roots["chat-boss"]
    )
    calls: list[dict[str, Any]] = []
    status = {"code": 500}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.read().decode())  # type: ignore[arg-type]
        return httpx.Response(status["code"], text="ok" if status["code"] == 200 else "boom")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sender = SlackSender(world.pool, "https://hooks.slack.test/x", admin_ui_url="https://admin.example", client=client)

    assert await sender.send_pending() == 0
    async with transaction(world.pool) as conn:
        [failed] = await fetchall(conn, "SELECT attempts, last_error, next_attempt_at > now() AS later FROM notifications")
    assert failed["attempts"] == 1 and "500" in failed["last_error"] and failed["later"]
    assert await sender.send_pending() == 0 and len(calls) == 1  # waits for its backoff

    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE notifications SET next_attempt_at = now()")
    status["code"] = 200
    assert await sender.send_pending() == 1
    assert await sender.send_pending() == 0 and len(calls) == 2  # never sent twice
    assert "https://admin.example/tasks/" in calls[-1]
    [row] = await rows(world)
    assert row["sent_at"] is not None
    await client.aclose()
