"""Notifications: written with the event, delivered to Slack by a separate sender."""

import json
from typing import Any

import httpx
import pytest

from pact.db import fetchall, transaction
from pact.errors import PactError
from pact.notify import SlackSender, slack_message, sweep_expiring

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
    header, body, context, actions = msg["blocks"]
    assert header["text"]["text"] == "↩️ ส่งกลับให้คนตัดสิน"
    assert body["text"]["text"] == "*<https://admin.example/tasks/t1|a &lt;b&gt; &amp; c>*\nx&gt;y"
    assert context["elements"][0]["text"] == "web · โดย code-web"
    assert actions["elements"][0]["url"] == "https://admin.example/tasks/t1"
    assert msg["text"] == "↩️ ส่งกลับให้คนตัดสิน · a <b> & c"  # the phone notification line


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


async def test_a_completed_brief_goes_whole_without_its_handoff(world: World) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])
    await world.agent(
        "sec-web", "runner", ["web"], scope=["task.read@project:web", "task.post@project:web", "report.brief@project:web"]
    )
    t = await world.board.post(
        world.agents["sec-web"], project_id="web", title="Brief", action="report.brief", mandate_id=world.roots["sec-web"]
    )
    await world.board.claim(world.agents["sec-web"], task_id=t["task_id"], mandate_id=world.roots["sec-web"])
    brief = (
        "Good morning\n\nWaiting for you (1)\n1. Approve the plan   token=sk-ant-api03-abcdefghijklmnopqrstuv"
        "\n\n## Handoff\n- Done: brief"
    )
    await world.board.report(
        world.agents["sec-web"], task_id=t["task_id"], status="completed", mandate_id=world.roots["sec-web"], result=brief
    )
    [row] = await rows(world)
    assert row["kind"] == "brief" and row["detail"].startswith("Good morning\n\nWaiting for you (1)\n1. Approve the plan")
    assert "Handoff" not in row["detail"] and "sk-ant-api03" not in row["detail"]
    blocks = slack_message({**row, "project_id": "web"}, None)["blocks"]
    assert blocks[0]["text"]["text"] == "📋 รายงานประจำวัน"
    assert blocks[2]["text"]["text"].startswith("Good morning\n\nWaiting for you (1)")


async def test_list_reports_the_head_of_the_board(world: World) -> None:
    await setup(world)
    empty = await world.board.list_tasks(world.agents["code-web"], mandate_id=world.roots["code-web"])
    await delegated(world)
    after = await world.board.list_tasks(world.agents["code-web"], mandate_id=world.roots["code-web"], filter="mine", limit=1)
    assert empty["head"] == 0 and after["head"] > 0


# ── mandates and tokens running out ───────────────────────────────────────────


async def sweep(w: World) -> int:
    async with transaction(w.pool) as conn:
        return await sweep_expiring(conn, 48)


async def test_expiring_root_mandates_and_tokens_are_announced_once(world: World) -> None:
    await world.project("web")
    await world.agent("runner-web", "runner", ["web"], mandate_days=1, token_days=1)
    await world.agent("code-web", "code", ["web"])  # 30 days: nothing to say
    assert await sweep(world) == 2
    assert await sweep(world) == 0
    found = await rows(world)
    assert {r["kind"] for r in found} == {"expiring"} and {r["agent_id"] for r in found} == {"runner-web"}
    titles = sorted(r["title"] for r in found)
    assert titles[0].startswith("runner-web: token จะหมดอายุ") and titles[1].startswith("runner-web: ใบมอบอำนาจราก จะหมดอายุ")
    assert slack_message({**found[0], "project_id": "web"}, None)["text"].startswith("⏳ ใกล้หมดอายุ · runner-web")


async def test_expired_is_announced_but_old_news_is_not(world: World) -> None:
    await world.project("web")
    await world.agent("runner-web", "runner", ["web"], mandate_days=1, token_days=1)
    await world.agent("old-web", "runner", ["web"], mandate_days=1, token_days=1)
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE mandates SET expires_at = now() - interval '1 hour' WHERE holder = 'runner-web'")
        await conn.execute("UPDATE agent_tokens SET expires_at = now() - interval '1 hour' WHERE agent_id = 'runner-web'")
        await conn.execute("UPDATE mandates SET expires_at = now() - interval '3 days' WHERE holder = 'old-web'")
        await conn.execute("UPDATE agent_tokens SET expires_at = now() - interval '3 days' WHERE agent_id = 'old-web'")
    assert await sweep(world) == 2
    assert {(r["kind"], r["agent_id"]) for r in await rows(world)} == {("expired", "runner-web")}


async def test_a_renewed_mandate_and_a_paused_agent_say_nothing(world: World) -> None:
    await world.project("web")
    await world.agent("runner-web", "runner", ["web"], mandate_days=1, token_days=30)
    await world.agent("paused-web", "runner", ["web"], mandate_days=1, token_days=1)
    await world.admin.set_agent_status("paused-web", "paused", by="boss")
    await world.admin.issue_mandate("runner-web", by="boss", scope=["task.read@project:web", "task.work@project:web"], days=7)
    assert await sweep(world) == 0


async def test_a_structured_brief_becomes_one_card_with_a_button_per_item(world: World) -> None:
    await world.project("web")
    await world.agent(
        "sec-web", "runner", ["web"], scope=["task.read@project:web", "task.post@project:web", "report.brief@project:web"]
    )
    sec, root = world.agents["sec-web"], world.roots["sec-web"]
    t = await world.board.post(sec, project_id="web", title="รายงานประจำวัน 2026-10-06", action="report.brief", mandate_id=root)
    await world.board.claim(sec, task_id=t["task_id"], mandate_id=root)
    other = "11111111-2222-3333-4444-555555555555"
    report = {
        "greeting": "สวัสดีครับ",
        "sections": [
            {"title": "รอคุณตัดสิน (1)", "items": [{"text": "อนุมัติแผน token=sk-ant-api03-abcdefghijklmnopqrstuv", "task_id": other}]},
            {"title": "ความคืบหน้า", "items": [{"text": "R3 เสร็จ"}, {"text": "bad id", "task_id": "not-a-uuid"}]},
            {"title": "", "items": [{"text": "no title, dropped"}]},
        ],
    }
    result = {"report": report, "handoff": "- Done: brief", "text": "fallback"}
    await world.board.report(sec, task_id=t["task_id"], status="completed", mandate_id=root, result=result)
    [row] = await rows(world)
    stored = json.loads(row["detail"])
    assert [s["title"] for s in stored["sections"]] == ["รอคุณตัดสิน (1)", "ความคืบหน้า"]
    assert "sk-ant-api03" not in row["detail"] and stored["sections"][1]["items"][1] == {"text": "bad id"}

    msg = slack_message({**row, "project_id": "web"}, "https://admin.example")
    kinds = [b["type"] for b in msg["blocks"]]
    assert kinds == [
        "header",
        "section",
        "divider",
        "section",
        "section",
        "divider",
        "section",
        "section",
        "divider",
        "context",
        "actions",
    ]
    item = msg["blocks"][4]
    assert item["text"]["text"].startswith("1. อนุมัติแผน") and item["accessory"]["url"] == f"https://admin.example/tasks/{other}"
    assert msg["blocks"][7]["text"]["text"] == "• R3 เสร็จ\n• bad id"
    assert msg["blocks"][-1]["elements"][0]["url"] == "https://admin.example/tasks"
    assert msg["text"] == "📋 สวัสดีครับ"


def test_a_card_never_exceeds_slack_limits() -> None:
    report = {"greeting": "g", "sections": [{"title": f"s{i}", "items": [{"text": "x" * 600}] * 10} for i in range(6)]}
    row = {
        "kind": "brief",
        "project_id": "web",
        "task_id": None,
        "agent_id": "sec",
        "title": "t" * 400,
        "detail": json.dumps(report),
    }
    msg = slack_message(row, "https://admin.example")
    assert len(msg["blocks"]) <= 50 and len(msg["blocks"][0]["text"]["text"]) <= 150
    assert all(len(b["text"]["text"]) <= 3000 for b in msg["blocks"] if b["type"] == "section")
