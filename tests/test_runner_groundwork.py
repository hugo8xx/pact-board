"""Runner groundwork (R0): run and turn budgets that shrink down the mandate chain, per-agent
preferences, and a heads-up when work goes to an agent nothing can wake."""

from typing import Any

import pytest

from pact.db import fetchall, transaction
from pact.errors import PactError
from pact.scope import board_scope

from .conftest import HANDOFF, World

pytestmark = pytest.mark.anyio


async def refused(coro: Any, code: str) -> PactError:
    with pytest.raises(PactError) as info:
        await coro
    assert info.value.code == code, f"expected {code}, got {info.value.code}: {info.value.message}"
    return info.value


async def setup(w: World, limits: dict[str, float] | None = None) -> None:
    await w.project("web")
    await w.agent("chat-boss", "chat", ["web"])
    await w.agent("runner-web", "runner", ["web"], limits=limits or {"runs": 3, "turns": 100})


async def task_for_runner(w: World, title: str = "job") -> str:
    t = await w.board.post(w.agents["chat-boss"], project_id="web", title=title, mandate_id=w.roots["chat-boss"])
    return str(t["task_id"])


async def subtask(w: World, parent: str, limits: dict[str, float], title: str = "sub") -> dict[str, Any]:
    """The runner splits its work into a subtask for a worker under a narrower mandate of its own."""
    out = await w.board.post(
        w.agents["runner-web"],
        project_id="web",
        title=title,
        mandate_id=w.roots["runner-web"],
        parent_task_id=parent,
        delegate_to="worker-web",
        child_scope=[board_scope("task.work", "web"), board_scope("task.read", "web")],
        child_limits=limits,
    )
    return dict(out)


# ── budgets ───────────────────────────────────────────────────────────────────


async def test_claim_reserves_a_run_and_answers_with_the_budget(world: World) -> None:
    await setup(world)
    runner = world.agents["runner-web"]
    out = await world.board.claim(
        runner, task_id=await task_for_runner(world), mandate_id=world.roots["runner-web"], reserve={"runs": 1}
    )
    assert out["budget"] == {"runs": 2, "turns": 100}


async def test_no_runs_left_means_no_claim(world: World) -> None:
    await setup(world, {"runs": 1})
    runner = world.agents["runner-web"]
    first, second = await task_for_runner(world, "one"), await task_for_runner(world, "two")
    await world.board.claim(runner, task_id=first, mandate_id=world.roots["runner-web"], reserve={"runs": 1})
    await refused(
        world.board.claim(runner, task_id=second, mandate_id=world.roots["runner-web"], reserve={"runs": 1}), "limit_exceeded"
    )
    async with transaction(world.pool) as conn:
        [row] = await fetchall(conn, "SELECT status, assignee FROM tasks WHERE id = %s", (second,))
    assert row == {"status": "submitted", "assignee": None}  # the refused claim left the task free


async def test_reported_usage_is_recorded_even_past_the_ceiling(world: World) -> None:
    await setup(world, {"turns": 10})
    runner = world.agents["runner-web"]
    tid = await task_for_runner(world)
    await world.board.claim(runner, task_id=tid, mandate_id=world.roots["runner-web"])
    out = await world.board.report(
        runner, task_id=tid, status="working", mandate_id=world.roots["runner-web"], usage={"turns": 6}
    )
    assert out["budget"] == {"turns": 4} and "budget_exceeded" not in out
    out = await world.board.report(
        runner, task_id=tid, status="completed", mandate_id=world.roots["runner-web"], result=HANDOFF, usage={"turns": 7}
    )
    assert out["status"] == "completed"
    assert out["budget"] == {"turns": 0} and out["budget_exceeded"] == ["turns"]


async def test_usage_cannot_be_negative(world: World) -> None:
    await setup(world)
    runner = world.agents["runner-web"]
    tid = await task_for_runner(world)
    await world.board.claim(runner, task_id=tid, mandate_id=world.roots["runner-web"])
    await refused(
        world.board.report(runner, task_id=tid, status="working", mandate_id=world.roots["runner-web"], usage={"turns": -5}),
        "invalid_request",
    )
    await refused(
        world.board.claim(
            runner, task_id=await task_for_runner(world), mandate_id=world.roots["runner-web"], reserve={"runs": -1}
        ),
        "invalid_request",
    )


async def test_worker_budget_comes_out_of_the_parents(world: World) -> None:
    """A sub-agent needs no human approval while it stays inside the budget it was handed, and what
    it spends counts against every mandate above it."""
    await setup(world, {"runs": 3, "turns": 100})
    await world.agent("worker-web", "runner", ["web"])
    runner, worker = world.agents["runner-web"], world.agents["worker-web"]
    parent = await task_for_runner(world)
    await world.board.claim(runner, task_id=parent, mandate_id=world.roots["runner-web"], reserve={"runs": 1})

    await refused(subtask(world, parent, {"runs": 1, "turns": 101}), "limit_exceeded")  # more than the parent holds
    sub = await subtask(world, parent, {"runs": 1, "turns": 30})
    child = sub["delegated_mandate_id"]
    out = await world.board.claim(worker, task_id=sub["task_id"], mandate_id=child, reserve={"runs": 1})
    assert out["budget"] == {"runs": 0, "turns": 30}

    out = await world.board.report(
        worker, task_id=sub["task_id"], status="completed", mandate_id=child, result=HANDOFF, usage={"turns": 25}
    )
    assert out["budget"] == {"runs": 0, "turns": 5}
    async with transaction(world.pool) as conn:
        used = {
            (r["holder"], r["limit_key"]): float(r["used"])
            for r in await fetchall(
                conn, "SELECT m.holder, u.limit_key, u.used FROM limit_usage u JOIN mandates m ON m.id = u.mandate_id"
            )
        }
    assert used == {
        ("runner-web", "runs"): 2,
        ("runner-web", "turns"): 25,
        ("worker-web", "runs"): 1,
        ("worker-web", "turns"): 25,
    }


async def test_a_claim_without_limits_answers_no_budget(world: World) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])
    await world.agent("code-web", "code", ["web"])
    t = await world.board.post(world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"])
    out = await world.board.claim(world.agents["code-web"], task_id=t["task_id"], mandate_id=world.roots["code-web"])
    assert "budget" not in out


# ── preferences ───────────────────────────────────────────────────────────────


async def test_whoami_hands_the_agent_its_preferences(world: World) -> None:
    await setup(world)
    runner = world.agents["runner-web"]
    assert (await world.board.whoami(runner))["agent"]["preferences"] == {}
    prefs = {"language": "th", "report": "short, mobile first"}
    await world.admin.set_agent_preferences("runner-web", prefs, by="boss")
    assert (await world.board.whoami(runner))["agent"]["preferences"] == prefs


async def test_preferences_are_checked(world: World) -> None:
    await setup(world)
    await world.admin.add_human("vic", "Vic", "viewer", by="boss")
    await refused(world.admin.set_agent_preferences("runner-web", {"a": 1}, by="vic"), "forbidden")
    await refused(world.admin.set_agent_preferences("runner-web", ["not", "an", "object"], by="boss"), "invalid_request")
    await refused(world.admin.set_agent_preferences("runner-web", {"x": "y" * 5000}, by="boss"), "invalid_request")
    await refused(world.admin.set_agent_preferences("nobody", {}, by="boss"), "not_found")


# ── agents nothing can wake ───────────────────────────────────────────────────


async def test_delegating_to_a_wakeless_agent_tells_people(world: World) -> None:
    await setup(world)
    await world.agent("design-web", "design", ["web"])
    await world.board.post(
        world.agents["chat-boss"],
        project_id="web",
        title="draw it",
        mandate_id=world.roots["chat-boss"],
        delegate_to="design-web",
    )
    await world.board.post(
        world.agents["chat-boss"], project_id="web", title="run it", mandate_id=world.roots["chat-boss"], delegate_to="runner-web"
    )
    async with transaction(world.pool) as conn:
        rows = await fetchall(conn, "SELECT kind, title, detail FROM notifications ORDER BY id")
    assert rows == [
        {"kind": "awaiting_session", "title": "draw it", "detail": "design-web (design) starts it only when someone opens it"}
    ]


async def test_list_the_subtasks_of_a_task(world: World) -> None:
    await setup(world)
    chat, runner = world.agents["chat-boss"], world.agents["runner-web"]
    parent = await task_for_runner(world, "parent")
    other = await task_for_runner(world, "other")
    for title, under in (("a", parent), ("b", parent), ("c", other)):
        await world.board.post(chat, project_id="web", title=title, mandate_id=world.roots["chat-boss"], parent_task_id=under)
    listed = await world.board.list_tasks(runner, mandate_id=world.roots["runner-web"], filter="all", parent_task_id=parent)
    assert sorted(t["title"] for t in listed["tasks"]) == ["a", "b"]
    await refused(
        world.board.list_tasks(
            runner, mandate_id=world.roots["runner-web"], filter="all", parent_task_id="00000000-0000-0000-0000-000000000000"
        ),
        "not_found",
    )
