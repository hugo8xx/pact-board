"""Phase 1 done-criteria, one test (or a few) per criterion in the requirement document."""

import asyncio
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError
from pact.mandates import issue_root
from pact.scope import board_scope

from .conftest import World

pytestmark = pytest.mark.anyio


async def refused(coro: Any, code: str) -> PactError:
    with pytest.raises(PactError) as info:
        await coro
    assert info.value.code == code, f"expected {code}, got {info.value.code}: {info.value.message}"
    return info.value


async def setup_web(w: World) -> None:
    await w.project("web")
    await w.agent("chat-boss", "chat", ["web"])
    await w.agent("code-web", "code", ["web"])
    await w.agent("code-web-2", "gemini", ["web"])


# ── claims ────────────────────────────────────────────────────────────────────


async def test_parallel_claims_have_exactly_one_winner(world: World) -> None:
    await setup_web(world)
    chat, a, b = world.agents["chat-boss"], world.agents["code-web"], world.agents["code-web-2"]
    for _ in range(50):
        t = await world.board.post(chat, project_id="web", title="race", mandate_id=world.roots["chat-boss"])
        results = await asyncio.gather(
            world.board.claim(a, task_id=t["task_id"], mandate_id=world.roots["code-web"]),
            world.board.claim(b, task_id=t["task_id"], mandate_id=world.roots["code-web-2"]),
            return_exceptions=True,
        )
        wins = [r for r in results if isinstance(r, dict)]
        losses = [r for r in results if isinstance(r, PactError)]
        assert len(wins) == 1
        assert [e.code for e in losses] == ["already_claimed"]


async def test_post_only_clients_cannot_claim(world: World) -> None:
    await setup_web(world)
    t = await world.board.post(world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"])
    await refused(
        world.board.claim(world.agents["chat-boss"], task_id=t["task_id"], mandate_id=world.roots["chat-boss"]), "scope_exceeded"
    )


# ── mandate rules ─────────────────────────────────────────────────────────────


async def test_zero_delegations_cannot_delegate(world: World) -> None:
    await setup_web(world)
    await world.agent("chat-nodelegate", "chat", ["web"], delegations=0)
    await refused(
        world.board.post(
            world.agents["chat-nodelegate"],
            project_id="web",
            title="x",
            mandate_id=world.roots["chat-nodelegate"],
            delegate_to="code-web",
        ),
        "delegation_exhausted",
    )


async def test_child_scope_wider_than_parent_is_refused(world: World) -> None:
    await setup_web(world)
    await world.project("billing")
    await refused(
        world.board.post(
            world.agents["chat-boss"],
            project_id="web",
            title="x",
            mandate_id=world.roots["chat-boss"],
            delegate_to="code-web",
            child_scope=[board_scope("task.work", "billing")],
        ),
        "scope_exceeded",
    )
    await refused(
        world.board.post(
            world.agents["chat-boss"],
            project_id="web",
            title="x",
            mandate_id=world.roots["chat-boss"],
            delegate_to="code-web",
            child_scope=[board_scope("deploy.prod", "web")],
        ),
        "scope_exceeded",
    )


async def test_revoking_a_middle_mandate_stops_everything_below(world: World) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"], delegations=3, scope=[board_scope("task.*", "web")])
    await world.agent("code-a", "code", ["web"])
    await world.agent("code-b", "gemini", ["web"])
    chat, a, b = world.agents["chat-boss"], world.agents["code-a"], world.agents["code-b"]

    t1 = await world.board.post(
        chat,
        project_id="web",
        title="a's job",
        mandate_id=world.roots["chat-boss"],
        delegate_to="code-a",
        child_scope=[board_scope("task.*", "web")],
    )
    middle = t1["delegated_mandate_id"]
    t2 = await world.board.post(a, project_id="web", title="b's job", mandate_id=middle, delegate_to="code-b")
    grandchild = t2["delegated_mandate_id"]
    await world.board.claim(b, task_id=t2["task_id"], mandate_id=grandchild)

    out = await world.board.revoke(chat, mandate_id=middle)
    assert out["descendant_mandates"] == 1
    assert out["tasks_stopped"] == 2

    async with transaction(world.pool) as conn:
        statuses = {r["id"]: r["status"] for r in await fetchall(conn, "SELECT id::text, status FROM tasks")}
    assert statuses == {t1["task_id"]: "canceled", t2["task_id"]: "canceled"}
    err = await refused(world.board.list_tasks(b, mandate_id=grandchild), "mandate_revoked")
    assert err.mandate_id == middle  # the message names the link at fault


async def test_entries_trace_back_to_the_human_root(world: World) -> None:
    await setup_web(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    t = await world.board.post(chat, project_id="web", title="trace", mandate_id=world.roots["chat-boss"], delegate_to="code-web")
    await world.board.claim(code, task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    await world.board.report(code, task_id=t["task_id"], status="completed", mandate_id=t["delegated_mandate_id"], result="done")

    async with transaction(world.pool) as conn:
        entries = await fetchall(conn, "SELECT mandate_chain FROM entries WHERE task_id = %s", (t["task_id"],))
        assert len(entries) == 4  # post, claim, report, and the delegated mandate revoked on close
        for e in entries:
            root = await fetchone(
                conn, "SELECT issuer_kind, issuer, parent_id FROM mandates WHERE id = %s", (e["mandate_chain"][0],)
            )
            assert root == {"issuer_kind": "human", "issuer": "boss", "parent_id": None}


async def test_aggregate_limit_across_children(world: World) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"], limits={"thb": 100_000})
    for i in range(3):
        await world.agent(f"code-{i}", "gemini", ["web"])
    chat = world.agents["chat-boss"]
    children = []
    for i in range(3):
        t = await world.board.post(
            chat,
            project_id="web",
            title=f"split {i}",
            mandate_id=world.roots["chat-boss"],
            delegate_to=f"code-{i}",
            child_limits={"thb": 100_000},
            child_scope=[board_scope("task.post", "web"), board_scope("task.work", "web")],
        )
        children.append(t["delegated_mandate_id"])

    async def spend(i: int) -> Any:
        return await world.board.post(
            world.agents[f"code-{i}"], project_id="web", title="spend", mandate_id=children[i], cost={"thb": 40_000}
        )

    results = await asyncio.gather(*(spend(i) for i in range(3)), return_exceptions=True)
    assert sum(isinstance(r, dict) for r in results) == 2
    assert [r.code for r in results if isinstance(r, PactError)] == ["limit_exceeded"]


async def test_child_limit_above_parent_is_refused(world: World) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"], limits={"thb": 100})
    await world.agent("code-web", "code", ["web"])
    await refused(
        world.board.post(
            world.agents["chat-boss"],
            project_id="web",
            title="x",
            mandate_id=world.roots["chat-boss"],
            delegate_to="code-web",
            child_limits={"thb": 101},
        ),
        "limit_exceeded",
    )


async def test_tampered_mandate_breaks_the_chain(world: World) -> None:
    await setup_web(world)
    async with transaction(world.pool) as conn:
        await conn.execute(
            "UPDATE mandates SET scope = scope || %s::text WHERE id = %s", ("deploy.*@project:web", world.roots["code-web"])
        )
    await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=world.roots["code-web"]), "chain_broken")


async def test_mandate_of_another_agent_is_refused(world: World) -> None:
    await setup_web(world)
    await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=world.roots["chat-boss"]), "chain_broken")


async def test_expired_mandate(world: World) -> None:
    await setup_web(world)
    async with transaction(world.pool) as conn:
        mid = (
            await issue_root(
                conn,
                human="boss",
                holder="code-web",
                scope=[board_scope("task.read", "web")],
                limits={},
                delegations=0,
                expires_at=datetime.now(UTC) - timedelta(seconds=1),
            )
        ).id
    await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=mid), "mandate_expired")


# ── list ──────────────────────────────────────────────────────────────────────


async def test_since_cursor_never_returns_the_same_task_twice(world: World) -> None:
    await setup_web(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    for i in range(3):
        await world.board.post(chat, project_id="web", title=f"t{i}", mandate_id=world.roots["chat-boss"])
    first = await world.board.list_tasks(code, mandate_id=world.roots["code-web"])
    assert len(first["tasks"]) == 3
    again = await world.board.list_tasks(code, mandate_id=world.roots["code-web"], since=first["next_since"])
    assert again["tasks"] == []
    await world.board.post(chat, project_id="web", title="t3", mandate_id=world.roots["chat-boss"])
    newer = await world.board.list_tasks(code, mandate_id=world.roots["code-web"], since=first["next_since"])
    assert [t["title"] for t in newer["tasks"]] == ["t3"]


async def test_deferred_tasks_show_separately_and_resume(world: World) -> None:
    await setup_web(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    t = await world.board.post(chat, project_id="web", title="needs more", mandate_id=world.roots["chat-boss"])
    await world.board.defer(
        code,
        task_id=t["task_id"],
        reason="needs deploy",
        needed_scope=["deploy.web@project:web"],
        mandate_id=world.roots["code-web"],
    )
    listed = await world.board.list_tasks(chat, mandate_id=world.roots["chat-boss"], filter="all")
    assert [d["id"] for d in listed["deferred"]] == [t["task_id"]]
    assert listed["deferred"][0]["needed_scope"] == ["deploy.web@project:web"]

    await world.admin.resume_task(t["task_id"], by="boss")
    await world.board.claim(code, task_id=t["task_id"], mandate_id=world.roots["code-web"])  # same task, not a new one


# ── project isolation ─────────────────────────────────────────────────────────


async def test_code_agent_cannot_see_or_claim_another_project(world: World) -> None:
    await setup_web(world)
    await world.project("billing")
    await world.agent("chat-billing", "chat", ["billing"])
    t = await world.board.post(
        world.agents["chat-billing"], project_id="billing", title="billing job", mandate_id=world.roots["chat-billing"]
    )
    # A mandate that covers both projects still does not let a web-only agent touch billing.
    async with transaction(world.pool) as conn:
        wide = (
            await issue_root(
                conn,
                human="boss",
                holder="code-web",
                scope=[board_scope(a, p) for a in ("task.read", "task.work") for p in ("web", "billing")],
                limits={},
                delegations=0,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        ).id
    code = world.agents["code-web"]
    listed = await world.board.list_tasks(code, mandate_id=wide, filter="all")
    assert listed["tasks"] == []
    await refused(world.board.list_tasks(code, mandate_id=wide, project_id="billing"), "project_mismatch")
    await refused(world.board.claim(code, task_id=t["task_id"], mandate_id=wide), "project_mismatch")


async def test_post_without_project_is_refused(world: World) -> None:
    await setup_web(world)
    await refused(
        world.board.post(world.agents["chat-boss"], project_id=None, title="x", mandate_id=world.roots["chat-boss"]),
        "project_required",
    )


async def test_runner_never_touches_production(world: World) -> None:
    await setup_web(world)
    await world.agent("runner-web", "runner", ["web"])
    t = await world.board.post(world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"])
    await world.admin.set_project_flags("web", by="boss", production=True)
    await refused(
        world.board.claim(world.agents["runner-web"], task_id=t["task_id"], mandate_id=world.roots["runner-web"]),
        "project_mismatch",
    )
    with pytest.raises(PactError) as info:
        await world.agent("runner-web-2", "runner", ["web"])
    assert info.value.code == "project_mismatch"


# ── claims released, delegation targets, revoke rights ────────────────────────


async def test_stale_claim_is_released_and_old_holder_gets_claim_lost(world: World) -> None:
    await setup_web(world)
    chat, a, b = world.agents["chat-boss"], world.agents["code-web"], world.agents["code-web-2"]
    t = await world.board.post(chat, project_id="web", title="slow", mandate_id=world.roots["chat-boss"])
    await world.board.claim(a, task_id=t["task_id"], mandate_id=world.roots["code-web"])
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE task_activity SET at = now() - interval '31 minutes' WHERE task_id = %s", (t["task_id"],))
    await world.board.claim(b, task_id=t["task_id"], mandate_id=world.roots["code-web-2"])
    await world.board.report(b, task_id=t["task_id"], status="completed", result="b's work", mandate_id=world.roots["code-web-2"])
    await refused(
        world.board.report(a, task_id=t["task_id"], status="completed", result="a's work", mandate_id=world.roots["code-web"]),
        "claim_lost",
    )
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT result FROM tasks WHERE id = %s", (t["task_id"],))
    assert row == {"result": "b's work"}


async def test_heartbeat_keeps_the_claim(world: World) -> None:
    await setup_web(world)
    chat, a, b = world.agents["chat-boss"], world.agents["code-web"], world.agents["code-web-2"]
    t = await world.board.post(chat, project_id="web", title="slow", mandate_id=world.roots["chat-boss"])
    await world.board.claim(a, task_id=t["task_id"], mandate_id=world.roots["code-web"])
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE task_activity SET at = now() - interval '29 minutes' WHERE task_id = %s", (t["task_id"],))
    await world.board.report(a, task_id=t["task_id"], status="working", mandate_id=world.roots["code-web"])
    await refused(world.board.claim(b, task_id=t["task_id"], mandate_id=world.roots["code-web-2"]), "already_claimed")


async def test_delegated_task_only_for_its_target(world: World) -> None:
    await setup_web(world)
    chat = world.agents["chat-boss"]
    t = await world.board.post(
        chat, project_id="web", title="for code-web", mandate_id=world.roots["chat-boss"], delegate_to="code-web"
    )
    await refused(
        world.board.claim(world.agents["code-web-2"], task_id=t["task_id"], mandate_id=world.roots["code-web-2"]), "wrong_agent"
    )
    await refused(
        world.board.post(chat, project_id="web", title="x", mandate_id=world.roots["chat-boss"], delegate_to="nobody"),
        "agent_unknown",
    )
    assert "starts this when it next pulls work" in t["note"]


async def test_agents_revoke_only_what_they_issued(world: World) -> None:
    await setup_web(world)
    await refused(world.board.revoke(world.agents["code-web"], mandate_id=world.roots["chat-boss"]), "not_issuer")


# ── governance gates ──────────────────────────────────────────────────────────


async def test_pause_freeze_and_kill_switch(world: World) -> None:
    await setup_web(world)
    code, chat = world.agents["code-web"], world.agents["chat-boss"]
    await world.admin.set_agent_status("code-web", "paused", by="boss")
    await refused(world.board.list_tasks(code, mandate_id=world.roots["code-web"]), "agent_paused")
    await world.admin.set_agent_status("code-web", "active", by="boss")

    await world.admin.set_project_flags("web", by="boss", frozen=True)
    await refused(world.board.post(chat, project_id="web", title="x", mandate_id=world.roots["chat-boss"]), "project_frozen")
    await world.admin.set_project_flags("web", by="boss", frozen=False)

    await world.admin.set_halted(True, by="boss")
    await refused(world.board.whoami(chat), "system_halted")
    await world.admin.set_halted(False, by="boss")
    await world.board.whoami(chat)


async def test_approval_gate(world: World) -> None:
    await setup_web(world)
    await world.agent("code-deploy", "code", ["web"], scope=[board_scope(a, "web") for a in ("task.read", "deploy.*")])
    t = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="ship it", action="deploy.web", mandate_id=world.roots["chat-boss"]
    )
    assert t["status"] == "auth_required"
    code = world.agents["code-deploy"]
    await refused(world.board.claim(code, task_id=t["task_id"], mandate_id=world.roots["code-deploy"]), "approval_pending")
    await world.admin.approve_task(t["task_id"], by="boss")
    await world.board.claim(code, task_id=t["task_id"], mandate_id=world.roots["code-deploy"])


async def test_scope_exceeded_when_mandate_lacks_the_action(world: World) -> None:
    await setup_web(world)
    t = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="pay", action="finance.pay", mandate_id=world.roots["chat-boss"]
    )
    await world.admin.approve_task(t["task_id"], by="boss")
    err = await refused(
        world.board.claim(world.agents["code-web"], task_id=t["task_id"], mandate_id=world.roots["code-web"]), "scope_exceeded"
    )
    assert err.mandate_id == world.roots["code-web"]


# ── log ───────────────────────────────────────────────────────────────────────


async def test_refused_calls_are_logged_with_their_code(world: World) -> None:
    await setup_web(world)
    await refused(world.board.revoke(world.agents["code-web"], mandate_id=world.roots["chat-boss"]), "not_issuer")
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT action, outcome FROM entries WHERE agent_id = 'code-web' ORDER BY id DESC LIMIT 1")
    assert row == {"action": "pact_revoke", "outcome": "not_issuer"}


async def test_secrets_are_redacted_before_logging(world: World) -> None:
    await setup_web(world)
    secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    await world.board.post(
        world.agents["chat-boss"],
        project_id="web",
        title="deploy",
        body=f"use key {secret} and postgres://app:hunter2@db/prod",
        mandate_id=world.roots["chat-boss"],
    )
    async with transaction(world.pool) as conn:
        dump = await fetchone(conn, "SELECT string_agg(content::text, ' ') AS all FROM payloads")
    assert dump is not None
    assert secret not in dump["all"] and "hunter2" not in dump["all"]
    assert "[REDACTED]" in dump["all"]


async def test_erasing_a_payload_keeps_the_chain_valid_and_tampering_is_caught(world: World) -> None:
    await setup_web(world)
    for i in range(3):
        await world.board.post(
            world.agents["chat-boss"], project_id="web", title=f"customer {i}", mandate_id=world.roots["chat-boss"]
        )
    assert all(v["ok"] for v in await world.admin.verify_log("web"))

    async with transaction(world.pool) as conn:
        entry = await fetchone(
            conn, "SELECT id FROM entries WHERE chain_key = 'web' AND action = 'pact_post' ORDER BY id LIMIT 1"
        )
    assert entry is not None
    assert await world.admin.erase_payload(entry["id"], by="boss")
    assert all(v["ok"] for v in await world.admin.verify_log("web"))

    async with transaction(world.pool) as conn:
        await conn.execute("ALTER TABLE entries DISABLE TRIGGER entries_no_update")
        await conn.execute("UPDATE entries SET outcome = 'scope_exceeded' WHERE id = %s", (entry["id"],))
        await conn.execute("ALTER TABLE entries ENABLE TRIGGER entries_no_update")
    [verdict] = await world.admin.verify_log("web")
    assert verdict["ok"] is False and verdict["broken_at"] == entry["id"]


async def test_entries_cannot_be_updated_or_deleted(world: World) -> None:
    await setup_web(world)
    await world.board.whoami(world.agents["chat-boss"])
    with pytest.raises(Exception, match="append-only"):
        async with transaction(world.pool) as conn:
            await conn.execute("DELETE FROM entries")


# ── performance ───────────────────────────────────────────────────────────────


async def test_every_tool_under_five_seconds_with_1000_tasks_and_depth_5(world: World) -> None:
    await world.project("web")
    names = [f"a{i}" for i in range(6)]
    await world.agent("a0", "chat", ["web"], delegations=5, scope=[board_scope("task.*", "web")])
    for n in names[1:]:
        await world.agent(n, "gemini", ["web"])
    async with transaction(world.pool) as conn:
        await conn.execute(
            """INSERT INTO tasks (id, project_id, title, created_by, mandate_id, status)
               SELECT gen_random_uuid(), 'web', 'bulk ' || g, 'a0', %s, 'submitted' FROM generate_series(1, 1000) g""",
            (world.roots["a0"],),
        )
    # Build a chain five links deep: a0 → a1 → … → a5.
    mandate = world.roots["a0"]
    for prev, nxt in zip(names, names[1:], strict=False):
        t = await world.board.post(
            world.agents[prev],
            project_id="web",
            title=f"to {nxt}",
            mandate_id=mandate,
            delegate_to=nxt,
            child_scope=[board_scope("task.*", "web")],
        )
        mandate = t["delegated_mandate_id"]
    deepest = world.agents["a5"]

    timings: dict[str, float] = {}

    async def timed(name: str, coro: Any) -> Any:
        start = time.perf_counter()
        out = await coro
        timings[name] = time.perf_counter() - start
        return out

    await timed("whoami", world.board.whoami(deepest))
    listed = await timed("list", world.board.list_tasks(deepest, mandate_id=mandate, limit=200))
    task_id = listed["tasks"][0]["id"]
    await timed("claim", world.board.claim(deepest, task_id=task_id, mandate_id=mandate))
    await timed("report", world.board.report(deepest, task_id=task_id, status="completed", mandate_id=mandate))
    await timed("post", world.board.post(deepest, project_id="web", title="deep", mandate_id=mandate))
    other = listed["tasks"][1]["id"]
    await timed("defer", world.board.defer(deepest, task_id=other, reason="r", mandate_id=mandate))
    await timed("revoke", refused(world.board.revoke(deepest, mandate_id=world.roots["a0"]), "not_issuer"))
    assert max(timings.values()) < 5, timings


# ── mandates die with their task ──────────────────────────────────────────────


async def delegate(w: World, to: str, title: str = "job", **kw: Any) -> dict[str, Any]:
    return await w.board.post(
        w.agents["chat-boss"], project_id="web", title=title, mandate_id=w.roots["chat-boss"], delegate_to=to, **kw
    )


@pytest.mark.parametrize("status", ["completed", "failed", "canceled"])
async def test_closing_a_task_revokes_its_delegated_mandate(world: World, status: str) -> None:
    await setup_web(world)
    code = world.agents["code-web"]
    t = await delegate(world, "code-web")
    child = t["delegated_mandate_id"]
    await world.board.claim(code, task_id=t["task_id"], mandate_id=child)
    out = await world.board.report(code, task_id=t["task_id"], status=status, mandate_id=child)  # type: ignore[arg-type]
    assert out["revoked_mandate"] == child

    err = await refused(world.board.list_tasks(code, mandate_id=child), "mandate_revoked")
    assert err.mandate_id == child
    await world.board.list_tasks(code, mandate_id=world.roots["code-web"])  # its own root is untouched

    async with transaction(world.pool) as conn:
        entry = await fetchone(
            conn,
            "SELECT actor, mandate_chain FROM entries WHERE action = 'mandate.revoke_on_close' AND task_id = %s",
            (t["task_id"],),
        )
    assert entry is not None and entry["actor"] == "system"
    assert [str(m) for m in entry["mandate_chain"]] == [world.roots["chat-boss"], child]  # traceable to the human


async def test_rejecting_a_task_revokes_its_delegated_mandate(world: World) -> None:
    await setup_web(world)
    t = await delegate(world, "code-web", action="deploy.web", child_scope=[board_scope("task.read", "web")])
    assert t["status"] == "auth_required"
    await world.board.list_tasks(world.agents["code-web"], mandate_id=t["delegated_mandate_id"])
    await world.admin.approve_task(t["task_id"], by="boss", approve=False)
    await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=t["delegated_mandate_id"]), "mandate_revoked")


async def test_open_tasks_keep_their_mandate_through_defer_and_approval(world: World) -> None:
    await setup_web(world)
    code = world.agents["code-web"]
    t = await delegate(world, "code-web")
    child = t["delegated_mandate_id"]
    await world.board.claim(code, task_id=t["task_id"], mandate_id=child)
    await world.board.defer(code, task_id=t["task_id"], reason="needs a human", mandate_id=child)
    await world.admin.resume_task(t["task_id"], by="boss")
    await world.board.claim(code, task_id=t["task_id"], mandate_id=child)  # the same mandate still works
    await world.board.report(code, task_id=t["task_id"], status="input_required", mandate_id=child)
    await world.board.list_tasks(code, mandate_id=child)

    gated = await delegate(world, "code-web", action="deploy.web", child_scope=[board_scope("task.read", "web")])
    assert gated["status"] == "auth_required"
    await world.admin.approve_task(gated["task_id"], by="boss")
    await world.board.list_tasks(code, mandate_id=gated["delegated_mandate_id"])


async def test_closing_a_task_reaches_grandchildren_and_cancels_open_subtasks(world: World) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"], delegations=3, scope=[board_scope("task.*", "web")])
    await world.agent("code-a", "code", ["web"])
    await world.agent("code-b", "gemini", ["web"])
    a, b = world.agents["code-a"], world.agents["code-b"]
    parent = await world.board.post(
        world.agents["chat-boss"],
        project_id="web",
        title="parent",
        mandate_id=world.roots["chat-boss"],
        delegate_to="code-a",
        child_scope=[board_scope("task.*", "web")],
    )
    child = parent["delegated_mandate_id"]
    await world.board.claim(a, task_id=parent["task_id"], mandate_id=child)
    sub = await world.board.post(
        a, project_id="web", title="sub", mandate_id=child, delegate_to="code-b", parent_task_id=parent["task_id"]
    )
    grandchild = sub["delegated_mandate_id"]
    await world.board.claim(b, task_id=sub["task_id"], mandate_id=grandchild)

    out = await world.board.report(a, task_id=parent["task_id"], status="completed", mandate_id=child)
    assert out["subtasks_canceled"] == 1
    await refused(world.board.list_tasks(b, mandate_id=grandchild), "mandate_revoked")
    await refused(world.board.report(b, task_id=sub["task_id"], status="completed", mandate_id=grandchild), "mandate_revoked")
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT status, result FROM tasks WHERE id = %s", (sub["task_id"],))
    assert row == {"status": "canceled", "result": {"reason": "mandate_revoked", "mandate_id": child}}


async def test_sweep_revokes_mandates_left_behind_by_closed_tasks(world: World) -> None:
    await setup_web(world)
    done = await delegate(world, "code-web", title="closed before the rule")
    still_open = await delegate(world, "code-web", title="still open")
    async with transaction(world.pool) as conn:  # how the board looked before this rule existed
        await conn.execute("UPDATE tasks SET status = 'completed' WHERE id = %s", (done["task_id"],))

    swept = await world.admin.sweep_closed_task_mandates()
    assert [s["mandate_id"] for s in swept] == [done["delegated_mandate_id"]]
    assert await world.admin.sweep_closed_task_mandates() == []  # idempotent
    code = world.agents["code-web"]
    await refused(world.board.list_tasks(code, mandate_id=done["delegated_mandate_id"]), "mandate_revoked")
    await world.board.list_tasks(code, mandate_id=still_open["delegated_mandate_id"])
    assert all(v["ok"] for v in await world.admin.verify_log())


async def test_input_required_waits_for_a_human_and_resumes(world: World) -> None:
    await setup_web(world)
    chat, code = world.agents["chat-boss"], world.agents["code-web"]
    t = await world.board.post(
        chat, project_id="web", title="which db?", mandate_id=world.roots["chat-boss"], delegate_to="code-web"
    )
    child = t["delegated_mandate_id"]
    await world.board.claim(code, task_id=t["task_id"], mandate_id=child)
    out = await world.board.report(
        code, task_id=t["task_id"], status="input_required", mandate_id=child, result="Postgres or SQLite?"
    )
    assert out["status"] == "input_required"

    listed = await world.board.list_tasks(chat, mandate_id=world.roots["chat-boss"], filter="all")
    [waiting] = listed["deferred"]
    assert waiting["id"] == t["task_id"] and waiting["defer_reason"] == "Postgres or SQLite?"

    await world.admin.resume_task(t["task_id"], by="boss")
    await world.board.claim(code, task_id=t["task_id"], mandate_id=child)  # same task, same mandate
