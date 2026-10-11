"""pact_events: a Runner holds a call open and the board answers as soon as there is work for it."""

import asyncio
import time
from typing import Any

import pytest

from pact.board import MESSAGE_FRAME
from pact.db import fetchall, fetchone, transaction
from pact.oauth import ResourceSettings
from pact.scope import board_scope

from .conftest import HANDOFF, World
from .oauth_fixtures import Issuer
from .test_admin_api import admin_token, api
from .test_board import refused
from .test_tenancy import rival_agent

pytestmark = pytest.mark.anyio


async def setup(w: World) -> None:
    await w.project("web")
    await w.project("ops", production=True)
    await w.agent("chat-boss", "chat", ["web", "ops"])
    await w.agent("runner-web", "runner", ["web"], limits={"runs": 5})
    await w.agent("code-web", "code", ["web"])


async def post(w: World, title: str, project: str = "web", **kw: Any) -> dict[str, Any]:
    return await w.board.post(w.agents["chat-boss"], project_id=project, title=title, mandate_id=w.roots["chat-boss"], **kw)


async def events(w: World, agent: str, since: int | None = None, seconds: float = 0, **kw: Any) -> dict[str, Any]:
    return await w.board.wait_events(
        w.agents[agent], mandate_id=kw.pop("mandate_id", w.roots[agent]), since=since, seconds=seconds, **kw
    )


async def test_a_waiting_runner_hears_of_a_delegated_task_at_once(world: World) -> None:
    await setup(world)

    async def post_later() -> dict[str, Any]:
        await asyncio.sleep(0.5)
        return await post(world, "build it", delegate_to="runner-web")

    started = time.monotonic()
    got, posted = await asyncio.gather(events(world, "runner-web", seconds=30), post_later())
    took = time.monotonic() - started
    # Woken by NOTIFY, not by the 2-second fallback re-read, and long before the 30 seconds ran out.
    assert took < 1.5, took
    assert got["timed_out"] is False and got["has_more"] is False
    [event] = got["events"]
    assert (event["kind"], event["reason"], event["task"]["id"]) == ("task", "delegated", posted["task_id"])
    assert event["task"]["delegated_mandate_id"] == posted["delegated_mandate_id"]
    assert got["next_since"] == event["seq"] == event["task"]["seq"]


async def test_nothing_new_times_out_empty_with_the_same_cursor(world: World) -> None:
    await setup(world)
    first = await post(world, "open work")
    # Without since, what is waiting already comes back at once: the backlog.
    got = await events(world, "runner-web", seconds=30)
    assert [(e["reason"], e["task"]["id"]) for e in got["events"]] == [("open", first["task_id"])]

    started = time.monotonic()
    empty = await events(world, "runner-web", since=got["next_since"], seconds=0.6)
    assert time.monotonic() - started >= 0.5
    assert empty["events"] == [] and empty["timed_out"] is True and empty["next_since"] == got["next_since"]


async def test_a_dropped_call_resumes_from_since_without_missing_anything(world: World) -> None:
    await setup(world)
    chat = world.agents["chat-boss"]
    listed = await world.board.list_tasks(world.agents["runner-web"], mandate_id=world.roots["runner-web"])
    cursor = listed["next_since"]  # a pact_list cursor is a pact_events cursor

    # While the Runner is not connected: a task for it, a message to it, and changes it does not care about.
    mine = await post(world, "for the runner", delegate_to="runner-web")
    await world.board.claim(world.agents["runner-web"], task_id=mine["task_id"], mandate_id=mine["delegated_mandate_id"])
    await world.board.message(chat, task_id=mine["task_id"], mandate_id=world.roots["chat-boss"], body="use branch b")
    other = await post(world, "for code-web", delegate_to="code-web")
    later = await post(world, "open to all")

    got = await events(world, "runner-web", since=cursor, seconds=30)
    kinds = [(e["kind"], e.get("task", {}).get("id") or e["message"]["body"]) for e in got["events"]]
    # The claimed task is no longer claimable, the other agent's is not its business.
    assert kinds == [("message", "use branch b"), ("task", later["task_id"])]
    assert [e["seq"] for e in got["events"]] == sorted(e["seq"] for e in got["events"])
    assert got["events"][0]["message"]["task_title"] == "for the runner"
    assert got["note"] == MESSAGE_FRAME
    assert other["task_id"] not in str(got)
    # Waiting marks nothing read; the message is still in the inbox.
    assert len((await world.board.list_tasks(world.agents["runner-web"], mandate_id=world.roots["runner-web"]))["inbox"]) == 1

    # The same since again gives the same answer (nothing is consumed); the new cursor gives nothing.
    again = await events(world, "runner-web", since=cursor)
    assert [e["seq"] for e in again["events"]] == [e["seq"] for e in got["events"]]
    assert (await events(world, "runner-web", since=got["next_since"]))["events"] == []

    # limit pages through, in order.
    page = await events(world, "runner-web", since=cursor, limit=1)
    assert page["has_more"] is True and page["next_since"] == got["events"][0]["seq"]
    rest = await events(world, "runner-web", since=page["next_since"], limit=1)
    assert rest["has_more"] is False and rest["events"] == got["events"][1:]


async def test_a_task_a_person_resumes_wakes_its_agent(world: World) -> None:
    await setup(world)
    t = await post(world, "needs a call", delegate_to="runner-web")
    runner = world.agents["runner-web"]
    await world.board.claim(runner, task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    await world.board.defer(runner, task_id=t["task_id"], reason="which region?", mandate_id=t["delegated_mandate_id"])
    cursor = (await events(world, "runner-web"))["next_since"]

    async def resume_later() -> None:
        await asyncio.sleep(0.3)
        await world.admin.resume_task(t["task_id"], by="boss", answer="eu-west")

    got, _ = await asyncio.gather(events(world, "runner-web", since=cursor, seconds=30), resume_later())
    [event] = got["events"]
    assert event["reason"] == "resumed" and event["task"]["answer"] == "eu-west"


async def test_events_respect_the_organization_the_project_and_the_mandate(world: World) -> None:
    # Not two_organizations: it rewrites the default organization's roles, which outlive the test.
    async with transaction(world.pool) as conn:
        await conn.execute("INSERT INTO orgs (id, name, system_chain) VALUES ('rival', 'Rival', '_system:rival')")
        await conn.execute(
            """INSERT INTO agent_roles (org_id, id, name, client, actions)
               SELECT 'rival', id, name, client, actions FROM role_templates"""
        )
        await conn.execute(
            "INSERT INTO humans (id, name, role, email, org_id) VALUES ('rex', 'Rex', 'owner', 'rex@example.com', 'rival')"
        )
    await setup(world)
    await world.admin.add_project("acme", "Acme", by="rex")
    boss_task = (await post(world, "boss work"))["task_id"]
    spy, spy_root = await rival_agent(world)

    # The rival's agent never sees the default organization's work, even from the start.
    got = await world.board.wait_events(spy, mandate_id=spy_root, seconds=0)
    assert got["events"] == [] and boss_task not in str(got)
    await refused(world.board.wait_events(spy, mandate_id=spy_root, project_id="web"), "project_mismatch")
    await refused(world.board.wait_events(spy, mandate_id=world.roots["runner-web"]), "chain_broken")

    # Work posted in the rival organization while a default agent waits does not wake it.
    async def rival_posts() -> None:
        await asyncio.sleep(0.3)
        await world.board.post(spy, project_id="acme", title="rival work", mandate_id=spy_root)

    started = time.monotonic()
    quiet, _ = await asyncio.gather(
        world.board.wait_events(world.agents["runner-web"], mandate_id=world.roots["runner-web"], since=10**12, seconds=1.0),
        rival_posts(),
    )
    assert quiet["timed_out"] is True and time.monotonic() - started >= 0.9

    # A mandate without task.read on the project sees nothing there.
    narrow = await world.admin.issue_mandate("runner-web", by="boss", scope=[board_scope("task.post", "web")])
    assert (await world.board.wait_events(world.agents["runner-web"], mandate_id=narrow, seconds=0))["events"] == []
    full = await world.board.wait_events(world.agents["runner-web"], mandate_id=world.roots["runner-web"])
    assert [e["task"]["id"] for e in full["events"]] == [boss_task]


async def test_who_gets_which_events(world: World) -> None:
    await setup(world)
    await post(world, "open job")
    for_code = await post(world, "for code", delegate_to="code-web")
    chat = world.agents["chat-boss"]
    await world.board.claim(world.agents["code-web"], task_id=for_code["task_id"], mandate_id=for_code["delegated_mandate_id"])
    await world.board.message(
        world.agents["code-web"], task_id=for_code["task_id"], mandate_id=for_code["delegated_mandate_id"], body="q?"
    )

    # A Runner never touches production: once its project is flagged, its work no longer wakes it.
    assert [e["task"]["title"] for e in (await events(world, "runner-web"))["events"]] == ["open job"]
    await world.admin.set_project_flags("web", by="boss", production=True)
    assert (await events(world, "runner-web"))["events"] == []
    await world.admin.set_project_flags("web", by="boss", production=False)
    # chat posts and watches: it hears of messages to it, never of tasks to claim.
    got = await events(world, "chat-boss")
    assert [e["kind"] for e in got["events"]] == ["message"]
    await world.board.message(chat, task_id=for_code["task_id"], mandate_id=world.roots["chat-boss"])  # read it
    assert (await events(world, "chat-boss"))["events"] == []
    # code-web holds its own task now: only the open one is left for it.
    assert [e["task"]["title"] for e in (await events(world, "code-web"))["events"]] == ["open job"]


async def test_a_mandate_revoked_while_waiting_is_refused_at_the_end(world: World) -> None:
    await setup(world)
    t = await post(world, "parent", delegate_to="runner-web")
    runner = world.agents["runner-web"]
    child = t["delegated_mandate_id"]
    await world.board.claim(runner, task_id=t["task_id"], mandate_id=child)

    async def close_later() -> None:
        await asyncio.sleep(0.3)
        await world.board.report(runner, task_id=t["task_id"], status="completed", mandate_id=child, result=HANDOFF)

    started = time.monotonic()
    results = await asyncio.gather(
        world.board.wait_events(runner, mandate_id=child, since=10**12, seconds=30), close_later(), return_exceptions=True
    )
    assert getattr(results[0], "code", None) == "mandate_revoked"
    assert time.monotonic() - started < 5


async def test_waiting_is_a_heartbeat_the_admin_api_shows(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await setup(world)
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE humans SET email = 'boss@example.com' WHERE id = 'boss'")

    async def agents() -> dict[str, dict[str, Any]]:
        r = await api(url, "GET", "/agents", admin_token(issuer, settings))
        assert r.status_code == 200
        return {a["id"]: a for a in r.json()}

    before = await agents()
    assert before["runner-web"]["online"] is False and before["runner-web"]["listening_until"] is None

    waiting = asyncio.create_task(events(world, "runner-web", since=10**12, seconds=2))
    await asyncio.sleep(0.5)
    async with transaction(world.pool) as conn:
        row = await fetchone(
            conn, "SELECT listening_until > now() AS listening, last_seen IS NOT NULL AS seen FROM agents WHERE id = 'runner-web'"
        )
    assert row == {"listening": True, "seen": True}
    assert (await agents())["runner-web"]["online"] is True
    assert (await waiting)["timed_out"] is True

    after = await agents()
    # Between two waits it still counts as online; an agent that never waited does not.
    assert after["runner-web"]["online"] is True and after["code-web"]["online"] is False
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE agents SET listening_until = now() - interval '5 minutes' WHERE id = 'runner-web'")
    assert (await agents())["runner-web"]["online"] is False

    # An empty wait leaves no entry in the log; one that returns events does.
    async with transaction(world.pool) as conn:
        logged = await fetchall(conn, "SELECT outcome FROM entries WHERE action = 'pact_events'")
    assert logged == []
    await post(world, "work")
    assert (await events(world, "runner-web"))["events"]
    async with transaction(world.pool) as conn:
        logged = await fetchall(conn, "SELECT outcome FROM entries WHERE action = 'pact_events'")
    assert [r["outcome"] for r in logged] == ["ok"]
