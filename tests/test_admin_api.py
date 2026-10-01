"""Admin API: humans only, a second factor, role checks, and the Admin UI's operations."""

from typing import Any

import httpx2
import pytest

from pact.oauth import ResourceSettings

from .conftest import World
from .oauth_fixtures import HEADERS, Issuer

pytestmark = pytest.mark.anyio


async def people(world: World) -> None:
    from pact.db import transaction

    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE humans SET email = 'boss@example.com' WHERE id = 'boss'")
    await world.admin.add_human("vic", "Vic", "viewer", by="boss", email="vic@example.com")
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])
    await world.agent("code-web", "code", ["web"])


def admin_token(issuer: Issuer, settings: ResourceSettings, who: str = "boss", mfa: bool = True, aud: str | None = None) -> str:
    return issuer.token(
        f"sub-{who}", aud or settings.admin_audience, email=f"{who}@example.com", amr=["pwd", "otp", "mfa"] if mfa else ["pwd"]
    )


async def api(url: str, method: str, path: str, token: str | None, body: dict[str, Any] | None = None) -> httpx2.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(timeout=10) as http:
        return await http.request(method, f"{url}/admin/api{path}", headers=headers, json=body)


async def test_only_mfa_tokens_for_the_admin_audience_get_in(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await people(world)
    assert (await api(url, "GET", "/me", None)).status_code == 401
    assert (await api(url, "GET", "/me", world.tokens["chat-boss"])).status_code == 401  # agent token
    agent_aud = admin_token(issuer, settings, aud=settings.resource("chat-boss"))
    assert (await api(url, "GET", "/me", agent_aud)).status_code == 401  # minted for an agent URL
    assert (await api(url, "GET", "/me", admin_token(issuer, settings, mfa=False))).status_code == 401
    me = await api(url, "GET", "/me", admin_token(issuer, settings))
    assert me.status_code == 200 and me.json()["role"] == "owner"


async def test_viewer_reads_but_cannot_act(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    url, settings = board
    await people(world)
    vic = admin_token(issuer, settings, who="vic")
    assert (await api(url, "GET", "/overview", vic)).status_code == 200
    assert (await api(url, "GET", "/entries", vic)).status_code == 200
    r = await api(url, "POST", "/kill-switch", vic, {"halted": True})
    assert r.status_code == 403 and r.json()["error"] == "forbidden"


async def test_kill_switch_stops_agents_until_released(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    url, settings = board
    await people(world)
    boss = admin_token(issuer, settings)
    assert (await api(url, "POST", "/kill-switch", boss, {"halted": True})).json() == {"halted": True}
    assert (await api(url, "GET", "/overview", boss)).json()["halted"] is True

    headers = {**HEADERS, "Authorization": f"Bearer {world.tokens['code-web']}"}
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "pact_whoami", "arguments": {}}}
    async with httpx2.AsyncClient(timeout=10) as http:
        r = (await http.post(f"{url}/mcp/a/code-web", json=call, headers=headers)).json()
    assert r["result"]["isError"] and "system_halted" in r["result"]["content"][0]["text"]

    await api(url, "POST", "/kill-switch", boss, {"halted": False})
    assert (await api(url, "GET", "/overview", boss)).json()["halted"] is False


async def test_approval_and_trace_back_to_the_human(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    url, settings = board
    await people(world)
    boss = admin_token(issuer, settings)
    t = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="ship", action="deploy.web", mandate_id=world.roots["chat-boss"]
    )
    pending = (await api(url, "GET", "/tasks?status=auth_required", boss)).json()
    assert [x["id"] for x in pending] == [t["task_id"]]
    assert (await api(url, "POST", f"/tasks/{t['task_id']}/approve", boss)).status_code == 200
    again = await api(url, "POST", f"/tasks/{t['task_id']}/approve", boss)
    assert again.status_code == 400  # no longer waiting

    trace = (await api(url, "GET", f"/tasks/{t['task_id']}", boss)).json()
    assert trace["task"]["status"] == "submitted"
    roots = [m for m in trace["mandates"] if m["parent_id"] is None]
    assert roots and all(m["issuer_kind"] == "human" for m in roots)
    assert {e["action"] for e in trace["entries"]} >= {"pact_post", "admin.task.approve"}


async def test_register_pause_and_revoke_from_the_ui(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    url, settings = board
    await people(world)
    boss = admin_token(issuer, settings)
    out = (await api(url, "POST", "/agents", boss, {"id": "gem-web", "client": "gemini", "projects": ["web"]})).json()
    assert out["token"].startswith("pact_") and out["connector_path"] == "/mcp/a/gem-web"
    listed = {a["id"]: a for a in (await api(url, "GET", "/agents", boss)).json()}
    assert listed["gem-web"]["projects"] == ["web"] and listed["gem-web"]["live_tokens"] == 1

    assert (await api(url, "POST", "/agents/gem-web/status", boss, {"status": "paused"})).status_code == 200
    r = await api(url, "POST", f"/mandates/{out['root_mandate_id']}/revoke", boss)
    assert r.json() == {"descendant_mandates": 0, "tasks_stopped": 0}
    alive = {m["id"] for m in (await api(url, "GET", "/mandates", boss)).json()}
    assert out["root_mandate_id"] not in alive


async def test_refused_calls_show_in_the_audit_log(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    url, settings = board
    await people(world)
    from pact.errors import PactError

    with pytest.raises(PactError):
        await world.board.revoke(world.agents["code-web"], mandate_id=world.roots["chat-boss"])
    rows = (await api(url, "GET", "/entries?refused=1", admin_token(issuer, settings))).json()
    assert [(r["agent_id"], r["outcome"]) for r in rows] == [("code-web", "not_issuer")]
    verdicts = (await api(url, "GET", "/log/verify", admin_token(issuer, settings))).json()
    assert verdicts and all(v["ok"] for v in verdicts)


async def test_audit_log_filters_by_time(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    from pact.db import transaction

    url, settings = board
    await people(world)
    boss = admin_token(issuer, settings)
    async with transaction(world.pool) as conn:  # spread the entries over three days
        await conn.execute("ALTER TABLE entries DISABLE TRIGGER entries_no_update")
        await conn.execute("UPDATE entries SET at = '2026-09-01T12:00:00Z'")
        await conn.execute("ALTER TABLE entries ENABLE TRIGGER entries_no_update")
    await world.board.whoami(world.agents["code-web"])
    async with transaction(world.pool) as conn:
        await conn.execute("ALTER TABLE entries DISABLE TRIGGER entries_no_update")
        await conn.execute("UPDATE entries SET at = '2026-09-02T12:00:00Z' WHERE action = 'pact_whoami'")
        await conn.execute("ALTER TABLE entries ENABLE TRIGGER entries_no_update")

    def query(**q: str) -> str:
        return "/entries?" + "&".join(f"{k}={v}" for k, v in q.items())

    day2 = (await api(url, "GET", query(**{"from": "2026-09-02T00:00:00Z", "to": "2026-09-03T00:00:00Z"}), boss)).json()
    assert [e["action"] for e in day2] == ["pact_whoami"]
    # +07:00 sent unencoded arrives as a space; it still reads as the offset.
    bkk = (await api(url, "GET", query(to="2026-09-02T07:00:00+07:00"), boss)).json()
    assert bkk and all(e["action"] != "pact_whoami" for e in bkk)

    naive = await api(url, "GET", query(**{"from": "2026-09-02T00:00:00"}), boss)
    assert naive.status_code == 400 and "offset" in naive.json()["message"]
    assert (await api(url, "GET", query(to="yesterday"), boss)).status_code == 400


async def test_people_manage_project_context(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    url, settings = board
    await people(world)
    boss, vic = admin_token(issuer, settings), admin_token(issuer, settings, who="vic")
    path = "/projects/web/context/conventions"
    assert (await api(url, "PUT", path, vic, {"body": "x"})).status_code == 403  # viewers read only
    wrote = (await api(url, "PUT", path, boss, {"title": "Conventions", "body": "Conventional Commits."})).json()
    assert wrote["version"] == 1
    assert (await api(url, "POST", f"{path}/pin", boss)).json() == {"ok": True}
    listed = (await api(url, "GET", "/projects/web/context", vic)).json()
    assert [(n["key"], n["pinned"]) for n in listed] == [("conventions", True)]
    detail = (await api(url, "GET", path, vic)).json()
    assert detail["note"]["updated_by"] == "human:boss" and [v["version"] for v in detail["versions"]] == [1]


async def test_people_assign_tasks_to_agents_that_can_claim(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    from pact.errors import PactError

    url, settings = board
    await people(world)
    await world.agent("code-two", "code", ["web"])
    boss = admin_token(issuer, settings)
    chat = world.agents["chat-boss"]
    t = (await world.board.post(chat, project_id="web", title="fix", mandate_id=world.roots["chat-boss"]))["task_id"]

    r = await api(url, "POST", f"/tasks/{t}/assign", boss, {"agent": "chat-boss"})
    assert r.status_code == 400 and "cannot claim" in r.json()["message"]
    r = await api(url, "POST", f"/tasks/{t}/assign", boss, {"agent": "nobody"})
    assert r.json()["error"] == "agent_unknown"
    vic = admin_token(issuer, settings, who="vic")
    assert (await api(url, "POST", f"/tasks/{t}/assign", vic, {"agent": "code-web"})).status_code == 403

    assert (await api(url, "POST", f"/tasks/{t}/assign", boss, {"agent": "code-web"})).json()["delegate_to"] == "code-web"
    with pytest.raises(PactError) as e:
        await world.board.claim(world.agents["code-two"], task_id=t, mandate_id=world.roots["code-two"])
    assert e.value.code == "wrong_agent"

    # Open to anyone again, then claimed.
    assert (await api(url, "POST", f"/tasks/{t}/assign", boss, {"agent": None})).json()["delegate_to"] is None
    await world.board.claim(world.agents["code-two"], task_id=t, mandate_id=world.roots["code-two"])
    r = await api(url, "POST", f"/tasks/{t}/assign", boss, {"agent": "code-web"})
    assert r.status_code == 400 and "release it first" in r.json()["message"]

    trace = (await api(url, "GET", f"/tasks/{t}", boss)).json()
    assigns = [e["payload"] for e in trace["entries"] if e["action"] == "admin.task.assign"]
    assert [(p["from"], p["to"]) for p in assigns] == [(None, "code-web"), ("code-web", None)]


async def test_reassigning_revokes_the_mandate_delegated_for_the_task(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    from pact.errors import PactError

    url, settings = board
    await people(world)
    await world.agent("code-two", "code", ["web"])
    boss = admin_token(issuer, settings)
    out = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="fix", delegate_to="code-web", mandate_id=world.roots["chat-boss"]
    )
    t, child = out["task_id"], out["delegated_mandate_id"]

    r = (await api(url, "POST", f"/tasks/{t}/assign", boss, {"agent": "code-two"})).json()
    assert r["revoked_mandate"] == child
    with pytest.raises(PactError) as e:
        await world.board.list_tasks(world.agents["code-web"], mandate_id=child)
    assert e.value.code == "mandate_revoked"

    # The task itself stays open, and the new agent takes it with its own mandate.
    await world.board.claim(world.agents["code-two"], task_id=t, mandate_id=world.roots["code-two"])
    assert (await api(url, "GET", f"/tasks/{t}", boss)).json()["task"]["status"] == "working"


async def test_people_release_and_cancel_tasks(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    from pact.errors import PactError

    url, settings = board
    await people(world)
    boss = admin_token(issuer, settings)
    code = world.agents["code-web"]
    out = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="fix", delegate_to="code-web", mandate_id=world.roots["chat-boss"]
    )
    t, child = out["task_id"], out["delegated_mandate_id"]
    assert (await api(url, "POST", f"/tasks/{t}/release", boss)).status_code == 400  # nobody holds it

    await world.board.claim(code, task_id=t, mandate_id=child)
    assert (await api(url, "POST", f"/tasks/{t}/release", boss)).json()["released_from"] == "code-web"
    with pytest.raises(PactError) as e:
        await world.board.report(code, task_id=t, status="completed", mandate_id=child, result="done")
    assert e.value.code == "claim_lost"

    # Deferred tasks can be canceled too; the delegated mandate dies with the task.
    await world.board.claim(code, task_id=t, mandate_id=child)
    await world.board.defer(code, task_id=t, reason="stuck", mandate_id=child)
    open_ids = [x["id"] for x in (await api(url, "GET", "/tasks?open=1&agent=code-web", boss)).json()]
    assert open_ids == [t]
    r = await api(url, "POST", f"/tasks/{t}/cancel", boss, {"reason": "stale"})
    assert r.status_code == 200 and r.json()["revoked"][0]["mandate_id"] == child
    task = (await api(url, "GET", f"/tasks/{t}", boss)).json()["task"]
    assert task["status"] == "canceled" and not task["deferred"] and task["result"]["note"] == "stale"
    assert (await api(url, "GET", "/tasks?open=1", boss)).json() == []
    assert (await api(url, "POST", f"/tasks/{t}/cancel", boss)).status_code == 400  # already closed
    with pytest.raises(PactError) as e:
        await world.board.list_tasks(code, mandate_id=child)
    assert e.value.code == "mandate_revoked"
