"""Organizations never see or touch each other's data through the Admin API.

Two organizations: the default one (owner `boss`, project `web`, agents `code-web` and
`chat-boss`) and `rival` (owner `rex`, project `acme`). Rex calls every route with boss's ids and
must get nothing back and change nothing. Every route of the Admin API has to be listed in
ROUTES with how it treats organizations, so a new route cannot ship without deciding it.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pact import credentials
from pact.admin_api import build_admin_app
from pact.board import get_agent
from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError
from pact.keys import b64url
from pact.mandates import issue_root
from pact.oauth import ResourceSettings

from .conftest import World
from .oauth_fixtures import Issuer
from .test_admin_api import admin_token, api

pytestmark = pytest.mark.anyio

SECRET = "BOSS-ONLY"
"""Written into the default organization's data; it must never show up in rival's answers."""

# Every route, and what it does with an organization other than the caller's:
#   own   = reads or writes only the caller's organization (lists, creates in it)
#   ids   = names rows by id; another organization's ids answer not_found
#   global = shared by design (published credential revocation lists)
ROUTES: dict[tuple[str, str], str] = {
    ("POST", "/admin/api/signup"): "global",  # makes a new organization; tests/test_signup.py
    ("GET", "/admin/api/me"): "own",
    ("GET", "/admin/api/org"): "own",
    ("PUT", "/admin/api/org"): "own",
    ("GET", "/admin/api/overview"): "own",
    ("GET", "/admin/api/humans"): "own",
    ("POST", "/admin/api/humans"): "own",
    ("GET", "/admin/api/projects"): "own",
    ("POST", "/admin/api/projects"): "own",
    ("PATCH", "/admin/api/projects/{project_id}"): "ids",
    ("GET", "/admin/api/projects/{project_id}/context"): "ids",
    ("GET", "/admin/api/projects/{project_id}/context/{key}"): "ids",
    ("PUT", "/admin/api/projects/{project_id}/context/{key}"): "ids",
    ("POST", "/admin/api/projects/{project_id}/context/{key}/{action}"): "ids",
    ("POST", "/admin/api/context-versions/{version_id:int}/erase"): "ids",
    ("GET", "/admin/api/agents"): "own",
    ("POST", "/admin/api/agents"): "ids",
    ("POST", "/admin/api/agents/hire"): "ids",
    ("GET", "/admin/api/agents/{agent_id}/connection"): "ids",
    ("POST", "/admin/api/agents/{agent_id}/renew"): "ids",
    ("POST", "/admin/api/agents/{agent_id}/role"): "ids",
    ("PATCH", "/admin/api/agents/{agent_id}"): "ids",
    ("PATCH", "/admin/api/humans/{human_id}"): "ids",
    ("POST", "/admin/api/agents/{agent_id}/setup-code"): "ids",
    ("GET", "/admin/api/roles"): "own",
    ("PUT", "/admin/api/roles/{role_id}"): "own",
    ("POST", "/admin/api/roles/{role_id}/archive"): "own",
    ("POST", "/admin/api/agents/{agent_id}/status"): "ids",
    ("PUT", "/admin/api/agents/{agent_id}/preferences"): "ids",
    ("POST", "/admin/api/agents/{agent_id}/tokens"): "ids",
    ("DELETE", "/admin/api/agents/{agent_id}/tokens"): "ids",
    ("GET", "/admin/api/agents/{agent_id}/keys"): "ids",
    ("POST", "/admin/api/agents/{agent_id}/keys"): "ids",
    ("DELETE", "/admin/api/agents/{agent_id}/keys/{kid}"): "ids",
    ("POST", "/admin/api/agents/{agent_id}/credentials"): "ids",
    ("GET", "/admin/api/trusted-roots"): "own",
    ("GET", "/admin/api/credentials/status"): "global",
    ("POST", "/admin/api/trusted-roots"): "ids",
    ("DELETE", "/admin/api/trusted-roots/{principal}"): "ids",
    ("GET", "/admin/api/mandates"): "own",
    ("POST", "/admin/api/mandates"): "ids",
    ("GET", "/admin/api/mandates/{mandate_id}/impact"): "ids",
    ("POST", "/admin/api/mandates/{mandate_id}/revoke"): "ids",
    ("POST", "/admin/api/mandates/{mandate_id}/replace"): "ids",
    ("GET", "/admin/api/tasks"): "own",
    ("GET", "/admin/api/tasks/{task_id}"): "ids",
    ("POST", "/admin/api/tasks/{task_id}/{decision}"): "ids",
    ("GET", "/admin/api/entries"): "own",
    ("POST", "/admin/api/entries/{entry_id:int}/erase"): "ids",
    ("GET", "/admin/api/log/verify"): "own",
    ("POST", "/admin/api/kill-switch"): "own",
}


def test_every_admin_route_declares_how_it_treats_organizations() -> None:
    app = build_admin_app(None, None)  # type: ignore[arg-type]
    routes = {(m, r.path) for r in app.routes for m in (getattr(r, "methods", None) or []) if m != "HEAD"}
    assert routes == set(ROUTES), "classify new Admin API routes in ROUTES (and test them below)"


def public_key() -> str:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64url(raw)


async def two_organizations(world: World) -> dict[str, Any]:
    """The default organization with some of everything, and an empty rival with its own owner."""
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE humans SET email = 'boss@example.com' WHERE id = 'boss'")
        await conn.execute("INSERT INTO orgs (id, name, system_chain) VALUES ('rival', 'Rival', '_system:rival')")
        await conn.execute(
            """INSERT INTO agent_roles (org_id, id, name, description, client, actions, limits, delegations,
                                        mandate_days, token_days, settings, instructions, position)
               SELECT 'rival', id, name, description, client, actions, limits, delegations, mandate_days, token_days,
                      settings, instructions, position FROM role_templates"""
        )
        await conn.execute(
            "INSERT INTO humans (id, name, role, email, org_id) VALUES ('rex', 'Rex', 'owner', 'rex@example.com', 'rival')"
        )
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])
    code = await world.agent("code-web", "code", ["web"])
    key = await world.admin.add_agent_key("code-web", public_key(), by="boss")
    await world.admin.add_trusted_root(public_key(), human="boss", by="boss", label=SECRET)
    await world.admin.write_note("web", "plan", by="boss", title=SECRET, body=SECRET)
    await world.admin.save_role(
        "code", {"name": "Claude Code", "description": SECRET, "client": "code", "actions": ["task.read"]}, by="boss"
    )
    task = await world.board.post(code, project_id="web", title=SECRET, body=SECRET, mandate_id=world.roots["code-web"])
    await world.admin.add_project("acme", "Acme", by="rex")
    async with transaction(world.pool) as conn:
        version = await fetchone(conn, "SELECT id FROM context_note_versions WHERE project_id = 'web'")
        entry = await fetchone(conn, "SELECT id FROM entries WHERE project_id = 'web' ORDER BY id DESC LIMIT 1")
        root = await fetchone(conn, "SELECT principal FROM trusted_roots WHERE org_id = 'default'")
    assert version and entry and root
    return {
        "task": task["task_id"],
        "mandate": world.roots["code-web"],
        "kid": key["kid"],
        "version": version["id"],
        "entry": entry["id"],
        "principal": b64url(bytes(root["principal"])),
    }


async def boss_state(world: World) -> str:
    """Everything of the default organization a write could change, to compare before and after."""
    async with transaction(world.pool) as conn:
        rows = {
            "agents": await fetchall(
                conn, "SELECT id, status, owner, preferences, role_id, root_mandate_id FROM agents ORDER BY id"
            ),
            "projects": await fetchall(conn, "SELECT id, frozen, production FROM projects WHERE org_id = 'default'"),
            "humans": await fetchall(conn, "SELECT id, name, role, disabled_at FROM humans WHERE org_id = 'default'"),
            "tasks": await fetchall(conn, "SELECT id, title, status, delegate_to FROM tasks"),
            "mandates": await fetchall(conn, "SELECT id, revoked_at FROM mandates ORDER BY id"),
            "tokens": await fetchall(conn, "SELECT token_hash, revoked_at FROM agent_tokens ORDER BY token_hash"),
            "keys": await fetchall(conn, "SELECT kid, revoked_at FROM agent_keys"),
            "roots": await fetchall(conn, "SELECT label, revoked_at FROM trusted_roots WHERE org_id = 'default'"),
            "roles": await fetchall(conn, "SELECT id, description, archived_at FROM agent_roles WHERE org_id = 'default'"),
            "notes": await fetchall(conn, "SELECT key, title, pinned FROM context_notes"),
            "payloads": await fetchall(
                conn,
                """SELECT p.id, p.erased_at FROM payloads p JOIN entries e ON e.payload_ref = p.id
                   WHERE e.org_id = 'default' ORDER BY p.id""",
            ),
            "codes": await fetchall(conn, "SELECT count(*) AS n FROM setup_codes"),
            "org": await fetchall(conn, "SELECT name, halted, slack_webhook_url FROM orgs WHERE id = 'default'"),
        }
    return json.dumps(rows, default=str, sort_keys=True)


async def test_another_organization_sees_and_changes_nothing(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    ids = await two_organizations(world)
    rex = admin_token(issuer, settings, who="rex")
    before = await boss_state(world)
    secrets = [SECRET, "code-web", "chat-boss", "boss@example.com", ids["task"], ids["mandate"], ids["kid"], ids["principal"]]
    t, m = ids["task"], ids["mandate"]
    fmt = credentials.names()[0]

    # Lists answer only rival's rows.
    for path in ("/me", "/org", "/overview", "/humans", "/projects", "/agents", "/roles", "/roles?archived=1", "/trusted-roots",
                 "/mandates?all=1", "/tasks", "/entries", "/log/verify"):  # fmt: skip
        r = await api(url, "GET", path, rex)
        assert r.status_code == 200, path
        leaked = [s for s in secrets if s in r.text]
        assert not leaked, f"{path} leaked {leaked}"
    assert {v["chain_key"] for v in (await api(url, "GET", "/log/verify", rex)).json()} <= {"acme", "_system:rival"}

    # Anything that names the default organization's rows is refused as if they did not exist.
    refused: list[tuple[str, str, dict[str, Any] | None]] = [
        ("PATCH", "/projects/web", {"frozen": True}),
        ("GET", "/projects/web/context", None),
        ("GET", "/projects/web/context/plan", None),
        ("PUT", "/projects/web/context/plan", {"title": "x", "body": "x"}),
        ("POST", "/projects/web/context/plan/pin", None),
        ("POST", "/projects/web/context/plan/archive", None),
        ("POST", f"/context-versions/{ids['version']}/erase", None),
        ("POST", "/agents", {"id": "spy", "client": "code", "projects": ["web"]}),
        ("POST", "/agents/hire", {"role": "code", "project": "web", "id": "spy-web"}),
        ("GET", "/agents/code-web/connection", None),
        ("POST", "/agents/code-web/renew", None),
        ("POST", "/agents/code-web/role", {"role_id": "code"}),
        ("PATCH", "/agents/code-web", {"owner": "rex"}),
        ("PATCH", "/humans/boss", {"name": "pwned"}),
        ("POST", "/agents/code-web/setup-code", None),
        ("POST", "/agents/code-web/status", {"status": "paused"}),
        ("PUT", "/agents/code-web/preferences", {"preferences": {"x": "y"}}),
        ("POST", "/agents/code-web/tokens", {"days": 1}),
        ("DELETE", "/agents/code-web/tokens", None),
        ("GET", "/agents/code-web/keys", None),
        ("POST", "/agents/code-web/keys", {"public_key": public_key()}),
        ("DELETE", f"/agents/code-web/keys/{ids['kid']}", None),
        ("POST", "/agents/code-web/credentials", {"format": fmt, "credential": "x"}),
        ("POST", "/trusted-roots", {"public_key": public_key(), "human": "boss"}),
        ("DELETE", f"/trusted-roots/{ids['principal']}", None),
        ("POST", "/mandates", {"holder": "code-web", "scope": ["task.read@project:web"]}),
        ("GET", f"/mandates/{m}/impact", None),
        ("POST", f"/mandates/{m}/revoke", None),
        ("POST", f"/mandates/{m}/replace", {"scope": ["task.read@project:web"], "revoke": True}),
        ("GET", f"/tasks/{t}", None),
        ("POST", f"/tasks/{t}/assign", {"agent": "code-web"}),
        ("POST", f"/tasks/{t}/release", None),
        ("POST", f"/tasks/{t}/edit", {"title": "pwned"}),
        ("POST", f"/tasks/{t}/cancel", None),
        ("POST", f"/tasks/{t}/approve", None),
        ("POST", f"/tasks/{t}/resume", {"answer": "x"}),
        ("POST", f"/entries/{ids['entry']}/erase", None),
    ]
    for method, path, body in refused:
        r = await api(url, method, path, rex, body)
        assert r.status_code in (400, 404), f"{method} {path} answered {r.status_code}: {r.text}"
        # A refusal may repeat the id it was given (exactly as for an id that does not exist);
        # anything else of the default organization must not appear.
        asked = path + json.dumps(body)
        leaked = [s for s in secrets if s in r.text and s not in asked]
        assert not leaked, f"{method} {path} leaked {leaked}"

    # Writes that act on the caller's own organization stay there.
    assert (
        await api(url, "PUT", "/roles/code", rex, {"name": "C", "client": "code", "actions": ["task.read"]})
    ).status_code == 200
    assert (await api(url, "POST", "/roles/code/archive", rex)).status_code == 200
    assert (await api(url, "POST", "/humans", rex, {"id": "ria", "name": "Ria", "role": "viewer"})).status_code == 200
    assert (await api(url, "POST", "/kill-switch", rex, {"halted": True})).status_code == 200
    hook = "https://hooks.slack.com/services/T0/B0/rival"
    assert (await api(url, "PUT", "/org", rex, {"name": "Rival 2", "slack_webhook_url": hook})).status_code == 200
    # A taken id is refused without saying whose it is.
    taken = await api(url, "POST", "/projects", rex, {"id": "web", "name": "Web"})
    assert taken.status_code == 409 and SECRET not in taken.text

    assert await boss_state(world) == before
    async with transaction(world.pool) as conn:
        assert await fetchone(conn, "SELECT org_id FROM humans WHERE id = 'ria'") == {"org_id": "rival"}
        assert await fetchone(conn, "SELECT halted FROM orgs WHERE id = 'rival'") == {"halted": True}


async def test_one_organization_halting_does_not_stop_another(world: World) -> None:
    await two_organizations(world)
    await world.admin.set_halted(True, by="rex")
    agent = world.agents["code-web"]
    out = await world.board.list_tasks(agent, mandate_id=world.roots["code-web"])
    assert out["tasks"]  # the default organization still works
    await world.admin.set_halted(True, by="boss")
    with pytest.raises(Exception, match="kill switch"):
        await world.board.list_tasks(agent, mandate_id=world.roots["code-web"])


async def test_entries_without_a_project_go_to_the_organizations_own_chain(world: World) -> None:
    await two_organizations(world)
    await world.admin.add_human("ria", "Ria", "viewer", by="rex")
    async with transaction(world.pool) as conn:
        row = await fetchone(
            conn, "SELECT chain_key, org_id FROM entries WHERE action = 'admin.human.add' ORDER BY id DESC LIMIT 1"
        )
    assert row == {"chain_key": "_system:rival", "org_id": "rival"}
    assert all(v["ok"] for v in await world.admin.verify_log("rival"))
    assert all(v["ok"] for v in await world.admin.verify_log("default"))


async def test_a_refused_call_naming_another_organizations_project_stays_in_the_callers_log(world: World) -> None:
    """An agent that names another organization's project or task is refused, and the record of
    it goes to its own organization's log: the other organization never sees text it wrote, and its
    own people see the attempt."""
    ids = await two_organizations(world)
    await world.admin.register_agent("code-acme", by="rex", client="code", projects=["acme"])
    async with transaction(world.pool) as conn:
        spy = await get_agent(conn, "code-acme")
        root = await fetchone(conn, "SELECT root_mandate_id FROM agents WHERE id = 'code-acme'")
    assert spy and root
    before = await boss_state(world)
    for call in (
        world.board.post(spy, project_id="web", title="SPY-TEXT", mandate_id=str(root["root_mandate_id"])),
        world.board.list_tasks(spy, mandate_id=str(root["root_mandate_id"]), project_id="web"),
        world.board.claim(spy, task_id=ids["task"], mandate_id=str(root["root_mandate_id"])),
    ):
        with pytest.raises(Exception):  # noqa: B017 — any refusal; where it is logged is what matters
            await call
    async with transaction(world.pool) as conn:
        theirs = await fetchall(conn, "SELECT e.id FROM entries e WHERE e.agent_id = 'code-acme' AND e.org_id = 'default'")
        mine = await fetchall(
            conn, "SELECT chain_key, project_id, task_id FROM entries WHERE agent_id = 'code-acme' AND org_id = 'rival'"
        )
    assert theirs == []
    assert mine and all(r["chain_key"] in ("acme", "_system:rival") and r["project_id"] != "web" for r in mine)
    assert all(str(r["task_id"]) != ids["task"] for r in mine)
    assert await boss_state(world) == before
    assert all(v["ok"] for v in await world.admin.verify_log("default"))
    assert all(v["ok"] for v in await world.admin.verify_log("rival"))


async def test_a_public_key_of_another_organization_is_not_named(world: World) -> None:
    await two_organizations(world)
    await world.admin.register_agent("code-acme", by="rex", client="code", projects=["acme"])
    key = public_key()
    await world.admin.add_agent_key("code-web", key, by="boss")
    with pytest.raises(PactError) as info:
        await world.admin.add_agent_key("code-acme", key, by="rex")
    assert "code-web" not in info.value.message


async def test_an_organization_with_no_log_yet_verifies_nothing(world: World) -> None:
    async with transaction(world.pool) as conn:
        await conn.execute("INSERT INTO orgs (id, name, system_chain) VALUES ('empty', 'Empty', '_system:empty')")
    assert await world.admin.verify_log("empty") == []


# ── the agent (MCP) side ────────────────────────────────────────────────────


async def rival_agent(world: World) -> tuple[Any, str]:
    await world.admin.register_agent("code-acme", by="rex", client="code", projects=["acme"])
    async with transaction(world.pool) as conn:
        spy = await get_agent(conn, "code-acme")
        root = await fetchone(conn, "SELECT root_mandate_id FROM agents WHERE id = 'code-acme'")
    assert spy and root
    return spy, str(root["root_mandate_id"])


async def test_another_organizations_task_cannot_be_probed_as_a_parent(world: World) -> None:
    ids = await two_organizations(world)
    spy, root = await rival_agent(world)
    missing = "00000000-0000-4000-8000-000000000000"
    errors = []
    for parent in (ids["task"], missing):
        with pytest.raises(PactError) as info:
            await world.board.list_tasks(spy, mandate_id=root, filter="all", parent_task_id=parent)
        errors.append((info.value.code, info.value.message.replace(parent, "<id>")))
    assert errors[0] == errors[1] == ("not_found", "task <id> does not exist")


async def test_authority_never_crosses_organizations(world: World) -> None:
    """A mandate whose root person belongs to another organization than its holder is dead, even
    if a row like that got into the table some other way."""
    await two_organizations(world)
    spy, _ = await rival_agent(world)
    async with transaction(world.pool) as conn:
        forged = await issue_root(
            conn,
            human="boss",
            holder="code-acme",
            scope=["task.read@project:acme"],
            limits={},
            delegations=0,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    with pytest.raises(PactError) as info:
        await world.board.list_tasks(spy, mandate_id=forged.id)
    assert info.value.code == "chain_broken" and "crosses organizations" in info.value.message


async def test_each_organization_keeps_its_own_approval_rules(world: World) -> None:
    await two_organizations(world)
    spy, root = await rival_agent(world)
    code = world.agents["code-web"]
    boss_task = await world.board.post(
        code, project_id="web", title="ship", action="deploy.web", mandate_id=world.roots["code-web"]
    )
    assert boss_task["status"] == "auth_required"  # the default organization's rules: deploy.* waits
    # Rival has no rule of its own yet, so the same action goes straight to the board there.
    rival_deploy = await world.board.post(spy, project_id="acme", title="ship", action="deploy.web", mandate_id=root)
    assert rival_deploy["status"] == "submitted"
    async with transaction(world.pool) as conn:
        await conn.execute("INSERT INTO approval_actions (org_id, action) VALUES ('rival', 'task.work')")
    rival_task = await world.board.post(spy, project_id="acme", title="x", mandate_id=root)
    plain = await world.board.post(code, project_id="web", title="x", mandate_id=world.roots["code-web"])
    assert rival_task["status"] == "auth_required" and plain["status"] == "submitted"
