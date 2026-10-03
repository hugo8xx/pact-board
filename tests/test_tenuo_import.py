"""Phase 2 of credential adapters: a Tenuo warrant issued by an outside organization becomes a root mandate."""

import asyncio
import base64
import time
from typing import Any

import pytest
from tenuo import Exact, OneOf, Pattern, Range, SigningKey, Warrant, Wildcard, encode_warrant_stack

from pact.credentials import TrustedRoot
from pact.credentials.tenuo import TenuoFormat
from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError
from pact.keys import b64url, keyring, public_bytes
from pact.mandates import get_mandate, verify_chain
from pact.oauth import ResourceSettings

from .conftest import World
from .oauth_fixtures import Issuer
from .test_admin_api import admin_token, api

pytestmark = pytest.mark.anyio


def key_text(key: SigningKey) -> str:
    return b64url(key.public_key.to_bytes())


def stack(*warrants: Warrant) -> str:
    return encode_warrant_stack(list(warrants))


def warrant(org: SigningKey, holder: SigningKey, ttl: int = 3600, **caps: dict[str, Any]) -> Warrant:
    """A root warrant minted by ``org`` for ``holder``. Default: read and work on web, cost_usd ≤ 7."""
    caps = caps or {
        "task.work": {"project": Exact("web"), "task_id": Wildcard(), "cost_usd": Range.max_value(7)},
        "task.read": {"project": Exact("web")},
    }
    mb = Warrant.mint_builder()
    for tool, cons in caps.items():
        mb = mb.capability(tool, **cons)
    return mb.holder(holder.public_key).ttl(ttl).mint(org)


async def setup(w: World) -> dict[str, SigningKey]:
    """Project web; chat-boss posts there; code-web holds a registered key. ``org`` is the outside
    organization's key, trusted to issue on boss's behalf; ``ann`` is an approver."""
    await w.project("web")
    await w.project("api")
    await w.agent("chat-boss", "chat", ["web"])
    await w.agent("code-web", "code", ["web"])
    await w.admin.add_human("ann", "Ann", "approver", by="boss")
    keys = {"code-web": SigningKey.generate(), "org": SigningKey.generate()}
    await w.admin.add_agent_key("code-web", key_text(keys["code-web"]), by="boss")
    await w.admin.add_trusted_root(key_text(keys["org"]), human="boss", by="boss", label="Acme control plane")
    return keys


async def refused(coro: Any) -> PactError:
    with pytest.raises(PactError) as info:
        await coro
    return info.value


# ── trusted roots ───────────────────────────────────────────────────────────


async def test_only_owners_manage_trusted_roots_and_each_stands_for_a_registered_human(world: World) -> None:
    await world.admin.add_human("ann", "Ann", "approver", by="boss")
    org = SigningKey.generate()
    assert (await refused(world.admin.add_trusted_root(key_text(org), human="boss", by="ann"))).code == "forbidden"
    assert (await refused(world.admin.add_trusted_root(key_text(org), human="nobody", by="boss"))).code == "not_found"
    assert (await refused(world.admin.add_trusted_root("not-a-key", human="boss", by="boss"))).code == "invalid_request"
    out = await world.admin.add_trusted_root(key_text(org), human="ann", by="boss", label="Acme")
    assert out == {"principal": key_text(org), "human": "ann", "label": "Acme"}
    assert (await refused(world.admin.add_trusted_root(key_text(org), human="ann", by="boss"))).code == "invalid_request"
    assert (await refused(world.admin.revoke_trusted_root(key_text(org), by="ann"))).code == "forbidden"
    assert await world.admin.revoke_trusted_root(key_text(org), by="boss") == 1
    [row] = await world.admin.list_trusted_roots()
    assert row["principal"] == key_text(org) and row["human"] == "ann" and row["revoked_at"] is not None
    async with transaction(world.pool) as conn:
        actions = [
            r["action"] for r in await fetchall(conn, "SELECT action FROM entries WHERE action LIKE 'admin.trusted_root%'")
        ]
    assert actions == ["admin.trusted_root.add", "admin.trusted_root.revoke"]


# ── happy path: criteria 10 and ค ─────────────────────────────────────────────


async def test_an_outside_warrant_becomes_a_root_mandate_that_traces_to_its_human(world: World) -> None:
    keys = await setup(world)
    cred = stack(warrant(keys["org"], keys["code-web"]))
    mandate_id = await world.admin.import_credential("code-web", "tenuo", cred, by="ann")

    async with transaction(world.pool) as conn:
        m = await get_mandate(conn, mandate_id)
        row = await fetchone(conn, "SELECT credential FROM mandates WHERE id = %s", (mandate_id,))
    assert m is not None and m.parent_id is None and m.depth == 0
    # The issuer is the human the trusted root stands for, not the approver who imported it.
    assert (m.issuer_kind, m.issuer, m.holder) == ("human", "boss", "code-web")
    assert m.scope == ["task.read@project:web", "task.work@project:web"] and m.limits == {"cost_usd": 7.0}
    assert (m.format, m.issuer_principal) == ("tenuo", key_text(keys["org"]))
    assert m.delegations_left == 2  # not terminal: the board's default, within Tenuo's remaining depth
    assert row is not None and bytes(row["credential"]).decode() == cred

    task = await world.board.post(world.agents["chat-boss"], project_id="web", title="t", mandate_id=world.roots["chat-boss"])
    listed = await world.board.list_tasks(world.agents["code-web"], mandate_id=mandate_id)
    assert task["task_id"] in {t["id"] for t in listed["tasks"]}
    claimed = await world.board.claim(world.agents["code-web"], task_id=task["task_id"], mandate_id=mandate_id)
    assert claimed["status"] == "working"

    async with transaction(world.pool) as conn:
        entries = await fetchall(
            conn,
            "SELECT action, actor, mandate_chain FROM entries WHERE mandate_chain @> ARRAY[%s::uuid] ORDER BY id",
            (mandate_id,),
        )
        root_issuers = await fetchall(
            conn,
            """SELECT DISTINCT m.issuer_kind, m.issuer FROM entries e JOIN mandates m ON m.id = e.mandate_chain[1]
               WHERE e.mandate_chain @> ARRAY[%s::uuid]""",
            (mandate_id,),
        )
    assert [e["action"] for e in entries] == ["admin.credential.import", "pact_list", "pact_claim"]
    assert entries[0]["actor"] == "human:ann"
    assert root_issuers == [{"issuer_kind": "human", "issuer": "boss"}]  # criterion 10


async def test_a_terminal_warrant_cannot_be_delegated_on_the_board(world: World) -> None:
    keys = await setup(world)
    org_agent = SigningKey.generate()
    root = warrant(keys["org"], org_agent)
    leaf = (
        root.grant_builder()
        .capability("task.work", project=Exact("web"), task_id=Wildcard(), cost_usd=Range.max_value(3))
        .holder(keys["code-web"].public_key)
        .ttl(600)
        .terminal()
        .grant(org_agent)
    )
    mandate_id = await world.admin.import_credential("code-web", "tenuo", stack(root, leaf), by="boss")
    async with transaction(world.pool) as conn:
        m = await get_mandate(conn, mandate_id)
    assert m is not None and m.delegations_left == 0 and m.external_id == leaf.id
    assert m.scope == ["task.work@project:web"] and m.limits == {"cost_usd": 3.0}
    assert abs((m.expires_at.timestamp() - time.time()) - 600) < 10  # the leaf's expiry


# ── criterion ค: only trusted roots, and revoking one stops what was imported under it ─


async def test_a_warrant_from_an_untrusted_or_revoked_root_is_refused(world: World) -> None:
    keys = await setup(world)
    stranger = SigningKey.generate()
    err = await refused(world.admin.import_credential("code-web", "tenuo", stack(warrant(stranger, keys["code-web"])), by="boss"))
    assert err.code == "chain_broken" and "not a trusted root" in err.message

    # A valid grant from a trusted root, sent without the root: the chain must start at a trusted key.
    org_agent = SigningKey.generate()
    root = warrant(keys["org"], org_agent)
    leaf = root.grant_builder().capability("task.read", project=Exact("web")).holder(keys["code-web"].public_key).ttl(60)
    leaf_only = await refused(world.admin.import_credential("code-web", "tenuo", stack(leaf.grant(org_agent)), by="boss"))
    assert leaf_only.code == "chain_broken"

    # A warrant from the trusted root with one signature byte flipped.
    raw = bytearray(base64.b64decode(stack(warrant(keys["org"], keys["code-web"]))))
    raw[-10] ^= 1
    err = await refused(world.admin.import_credential("code-web", "tenuo", base64.b64encode(bytes(raw)).decode(), by="boss"))
    assert err.code == "chain_broken" and "signature" in err.message

    await world.admin.revoke_trusted_root(key_text(keys["org"]), by="boss")
    err = await refused(
        world.admin.import_credential("code-web", "tenuo", stack(warrant(keys["org"], keys["code-web"])), by="boss")
    )
    assert err.code == "chain_broken"


async def test_revoking_the_trusted_root_stops_mandates_imported_under_it(world: World) -> None:
    keys = await setup(world)
    mandate_id = await world.admin.import_credential(
        "code-web", "tenuo", stack(warrant(keys["org"], keys["code-web"])), by="boss"
    )
    await world.board.list_tasks(world.agents["code-web"], mandate_id=mandate_id)

    await world.admin.revoke_trusted_root(key_text(keys["org"]), by="boss")
    err = await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=mandate_id))
    assert err.code == "mandate_revoked" and err.mandate_id == mandate_id
    # The agent's own board-issued root is untouched.
    await world.board.list_tasks(world.agents["code-web"], mandate_id=world.roots["code-web"])


async def test_the_issuing_key_is_signed_into_the_row(world: World) -> None:
    keys = await setup(world)
    mandate_id = await world.admin.import_credential(
        "code-web", "tenuo", stack(warrant(keys["org"], keys["code-web"])), by="boss"
    )
    other = SigningKey.generate()
    await world.admin.add_trusted_root(key_text(other), human="boss", by="boss")
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE mandates SET issuer_principal = %s WHERE id = %s", (key_text(other), mandate_id))
    err = await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=mandate_id))
    assert err.code == "chain_broken" and "signature" in err.message


async def test_an_expired_warrant_is_refused(world: World) -> None:
    keys = await setup(world)
    old = warrant(keys["org"], keys["code-web"], ttl=1)
    await asyncio.sleep(1.5)
    err = await refused(world.admin.import_credential("code-web", "tenuo", stack(old), by="boss"))
    assert err.code == "chain_broken" and "expired" in err.message


# ── refusals ────────────────────────────────────────────────────────────────


async def test_the_warrant_must_be_held_by_one_of_the_agents_live_keys(world: World) -> None:
    keys = await setup(world)
    someone = SigningKey.generate()
    err = await refused(world.admin.import_credential("code-web", "tenuo", stack(warrant(keys["org"], someone)), by="boss"))
    assert err.code == "invalid_request" and "live key" in err.message

    async with transaction(world.pool) as conn:
        kid = (await fetchone(conn, "SELECT kid FROM agent_keys WHERE agent_id = 'code-web'"))["kid"]  # type: ignore[index]
    await world.admin.revoke_agent_key("code-web", kid, by="boss")
    err = await refused(
        world.admin.import_credential("code-web", "tenuo", stack(warrant(keys["org"], keys["code-web"])), by="boss")
    )
    assert err.code == "invalid_request"


async def test_scope_outside_the_agents_projects_is_refused(world: World) -> None:
    keys = await setup(world)
    caps = {"task.work": {"project": OneOf(["web", "api"]), "task_id": Wildcard()}}
    err = await refused(
        world.admin.import_credential("code-web", "tenuo", stack(warrant(keys["org"], keys["code-web"], **caps)), by="boss")
    )
    assert err.code == "project_mismatch" and "task.work@project:api" in err.message


@pytest.mark.parametrize(
    ("caps", "why"),
    [
        ({"task.work": {"task_id": Wildcard()}}, "no project constraint"),
        ({"task.work": {"project": Pattern("web*")}}, "Exact or OneOf"),
        ({"task.work": {"project": Exact("web"), "branch": Exact("main")}}, "no ledger equivalent"),
        ({"task.work": {"project": Exact("web"), "branch": Wildcard()}}, "no ledger equivalent"),
        ({"task.work": {"project": Exact("web"), "cost_usd": Range(min=1, max=5)}}, "no ledger equivalent"),
        ({"*": {"project": Exact("web")}}, "wildcard"),
        ({"task.*": {"project": Exact("web")}}, "wildcard"),
    ],
)
async def test_warrants_the_ledger_cannot_hold_are_refused(world: World, caps: dict[str, Any], why: str) -> None:
    keys = await setup(world)
    err = await refused(
        world.admin.import_credential("code-web", "tenuo", stack(warrant(keys["org"], keys["code-web"], **caps)), by="boss")
    )
    assert err.code == "invalid_request" and why in err.message


async def test_import_needs_an_approver_a_known_format_and_a_fresh_credential(world: World) -> None:
    keys = await setup(world)
    await world.admin.add_human("vic", "Vic", "viewer", by="boss")
    cred = stack(warrant(keys["org"], keys["code-web"]))
    assert (await refused(world.admin.import_credential("code-web", "tenuo", cred, by="vic"))).code == "forbidden"
    assert (await refused(world.admin.import_credential("code-web", "nope", cred, by="boss"))).code == "invalid_request"
    assert (await refused(world.admin.import_credential("ghost", "tenuo", cred, by="boss"))).code == "not_found"
    assert (await refused(world.admin.import_credential("code-web", "tenuo", "garbage!!", by="boss"))).code == "invalid_request"
    await world.admin.import_credential("code-web", "tenuo", cred, by="boss")
    err = await refused(world.admin.import_credential("code-web", "tenuo", cred, by="boss"))
    assert err.code == "invalid_request" and "already on the board" in err.message


# ── criterion 28: only people revoke an imported root ─────────────────────────


async def test_agents_cannot_revoke_an_imported_root_but_people_can(world: World) -> None:
    keys = await setup(world)
    mandate_id = await world.admin.import_credential(
        "code-web", "tenuo", stack(warrant(keys["org"], keys["code-web"])), by="boss"
    )
    for agent in ("code-web", "chat-boss"):
        assert (await refused(world.board.revoke(world.agents[agent], mandate_id=mandate_id))).code == "not_issuer"
    await world.board.list_tasks(world.agents["code-web"], mandate_id=mandate_id)

    await world.admin.revoke_mandate(mandate_id, by="ann")
    err = await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=mandate_id))
    assert err.code == "mandate_revoked"


# ── round trip: what the board exports maps back to the same authority ───────


async def test_a_chain_the_board_exported_maps_back_to_the_same_scope_and_limits(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PACT_EXPORT_FORMAT", "tenuo")
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])
    await world.agent("code-web", "code", ["web"], limits={"cost_usd": 10, "tokens": 5000})
    agent_key = SigningKey.generate()
    await world.admin.add_agent_key("code-web", key_text(agent_key), by="boss")
    task = await world.board.post(world.agents["chat-boss"], project_id="web", title="t", mandate_id=world.roots["chat-boss"])
    out = await world.board.claim(world.agents["code-web"], task_id=task["task_id"], mandate_id=world.roots["code-web"])
    cred = out["credential"]["warrant_stack"]

    board = b64url(public_bytes(keyring().keys[keyring().active].public_key()))
    got = TenuoFormat().ingest(cred.encode(), trusted_roots=[TrustedRoot(principal=board, human="boss")])
    async with transaction(world.pool) as conn:
        chain = await verify_chain(conn, world.roots["code-web"], "code-web")
    assert got.scope == sorted(chain.leaf.scope)
    assert got.limits == chain.leaf.limits == {"cost_usd": 10.0, "tokens": 5000.0}
    assert (got.human, got.issuer_principal, got.holder_key) == ("boss", board, key_text(agent_key))
    assert got.external_id == out["credential"]["external_id"]
    # The board's own export is already on the ledger, so importing it again is refused.
    await world.admin.add_trusted_root(board, human="boss", by="boss")
    err = await refused(world.admin.import_credential("code-web", "tenuo", cred, by="boss"))
    assert err.code == "invalid_request" and "already on the board" in err.message


# ── Admin API ───────────────────────────────────────────────────────────────


async def test_admin_api_manages_trusted_roots_and_imports(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    keys = await setup(world)
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE humans SET email = 'boss@example.com' WHERE id = 'boss'")
    boss = admin_token(issuer, settings)
    other = SigningKey.generate()
    r = await api(url, "POST", "/trusted-roots", boss, {"public_key": key_text(other), "human": "boss", "label": "Beta"})
    assert r.status_code == 200 and r.json()["principal"] == key_text(other)
    listed = (await api(url, "GET", "/trusted-roots", boss)).json()
    assert {t["principal"] for t in listed} == {key_text(keys["org"]), key_text(other)}

    cred = stack(warrant(keys["org"], keys["code-web"]))
    r = await api(url, "POST", "/agents/code-web/credentials", boss, {"format": "tenuo", "credential": cred})
    assert r.status_code == 200
    mandate_id = r.json()["mandate_id"]
    r = await api(url, "POST", "/agents/code-web/credentials", boss, {"format": "tenuo", "credential": cred})
    assert r.status_code == 400

    r = await api(url, "DELETE", f"/trusted-roots/{key_text(keys['org'])}", boss)
    assert r.status_code == 200 and r.json() == {"revoked": 1}
    err = await refused(world.board.list_tasks(world.agents["code-web"], mandate_id=mandate_id))
    assert err.code == "mandate_revoked"
