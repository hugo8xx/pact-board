"""Phase 1 of credential adapters: the ledger exported as Tenuo warrants on claim, revocation reaching outside verifiers."""

import importlib.util
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx2
import pytest
from mcp import Client
from tenuo import Authorizer, SignedRevocationList, SigningKey, Warrant, decode_warrant_stack_base64, encode_warrant_stack
from tenuo.mcp import MCPVerifier
from tenuo.meta import argument_json
from tenuo_core import sign_meta

from pact import credentials
from pact.credentials.tenuo import MAX_WARRANT_TTL_SECS, TenuoFormat, capabilities, trusted_roots, trusted_roots_from_jwks
from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError
from pact.keys import b64url, keyring, new_seed
from pact.mandates import get_mandate

from .conftest import HANDOFF, World
from .test_http import server_url  # noqa: F401 — fixture

pytestmark = pytest.mark.anyio

FMT = "tenuo"
CAN_POST = ["task.work@project:web", "task.read@project:web", "task.post@project:web"]


@pytest.fixture(autouse=True)
def export_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACT_EXPORT_FORMAT", FMT)


async def setup(w: World, *, chat_limits: dict[str, float] | None = None) -> dict[str, SigningKey]:
    """chat-boss posts; code-web and code-web-2 work in web and hold registered keys."""
    await w.project("web")
    await w.agent("chat-boss", "chat", ["web"], limits=chat_limits)
    keys = {}
    for aid in ("code-web", "code-web-2"):
        await w.agent(aid, "code", ["web"])
        keys[aid] = SigningKey.generate()
        await w.admin.add_agent_key(aid, b64url(keys[aid].public_key.to_bytes()), by="boss")
    return keys


async def delegated_claim(w: World, poster: str, mandate: str, to: str, **post: Any) -> dict[str, Any]:
    """``poster`` posts a task delegated to ``to``, which claims it with the delegated mandate."""
    t = await w.board.post(w.agents[poster], project_id="web", title="work", mandate_id=mandate, delegate_to=to, **post)
    out = await w.board.claim(w.agents[to], task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    return {**out, "mandate_id": t["delegated_mandate_id"]}


async def srl(w: World) -> SignedRevocationList:
    async with transaction(w.pool) as conn:
        revoked, version = await credentials.revocation_state(conn, FMT)
    return SignedRevocationList.from_bytes(TenuoFormat().revocation_list(revoked, keyring=keyring(), version=version))


def verifier(revocations: SignedRevocationList | None = None, roots: Any = None) -> MCPVerifier:
    """An outside verifier: only the board's public keys, and its revocation list."""
    auth = Authorizer(trusted_roots=roots or trusted_roots(keyring()))
    if revocations is not None:
        auth.set_revocation_list(revocations)
    return MCPVerifier(authorizer=auth)


def meta(stack: str, key: SigningKey, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """What an agent attaches as ``params._meta``: the stack and its proof of possession over the
    argument JSON (Tenuo's canonical text, where 5.0 is written 5)."""
    chain = decode_warrant_stack_base64(stack)
    return {"tenuo": sign_meta(chain, key, tool, argument_json(args), int(time.time()))}


def allowed(v: MCPVerifier, cred: dict[str, Any], key: SigningKey, tool: str = "task.work", **args: Any) -> bool:
    call = {"project": "web", "task_id": "T-1", **args}
    return bool(v.verify(tool, call, meta=meta(cred["warrant_stack"], key, tool, call)).allowed)


async def links_of(w: World, mandate_id: str) -> set[str]:
    async with transaction(w.pool) as conn:
        rows = await fetchall(conn, "SELECT external_id FROM credential_links WHERE mandate_id = %s", (mandate_id,))
    return {r["external_id"] for r in rows}


# ── criterion ก: an exported credential verifies offline and matches the ledger ─────────────


async def test_a_credential_exported_on_claim_verifies_offline_and_matches_the_ledger(world: World) -> None:
    keys = await setup(world, chat_limits={"cost_usd": 50})
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web", child_limits={"cost_usd": 10})
    cred = out["credential"]
    assert cred["format"] == "tenuo"

    stack = decode_warrant_stack_base64(cred["warrant_stack"])
    board = trusted_roots(keyring())[0].to_bytes()
    # One board-held warrant per ledger link (chat-boss root, the delegated link), then the agent's leaf.
    assert len(stack) == 3 and all(w.issuer.to_bytes() == board for w in stack)
    assert [w.authorized_holder.to_bytes() for w in stack[:-1]] == [board, board]
    assert stack[-1].authorized_holder.to_bytes() == keys["code-web"].public_key.to_bytes()
    assert cred["external_id"] == stack[-1].id

    # Scope and expiry come from the ledger link.
    async with transaction(world.pool) as conn:
        mandate = await get_mandate(conn, out["mandate_id"])
        row = await fetchone(conn, "SELECT exported_as, external_id FROM mandates WHERE id = %s", (out["mandate_id"],))
    assert mandate is not None and row == {"exported_as": "tenuo", "external_id": cred["external_id"]}
    assert set(stack[-1].tools) == {"task.work", "task.read"}
    leaf_exp = datetime.fromisoformat(stack[-1].expires_at())
    assert abs((leaf_exp - mandate.expires_at).total_seconds()) < 5
    assert stack[-1].is_terminal() is False  # the delegated link may still delegate once

    v = verifier()
    assert allowed(v, cred, keys["code-web"], cost_usd=5.0)
    assert allowed(v, cred, keys["code-web"], "task.read", cost_usd=0.0)  # every limit applies to every tool
    assert not allowed(v, cred, keys["code-web"], "task.read")
    # Outside the scope: another tool, another project, over the limit, an unknown argument, someone else's key.
    assert not allowed(v, cred, keys["code-web"], "task.post")
    assert not allowed(v, cred, keys["code-web"], project="api", cost_usd=5.0)
    assert not allowed(v, cred, keys["code-web"], cost_usd=11.0)
    assert not allowed(v, cred, keys["code-web"], cost_usd=5.0, branch="main")
    assert not allowed(v, cred, keys["code-web-2"], cost_usd=5.0)
    # And a verifier that does not trust the board refuses it.
    assert not allowed(verifier(roots=[SigningKey.generate().public_key]), cred, keys["code-web"], cost_usd=5.0)


async def test_the_leaf_is_terminal_when_the_ledger_link_has_no_delegations_left(world: World) -> None:
    keys = await setup(world)
    first = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web", child_scope=CAN_POST)  # 2 → 1
    second = await delegated_claim(world, "code-web", first["mandate_id"], "code-web-2")  # grandchild has 0
    leaf = decode_warrant_stack_base64(second["credential"]["warrant_stack"])[-1]
    assert leaf.is_terminal()
    with pytest.raises(Exception) as info:  # noqa: B017 — the holder cannot extend it offline either
        (
            leaf.grant_builder()
            .capability("task.work", **capabilities(["task.work@project:web"], {})["task.work"])
            .holder(keys["code-web"].public_key)
            .ttl(60)
            .grant(keys["code-web-2"])
        )
    assert type(info.value).__name__ == "DepthExceeded"


async def test_ttl_is_capped_at_tenuos_maximum(world: World) -> None:
    await setup(world)
    long = await world.agent("code-long", "code", ["web"], mandate_days=200)
    key = SigningKey.generate()
    await world.admin.add_agent_key("code-long", b64url(key.public_key.to_bytes()), by="boss")
    t = await world.board.post(world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"])
    out = await world.board.claim(long, task_id=t["task_id"], mandate_id=world.roots["code-long"])
    leaf = decode_warrant_stack_base64(out["credential"]["warrant_stack"])[-1]
    assert datetime.fromisoformat(leaf.expires_at()) <= datetime.now(UTC) + timedelta(seconds=MAX_WARRANT_TTL_SECS + 5)
    assert allowed(verifier(), out["credential"], key)


def test_one_action_on_several_projects_becomes_one_of() -> None:
    caps = capabilities(["task.work@project:web", "task.work@project:api", "task.read@project:web"], {"cost_usd": 3})
    assert repr(caps["task.work"]["project"]) == 'OneOf([String("api"), String("web")])'
    assert repr(caps["task.read"]["project"]).startswith("Exact")
    assert set(caps["task.work"]) == {"project", "task_id", "cost_usd"}


# ── when no credential is issued, the claim still works ───────────────────────────────────


async def test_without_a_key_the_claim_works_and_says_why_no_credential(world: World) -> None:
    await setup(world)
    await world.agent("code-nokey", "code", ["web"])
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-nokey")
    assert out["ok"] and out["status"] == "working" and "credential" not in out
    assert "no registered public key" in out["credential_note"]


async def test_a_wildcard_scope_is_not_exported_and_the_note_names_it(world: World) -> None:
    await setup(world)
    agent = await world.agent("code-wild", "code", ["web"], scope=["task.*@project:web"])
    await world.admin.add_agent_key("code-wild", b64url(SigningKey.generate().public_key.to_bytes()), by="boss")
    t = await world.board.post(world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"])
    out = await world.board.claim(agent, task_id=t["task_id"], mandate_id=world.roots["code-wild"])
    assert out["status"] == "working" and "credential" not in out
    assert "task.*@project:web" in out["credential_note"]
    assert await links_of(world, world.roots["code-wild"]) == set()


async def test_minting_refuses_with_the_codes_agents_know(world: World) -> None:
    await setup(world)
    await world.agent("code-wild", "code", ["web"], scope=["task.*@project:web"])
    async with transaction(world.pool) as conn:
        from pact.mandates import verify_chain

        chain = await verify_chain(conn, world.roots["code-wild"], "code-wild")
    with pytest.raises(PactError) as info:
        TenuoFormat().mint(chain, keyring=keyring(), holder_keys={})
    assert info.value.code == "invalid_request"
    with pytest.raises(PactError) as info:
        TenuoFormat().mint(chain, keyring=keyring(), holder_keys={"code-wild": b"\x01" * 32})
    assert info.value.code == "invalid_request" and "cannot be exported" in info.value.message
    with pytest.raises(PactError) as info:
        TenuoFormat().ingest(b"", trusted_roots=[])
    assert info.value.code == "invalid_request" and "phase 2" in info.value.message


async def test_an_export_failure_never_fails_the_claim(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    await setup(world)

    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(TenuoFormat, "mint", boom)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    assert out["status"] == "working" and "export failed" in out["credential_note"]


async def test_with_the_env_unset_claim_output_is_unchanged(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PACT_EXPORT_FORMAT")
    await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    out.pop("mandate_id")
    assert out == {"ok": True, "task_id": out["task_id"], "status": "working"}
    assert await links_of(world, world.roots["chat-boss"]) == set()


# ── criteria 7, 8: the board refuses before anything is minted ────────────────────────────


async def test_the_board_refuses_a_child_before_any_export(world: World) -> None:
    await setup(world)
    await world.agent("chat-nodelegate", "chat", ["web"], delegations=0)
    with pytest.raises(PactError) as info:
        await delegated_claim(world, "chat-nodelegate", world.roots["chat-nodelegate"], "code-web")
    assert info.value.code == "delegation_exhausted"
    with pytest.raises(PactError) as info:
        await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web", child_scope=["context.write@project:web"])
    assert info.value.code == "scope_exceeded"
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT count(*) AS n FROM credential_links")
    assert row == {"n": 0}


# ── criterion ข and 9: revoking on the board reaches outside verifiers ─────────────────────


async def chain_of_three(w: World) -> dict[str, Any]:
    """chat-boss root → task for code-web → subtask for code-web-2 (two siblings)."""
    keys = await setup(w)
    top = await delegated_claim(w, "chat-boss", w.roots["chat-boss"], "code-web", child_scope=CAN_POST)
    a = await delegated_claim(w, "code-web", top["mandate_id"], "code-web-2")
    b = await delegated_claim(w, "code-web", top["mandate_id"], "code-web-2")
    return {"keys": keys, "top": top, "a": a, "b": b}


async def test_revoking_the_leaf_with_pact_revoke_denies_it_and_spares_its_sibling(world: World) -> None:
    c = await chain_of_three(world)
    key = c["keys"]["code-web-2"]
    assert allowed(verifier(await srl(world)), c["a"]["credential"], key)

    await world.board.revoke(world.agents["code-web"], mandate_id=c["a"]["mandate_id"])
    revocations = await srl(world)
    assert c["a"]["credential"]["external_id"] in revocations.revoked_ids
    v = verifier(revocations)
    assert not allowed(v, c["a"]["credential"], key)
    assert allowed(v, c["b"]["credential"], key)
    assert allowed(v, c["top"]["credential"], c["keys"]["code-web"])


async def test_revoking_a_middle_link_revokes_every_descendants_warrants(world: World) -> None:
    c = await chain_of_three(world)
    await world.board.revoke(world.agents["chat-boss"], mandate_id=c["top"]["mandate_id"])
    revocations = await srl(world)
    v = verifier(revocations)
    for name, holder in (("top", "code-web"), ("a", "code-web-2"), ("b", "code-web-2")):
        assert not allowed(v, c[name]["credential"], c["keys"][holder]), name
        # every warrant minted for the descendant links is listed, not only the cascade through the middle
        assert await links_of(world, c[name]["mandate_id"]) <= set(revocations.revoked_ids)


async def test_revoking_the_root_in_the_admin_denies_everything_under_it(world: World) -> None:
    c = await chain_of_three(world)
    before = (await srl(world)).version
    await world.admin.revoke_mandate(world.roots["chat-boss"], by="boss")
    revocations = await srl(world)
    assert revocations.version > before
    v = verifier(revocations)
    assert not allowed(v, c["a"]["credential"], c["keys"]["code-web-2"])
    assert not allowed(v, c["top"]["credential"], c["keys"]["code-web"])


async def test_closing_the_task_revokes_its_credential(world: World) -> None:
    c = await chain_of_three(world)
    task_id = c["a"]["task_id"]
    await world.board.report(
        world.agents["code-web-2"], task_id=task_id, status="completed", mandate_id=c["a"]["mandate_id"], result=HANDOFF
    )
    v = verifier(await srl(world))
    assert not allowed(v, c["a"]["credential"], c["keys"]["code-web-2"])
    assert allowed(v, c["b"]["credential"], c["keys"]["code-web-2"])


async def test_reassigning_a_task_revokes_the_previous_agents_credential(world: World) -> None:
    keys = await setup(world)
    t = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"], delegate_to="code-web"
    )
    out = await world.board.claim(world.agents["code-web"], task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    await world.admin.release_task(t["task_id"], by="boss")
    await world.admin.assign_task(t["task_id"], "code-web-2", by="boss")
    assert not allowed(verifier(await srl(world)), out["credential"], keys["code-web"])


async def test_each_export_mints_new_ids_and_revoking_finds_them_all(world: World) -> None:
    keys = await setup(world)
    first = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    # claim again under the same mandate (released, claimed again): a second set of warrant ids
    await world.admin.release_task(first["task_id"], by="boss")
    again = await world.board.claim(world.agents["code-web"], task_id=first["task_id"], mandate_id=first["mandate_id"])
    assert again["credential"]["external_id"] != first["credential"]["external_id"]
    assert len(await links_of(world, first["mandate_id"])) == 4  # two warrants per export for this link

    await world.board.revoke(world.agents["chat-boss"], mandate_id=first["mandate_id"])
    v = verifier(await srl(world))
    assert not allowed(v, first["credential"], keys["code-web"])
    assert not allowed(v, again["credential"], keys["code-web"])


# ── key rotation ──────────────────────────────────────────────────────────────────────────


async def test_a_credential_survives_rotation_while_the_old_key_is_trusted(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    old, new = new_seed(), new_seed()
    monkeypatch.setenv("PACT_BOARD_KEYS", f"k1={old}")
    keys = await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")

    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new},k1={old}")
    revocations = await srl(world)  # now signed by k2
    assert allowed(verifier(revocations), out["credential"], keys["code-web"])
    assert allowed(verifier(revocations, roots=trusted_roots_from_jwks(keyring().jwks())), out["credential"], keys["code-web"])

    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new}")  # k1 dropped: what it signed stops verifying
    assert not allowed(verifier(), out["credential"], keys["code-web"])


# ── the published list ────────────────────────────────────────────────────────────────────


async def test_the_signed_revocation_list_is_published(world: World, server_url: str) -> None:  # noqa: F811
    c = await chain_of_three(world)
    await world.board.revoke(world.agents["code-web"], mandate_id=c["a"]["mandate_id"])
    async with httpx2.AsyncClient(timeout=10) as http:
        r = await http.get(f"{server_url}/.well-known/pact-revocations/tenuo")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream" and r.headers["access-control-allow-origin"] == "*"
    published = SignedRevocationList.from_bytes(r.content)
    published.verify(trusted_roots(keyring())[0])
    assert int(r.headers["x-pact-revocations-version"]) == published.version >= 1
    assert c["a"]["credential"]["external_id"] in published.revoked_ids


# ── the example verifier, in process ──────────────────────────────────────────────────────


def example() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "examples" / "tenuo_verifier" / "server.py"
    spec = importlib.util.spec_from_file_location("tenuo_verifier_example", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_the_example_verifier_accepts_board_credentials_and_follows_revocations(world: World) -> None:
    ex = example()
    c = await chain_of_three(world)
    key = c["keys"]["code-web-2"]
    async with transaction(world.pool) as conn:
        revoked, version = await credentials.revocation_state(conn, FMT)
    trust = ex.BoardTrust()
    trust.load(keyring().jwks(), TenuoFormat().revocation_list(revoked, keyring=keyring(), version=version))
    server = ex.build_server(trust)

    async def call(cred: dict[str, Any], args: dict[str, Any]) -> Any:
        async with Client(server) as client:
            return await client.call_tool("task.work", args, meta=meta(cred["warrant_stack"], key, "task.work", args))

    args = {"project": "web", "task_id": "T-1"}
    ok = await call(c["a"]["credential"], args)
    assert not ok.is_error, ok
    assert ok.structured_content["warrant_id"] == c["a"]["credential"]["external_id"]
    assert (await call(c["a"]["credential"], {**args, "project": "api"})).is_error

    await world.board.revoke(world.agents["code-web"], mandate_id=c["a"]["mandate_id"])
    async with transaction(world.pool) as conn:
        revoked, version = await credentials.revocation_state(conn, FMT)
    trust.load(keyring().jwks(), TenuoFormat().revocation_list(revoked, keyring=keyring(), version=version))
    assert (await call(c["a"]["credential"], args)).is_error
    assert not (await call(c["b"]["credential"], args)).is_error

    # An older list is ignored, and a list nobody refreshed for over a minute refuses everything.
    trust.load(keyring().jwks(), TenuoFormat().revocation_list([], keyring=keyring(), version=0))
    assert (await call(c["a"]["credential"], args)).is_error
    trust.loaded_at = time.monotonic() - 61
    stale = await call(c["b"]["credential"], args)
    assert stale.is_error and "stale" in stale.content[0].text


def test_warrants_round_trip_from_the_published_stack() -> None:
    board = SigningKey.generate()
    w = Warrant.mint_builder().capability("task.work", **capabilities(["task.work@project:web"], {})["task.work"])
    root = w.holder(board.public_key).ttl(60).mint(board)
    assert TenuoFormat().revocation_ids(encode_warrant_stack([root]).encode()) == [root.id]
