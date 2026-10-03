"""One suite every credential format must pass (criterion ง): the format is picked by
``PACT_EXPORT_FORMAT`` alone, and nothing else on the board changes when it is swapped.

Each case runs once per driver in ``credential_drivers``. Format-specific behaviour (Tenuo's
warrant stack and terminal leaf, Biscuit's blocks and bearer semantics) is tested in
``test_tenuo_export.py`` and ``test_biscuit_export.py``.
"""

from typing import Any

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pact import credentials
from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError
from pact.keys import b64url, keyring, new_seed, public_bytes

from .conftest import HANDOFF, World
from .credential_drivers import DRIVERS, Driver
from .test_http import server_url  # noqa: F401 — fixture

pytestmark = pytest.mark.anyio

CAN_POST = ["task.work@project:web", "task.read@project:web", "task.post@project:web"]


@pytest.fixture(params=sorted(DRIVERS))
def driver(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Driver:
    monkeypatch.setenv("PACT_EXPORT_FORMAT", request.param)
    return DRIVERS[request.param]


async def setup(w: World, *, chat_limits: dict[str, float] | None = None) -> dict[str, Ed25519PrivateKey]:
    """chat-boss posts; code-web and code-web-2 work in web and hold registered keys."""
    await w.project("web")
    await w.agent("chat-boss", "chat", ["web"], limits=chat_limits)
    keys = {}
    for aid in ("code-web", "code-web-2"):
        await w.agent(aid, "code", ["web"])
        keys[aid] = Ed25519PrivateKey.generate()
        await w.admin.add_agent_key(aid, b64url(public_bytes(keys[aid].public_key())), by="boss")
    return keys


async def delegated_claim(w: World, poster: str, mandate: str, to: str, **post: Any) -> dict[str, Any]:
    t = await w.board.post(w.agents[poster], project_id="web", title="work", mandate_id=mandate, delegate_to=to, **post)
    out = await w.board.claim(w.agents[to], task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    return {**out, "mandate_id": t["delegated_mandate_id"]}


async def published(w: World, driver: Driver) -> bytes:
    """The revocation list exactly as the board serves it, built in process."""
    async with transaction(w.pool) as conn:
        revoked, version = await credentials.revocation_state(conn, driver.name)
    return credentials.get(driver.name).revocation_list(revoked, keyring=keyring(), version=version)


def ok(
    driver: Driver,
    cred: dict[str, Any],
    key: Ed25519PrivateKey,
    tool: str = "task.work",
    *,
    revocations: bytes | None = None,
    jwks: dict[str, Any] | None = None,
    **args: Any,
) -> bool:
    call = {"project": "web", "task_id": "T-1", **args}
    return driver.verify(cred, tool, call, trusted_jwks=jwks or keyring().jwks(), revocations=revocations, holder_key=key)


async def links_of(w: World, mandate_id: str) -> set[str]:
    async with transaction(w.pool) as conn:
        rows = await fetchall(conn, "SELECT external_id FROM credential_links WHERE mandate_id = %s", (mandate_id,))
    return {r["external_id"] for r in rows}


def untrusted_jwks() -> dict[str, Any]:
    pub = public_bytes(Ed25519PrivateKey.generate().public_key())
    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "stranger", "x": b64url(pub)}]}


# ── export on claim ───────────────────────────────────────────────────────────────────────


async def test_export_on_claim_is_recorded_against_every_ledger_link(world: World, driver: Driver) -> None:
    await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    cred = out["credential"]
    assert cred["format"] == driver.name and set(cred) == {"format", "external_id", driver.field}
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT exported_as, external_id FROM mandates WHERE id = %s", (out["mandate_id"],))
    assert row == {"exported_as": driver.name, "external_id": cred["external_id"]}
    ids = set(driver.revocation_ids(cred))
    assert cred["external_id"] in ids
    root, leaf = await links_of(world, world.roots["chat-boss"]), await links_of(world, out["mandate_id"])
    assert root and leaf and root | leaf == ids and not root & leaf


async def test_in_scope_calls_pass_and_everything_else_is_denied(world: World, driver: Driver) -> None:
    keys = await setup(world, chat_limits={"cost_usd": 50})
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web", child_limits={"cost_usd": 10})
    cred, key = out["credential"], keys["code-web"]
    assert ok(driver, cred, key, cost_usd=5.0)
    assert ok(driver, cred, key, cost_usd=10.0)
    assert ok(driver, cred, key, "task.read", cost_usd=0.0)  # every limit applies to every tool
    assert not ok(driver, cred, key, "task.read")  # a limited argument must be present
    assert not ok(driver, cred, key, "task.post", cost_usd=1.0)  # another tool
    assert not ok(driver, cred, key, project="api", cost_usd=1.0)  # another project
    assert not ok(driver, cred, key, cost_usd=11.0)  # over the per-call limit (child's, under the root's 50)
    assert not ok(driver, cred, key, cost_usd=1.0, branch="main")  # an argument nobody constrained


async def test_a_verifier_that_does_not_trust_the_board_refuses(world: World, driver: Driver) -> None:
    keys = await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    assert ok(driver, out["credential"], keys["code-web"])
    assert not ok(driver, out["credential"], keys["code-web"], jwks=untrusted_jwks())


async def test_proof_of_possession_refuses_another_agents_key(world: World, driver: Driver) -> None:
    if not driver.supports_pop:
        pytest.skip(f"{driver.name} has no proof of possession: its credential is a bearer token")
    keys = await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    assert ok(driver, out["credential"], keys["code-web"])
    assert not ok(driver, out["credential"], keys["code-web-2"])


async def test_without_proof_of_possession_any_bearer_is_accepted(world: World, driver: Driver) -> None:
    """The documented gap, pinned so it is never mistaken for a binding."""
    if driver.supports_pop:
        pytest.skip(f"{driver.name} proves possession")
    keys = await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    assert ok(driver, out["credential"], keys["code-web-2"])


# ── when no credential is issued, the claim still works ───────────────────────────────────


async def test_without_a_key_the_claim_works_and_says_why(world: World, driver: Driver) -> None:
    await setup(world)
    await world.agent("code-nokey", "code", ["web"])
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-nokey")
    assert out["ok"] and out["status"] == "working" and "credential" not in out
    assert out["credential_note"].startswith(f"no {driver.name} credential")
    assert "no registered public key" in out["credential_note"]


async def test_a_wildcard_scope_is_not_exported_and_the_note_names_it(world: World, driver: Driver) -> None:
    await setup(world)
    agent = await world.agent("code-wild", "code", ["web"], scope=["task.*@project:web"])
    await world.admin.add_agent_key("code-wild", b64url(public_bytes(Ed25519PrivateKey.generate().public_key())), by="boss")
    t = await world.board.post(world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"])
    out = await world.board.claim(agent, task_id=t["task_id"], mandate_id=world.roots["code-wild"])
    assert out["status"] == "working" and "credential" not in out
    assert "task.*@project:web" in out["credential_note"]
    assert await links_of(world, world.roots["code-wild"]) == set()


async def test_an_export_failure_never_fails_the_claim(world: World, driver: Driver, monkeypatch: pytest.MonkeyPatch) -> None:
    await setup(world)

    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(driver.format_cls, "mint", boom)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    assert out["status"] == "working" and "export failed" in out["credential_note"]


async def test_ingest_refuses_cleanly(driver: Driver) -> None:
    with pytest.raises(PactError) as info:
        driver.format_cls().ingest(b"", trusted_roots=[])
    assert info.value.code == "invalid_request"


async def test_the_board_refuses_a_child_before_any_export(world: World, driver: Driver) -> None:
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


# ── revoking on the board reaches outside verifiers ───────────────────────────────────────


async def chain_of_three(w: World) -> dict[str, Any]:
    """chat-boss root → task for code-web → subtask for code-web-2 (two siblings)."""
    keys = await setup(w)
    top = await delegated_claim(w, "chat-boss", w.roots["chat-boss"], "code-web", child_scope=CAN_POST)
    a = await delegated_claim(w, "code-web", top["mandate_id"], "code-web-2")
    b = await delegated_claim(w, "code-web", top["mandate_id"], "code-web-2")
    return {"keys": keys, "top": top, "a": a, "b": b}


async def test_revoking_the_leaf_denies_it_and_spares_its_sibling(world: World, driver: Driver) -> None:
    c = await chain_of_three(world)
    key = c["keys"]["code-web-2"]
    assert ok(driver, c["a"]["credential"], key, revocations=await published(world, driver))

    await world.board.revoke(world.agents["code-web"], mandate_id=c["a"]["mandate_id"])
    srl = await published(world, driver)
    revoked, _ = driver.listed(srl, keyring().jwks())
    assert c["a"]["credential"]["external_id"] in revoked
    assert not ok(driver, c["a"]["credential"], key, revocations=srl)
    assert ok(driver, c["b"]["credential"], key, revocations=srl)
    assert ok(driver, c["top"]["credential"], c["keys"]["code-web"], revocations=srl)


async def test_revoking_a_middle_link_denies_every_descendant(world: World, driver: Driver) -> None:
    c = await chain_of_three(world)
    await world.board.revoke(world.agents["chat-boss"], mandate_id=c["top"]["mandate_id"])
    srl = await published(world, driver)
    revoked, _ = driver.listed(srl, keyring().jwks())
    for name, holder in (("top", "code-web"), ("a", "code-web-2"), ("b", "code-web-2")):
        assert not ok(driver, c[name]["credential"], c["keys"][holder], revocations=srl), name
        # every id minted for the descendant links is listed, not only the cascade through the middle
        assert await links_of(world, c[name]["mandate_id"]) <= revoked


async def test_revoking_the_root_denies_everything_under_it(world: World, driver: Driver) -> None:
    c = await chain_of_three(world)
    _, before = driver.listed(await published(world, driver), keyring().jwks())
    await world.admin.revoke_mandate(world.roots["chat-boss"], by="boss")
    srl = await published(world, driver)
    _, after = driver.listed(srl, keyring().jwks())
    assert after > before
    assert not ok(driver, c["a"]["credential"], c["keys"]["code-web-2"], revocations=srl)
    assert not ok(driver, c["top"]["credential"], c["keys"]["code-web"], revocations=srl)


async def test_closing_the_task_revokes_its_credential(world: World, driver: Driver) -> None:
    c = await chain_of_three(world)
    await world.board.report(
        world.agents["code-web-2"], task_id=c["a"]["task_id"], status="completed", mandate_id=c["a"]["mandate_id"], result=HANDOFF
    )
    srl = await published(world, driver)
    assert not ok(driver, c["a"]["credential"], c["keys"]["code-web-2"], revocations=srl)
    assert ok(driver, c["b"]["credential"], c["keys"]["code-web-2"], revocations=srl)


async def test_reassigning_a_task_revokes_the_previous_agents_credential(world: World, driver: Driver) -> None:
    keys = await setup(world)
    t = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="x", mandate_id=world.roots["chat-boss"], delegate_to="code-web"
    )
    out = await world.board.claim(world.agents["code-web"], task_id=t["task_id"], mandate_id=t["delegated_mandate_id"])
    await world.admin.release_task(t["task_id"], by="boss")
    await world.admin.assign_task(t["task_id"], "code-web-2", by="boss")
    assert not ok(driver, out["credential"], keys["code-web"], revocations=await published(world, driver))


async def test_each_export_mints_new_ids_and_revoking_finds_them_all(world: World, driver: Driver) -> None:
    keys = await setup(world)
    first = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    await world.admin.release_task(first["task_id"], by="boss")
    again = await world.board.claim(world.agents["code-web"], task_id=first["task_id"], mandate_id=first["mandate_id"])
    assert again["credential"]["external_id"] != first["credential"]["external_id"]
    assert len(await links_of(world, first["mandate_id"])) == 2 * driver.ids_per_leaf_link

    await world.board.revoke(world.agents["chat-boss"], mandate_id=first["mandate_id"])
    srl = await published(world, driver)
    assert not ok(driver, first["credential"], keys["code-web"], revocations=srl)
    assert not ok(driver, again["credential"], keys["code-web"], revocations=srl)


async def test_the_revocation_list_is_published_for_the_format(world: World, driver: Driver, server_url: str) -> None:  # noqa: F811
    c = await chain_of_three(world)
    await world.board.revoke(world.agents["code-web"], mandate_id=c["a"]["mandate_id"])
    async with httpx2.AsyncClient(timeout=10) as http:
        r = await http.get(f"{server_url}/.well-known/pact-revocations/{driver.name}")
        jwks = (await http.get(f"{server_url}/.well-known/pact-keys.json")).json()
        missing = await http.get(f"{server_url}/.well-known/pact-revocations/no-such-format")
    assert r.status_code == 200
    assert r.headers["content-type"] == driver.content_type and r.headers["access-control-allow-origin"] == "*"
    assert r.headers["cache-control"] == "no-store"
    revoked, version = driver.listed(r.content, jwks)
    assert int(r.headers["x-pact-revocations-version"]) == version >= 1
    assert c["a"]["credential"]["external_id"] in revoked
    # An outside verifier with nothing but the two public documents refuses the revoked leaf.
    key = c["keys"]["code-web-2"]
    assert not ok(driver, c["a"]["credential"], key, revocations=r.content, jwks=jwks)
    assert ok(driver, c["b"]["credential"], key, revocations=r.content, jwks=jwks)
    assert missing.status_code == 404


async def test_a_list_signed_by_a_stranger_is_rejected(world: World, driver: Driver) -> None:
    await setup(world)
    srl = await published(world, driver)
    with pytest.raises(Exception):  # noqa: B017 — each format raises its own error
        driver.listed(srl, untrusted_jwks())


# ── key rotation ──────────────────────────────────────────────────────────────────────────


async def test_a_credential_survives_rotation_while_the_old_key_is_trusted(
    world: World, driver: Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, new = new_seed(), new_seed()
    monkeypatch.setenv("PACT_BOARD_KEYS", f"k1={old}")
    keys = await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")

    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new},k1={old}")
    srl = await published(world, driver)  # now signed by k2
    assert ok(driver, out["credential"], keys["code-web"], revocations=srl)

    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new}")  # k1 dropped: what it signed stops verifying
    assert not ok(driver, out["credential"], keys["code-web"])


# ── swapping the format is configuration only ─────────────────────────────────────────────


async def test_switching_the_format_needs_no_other_change(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    keys = await setup(world)
    outs = {}
    for name in sorted(DRIVERS):
        monkeypatch.setenv("PACT_EXPORT_FORMAT", name)
        outs[name] = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    for name, out in outs.items():
        d = DRIVERS[name]
        assert out["credential"]["format"] == name
        assert ok(d, out["credential"], keys["code-web"], revocations=await published(world, d))
    # A revoke on the board reaches every format's list, whichever was configured at the time.
    monkeypatch.setenv("PACT_EXPORT_FORMAT", sorted(DRIVERS)[0])
    await world.admin.revoke_mandate(world.roots["chat-boss"], by="boss")
    for name, out in outs.items():
        d = DRIVERS[name]
        assert not ok(d, out["credential"], keys["code-web"], revocations=await published(world, d))


async def test_with_the_env_unset_claim_output_is_unchanged(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PACT_EXPORT_FORMAT", raising=False)
    await setup(world)
    out = await delegated_claim(world, "chat-boss", world.roots["chat-boss"], "code-web")
    out.pop("mandate_id")
    assert out == {"ok": True, "task_id": out["task_id"], "status": "working"}
    assert await links_of(world, world.roots["chat-boss"]) == set()


def test_every_shipped_format_has_a_driver() -> None:
    assert set(credentials.names()) == set(DRIVERS)
