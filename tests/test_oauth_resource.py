"""The board as an OAuth protected resource, against a stand-in authorization server."""

import time

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pact.db import fetchone, transaction
from pact.oauth import ResourceSettings

from .conftest import World
from .oauth_fixtures import HEADERS, PING, Issuer

pytestmark = pytest.mark.anyio


async def setup(world: World) -> None:
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE humans SET email = 'boss@example.com' WHERE id = 'boss'")
    await world.admin.add_human("ann", "Ann", "approver", by="boss", email="ann@example.com")
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])


async def call(url: str, agent: str, token: str | None) -> httpx2.Response:
    headers = {**HEADERS, **({"Authorization": f"Bearer {token}"} if token else {})}
    async with httpx2.AsyncClient(timeout=10) as http:
        return await http.post(f"{url}/mcp/a/{agent}", json=PING, headers=headers)


async def test_unauthenticated_call_points_claude_at_the_metadata(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await setup(world)
    r = await call(url, "chat-boss", None)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == (
        'Bearer resource_metadata="http://mcp.test/.well-known/oauth-protected-resource/mcp/a/chat-boss", scope="pact"'
    )
    async with httpx2.AsyncClient() as http:
        meta = (await http.get(f"{url}/.well-known/oauth-protected-resource/mcp/a/chat-boss")).json()
    assert meta["resource"] == "http://mcp.test/mcp/a/chat-boss"
    assert meta["authorization_servers"] == [issuer.url]


async def test_owner_signs_in_and_is_pinned_by_sub(world: World, board: tuple[str, ResourceSettings], issuer: Issuer) -> None:
    url, settings = board
    await setup(world)
    aud = settings.resource("chat-boss")
    r = await call(url, "chat-boss", issuer.token("sub-boss", aud, email="BOSS@example.com"))
    assert r.status_code == 200, r.text
    assert len(r.json()["result"]["tools"]) == 8
    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT auth_sub FROM humans WHERE id = 'boss'")
    assert row == {"auth_sub": "sub-boss"}
    # Later tokens need no email: the sub is remembered.
    assert (await call(url, "chat-boss", issuer.token("sub-boss", aud))).status_code == 200


async def test_signed_in_person_who_is_not_the_owner_gets_403(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await setup(world)
    r = await call(url, "chat-boss", issuer.token("sub-ann", settings.resource("chat-boss"), email="ann@example.com"))
    assert r.status_code == 403


@pytest.mark.parametrize("problem", ["wrong_audience", "expired", "no_scope", "stranger", "bad_signature"])
async def test_bad_tokens_get_401_invalid_token(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer, problem: str
) -> None:
    url, settings = board
    await setup(world)
    aud = settings.resource("chat-boss")
    token = {
        "wrong_audience": lambda: issuer.token("sub-boss", "http://mcp.test/mcp/a/other", email="boss@example.com"),
        "expired": lambda: issuer.token("sub-boss", aud, email="boss@example.com", ttl=-120),
        "no_scope": lambda: issuer.token("sub-boss", aud, email="boss@example.com", scope="openid"),
        "stranger": lambda: issuer.token("sub-x", aud, email="nobody@example.com"),
        "bad_signature": lambda: jwt.encode(
            {"iss": issuer.url, "sub": "s", "aud": aud, "exp": int(time.time()) + 60},
            ec.generate_private_key(ec.SECP256R1()),
            algorithm="ES256",
            headers={"kid": "k1"},
        ),
    }[problem]()
    r = await call(url, "chat-boss", token)
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]


async def test_agent_tokens_still_work_alongside_oauth(world: World, board: tuple[str, ResourceSettings]) -> None:
    url, _ = board
    await setup(world)
    assert (await call(url, "chat-boss", world.tokens["chat-boss"])).status_code == 200
