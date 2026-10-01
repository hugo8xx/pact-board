"""The board as an OAuth protected resource, against a stand-in authorization server."""

import json
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx2
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from pact.db import create_pool, fetchone, transaction
from pact.oauth import ResourceSettings
from pact.server import create_app

from .conftest import World

pytestmark = pytest.mark.anyio


def _serve(app: Any) -> tuple[str, uvicorn.Server, threading.Thread]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.02)
    return f"http://127.0.0.1:{port}", server, thread


@dataclass
class Issuer:
    url: str
    key: ec.EllipticCurvePrivateKey

    def token(self, sub: str, aud: str, email: str | None = None, ttl: int = 300, scope: str = "pact", **extra: Any) -> str:
        claims = {"iss": self.url, "sub": sub, "aud": aud, "exp": int(time.time()) + ttl, "iat": int(time.time()), "scope": scope}
        if email:
            claims.update(email=email, email_verified=True)
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": "k1"})


@pytest.fixture
def issuer() -> Iterator[Issuer]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = {**json.loads(ECAlgorithm.to_jwk(key.public_key())), "kid": "k1", "alg": "ES256", "use": "sig"}
    holder: dict[str, str] = {}

    async def metadata(_r: Any) -> JSONResponse:
        return JSONResponse({"issuer": holder["url"], "jwks_uri": f"{holder['url']}/jwks.json"})

    async def jwks(_r: Any) -> JSONResponse:
        return JSONResponse({"keys": [jwk]})

    app = Starlette(routes=[Route("/.well-known/oauth-authorization-server", metadata), Route("/jwks.json", jwks)])
    url, server, thread = _serve(app)
    holder["url"] = url
    yield Issuer(url, key)
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def board(issuer: Issuer) -> Iterator[tuple[str, ResourceSettings]]:
    # The public URL is a placeholder: tokens are minted for it, requests go to the real port.
    settings = ResourceSettings(public_url="http://mcp.test", issuer=issuer.url)
    url, server, thread = _serve(create_app(create_pool(max_size=5), settings))
    yield url, settings
    server.should_exit = True
    thread.join(timeout=5)


PING = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
HEADERS = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}


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
    assert len(r.json()["result"]["tools"]) == 7
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
