"""A stand-in OAuth authorization server and a live board, for the OAuth and Admin API tests."""

import json
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from pact.db import create_pool
from pact.oauth import ResourceSettings
from pact.server import create_app


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
