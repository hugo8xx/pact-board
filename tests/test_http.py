"""End to end over Streamable HTTP with the official MCP client — what MCP Inspector would see."""

import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from pact.db import create_pool
from pact.server import create_app

from .conftest import World

pytestmark = pytest.mark.anyio

TOOLS = {"pact_whoami", "pact_post", "pact_list", "pact_claim", "pact_report", "pact_defer", "pact_revoke", "pact_note"}


@pytest.fixture
def server_url() -> Iterator[str]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(create_pool(max_size=5)), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@asynccontextmanager
async def session(url: str, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(headers=headers, timeout=10) as http:
        async with streamable_http_client(url, http_client=http, terminate_on_close=False) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as s:
                await s.initialize()
                yield s


def payload(result: Any) -> dict[str, Any]:
    return json.loads(result.content[0].text)


async def test_mcp_client_sees_eight_tools_and_works_end_to_end(world: World, server_url: str) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])
    await world.agent("code-web", "code", ["web"])

    async with session(f"{server_url}/mcp/a/chat-boss", world.tokens["chat-boss"]) as chat:
        tools = await chat.list_tools()
        assert {t.name for t in tools.tools} == TOOLS
        me = payload(await chat.call_tool("pact_whoami", {}))
        assert me["agent"]["id"] == "chat-boss"
        posted = payload(
            await chat.call_tool(
                "pact_post",
                {"project_id": "web", "title": "fix login", "mandate_id": me["mandates"][0]["id"], "delegate_to": "code-web"},
            )
        )

    started = time.perf_counter()
    async with session(f"{server_url}/mcp/a/code-web", world.tokens["code-web"]) as code:
        me = payload(await code.call_tool("pact_whoami", {}))
        listed = payload(await code.call_tool("pact_list", {"mandate_id": me["mandates"][0]["id"]}))
        assert [t["id"] for t in listed["tasks"]] == [posted["task_id"]]
        assert time.perf_counter() - started < 5  # posted from Chat, seen by Code within 5 seconds

        refused = await code.call_tool("pact_claim", {"task_id": posted["task_id"], "mandate_id": world.roots["chat-boss"]})
        assert refused.is_error and payload(refused)["error"] == "chain_broken"
        ok = payload(
            await code.call_tool("pact_claim", {"task_id": posted["task_id"], "mandate_id": posted["delegated_mandate_id"]})
        )
        assert ok["status"] == "working"


async def test_token_must_match_the_agent_in_the_url(world: World, server_url: str) -> None:
    await world.project("web")
    await world.agent("chat-boss", "chat", ["web"])
    await world.agent("code-web", "code", ["web"])
    async with httpx2.AsyncClient(timeout=5) as http:
        for token in (None, "pact_not-a-real-token-at-all-000000", world.tokens["chat-boss"]):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            r = await http.post(
                f"{server_url}/mcp/a/code-web", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
            )
            assert r.status_code == 401
        assert (await http.get(f"{server_url}/healthz")).status_code == 200
        assert (await http.post(f"{server_url}/mcp", json={})).status_code == 404


async def test_revoked_token_stops_working(world: World, server_url: str) -> None:
    await world.project("web")
    await world.agent("code-web", "code", ["web"])
    await world.admin.revoke_tokens("code-web", by="boss")
    async with httpx2.AsyncClient(timeout=5) as http:
        r = await http.post(
            f"{server_url}/mcp/a/code-web",
            headers={"Authorization": f"Bearer {world.tokens['code-web']}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
    assert r.status_code == 401


async def test_connect_trades_a_setup_code_for_a_token_once(world: World, server_url: str) -> None:
    await world.project("web")
    code = (await world.admin.hire("runner", "web", by="boss"))["connect"]["code"]
    async with httpx2.AsyncClient(timeout=5) as http:
        bad = await http.post(f"{server_url}/connect", json={"code": "nope"})
        ok = await http.post(f"{server_url}/connect", json={"code": code})
        again = await http.post(f"{server_url}/connect", json={"code": code})
    assert bad.status_code == 400
    assert ok.status_code == 200 and ok.headers["cache-control"] == "no-store"
    body = ok.json()
    assert body["agent_id"] == "runner-web" and body["token"].startswith("pact_")
    assert again.status_code == 403 and again.json()["error"] == "forbidden"
    async with session(f"{server_url}/mcp/a/runner-web", body["token"]) as s:
        me = payload(await s.call_tool("pact_whoami", {}))
    assert me["agent"]["id"] == "runner-web"
