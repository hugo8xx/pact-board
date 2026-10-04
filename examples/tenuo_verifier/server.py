"""A tool server outside the board that accepts PACT credentials exported as Tenuo warrants.

It trusts only the board's public keys (``/.well-known/pact-keys.json``) and the board's signed
revocation list (``/.well-known/pact-revocations/tenuo``), refetched every 30 seconds. If the list
is older than 60 seconds, because the board cannot be reached, every call is refused: a verifier
that kept going on an old list would honor credentials the board has already revoked.

Each proof-of-possession signature is accepted once. Tenuo accepts a signature for a short window
(30 s × 5 by default), so without a nonce store anyone who saw one call could replay it within that
window. The store outlives every refresh of the keys and the list, so a refresh never forgets what
was already used. It lives in this process; several workers need a shared backend (see
``tenuo.nonce.NonceStore``).

    uv run python examples/tenuo_verifier/server.py https://board.example.com

Each call carries ``params._meta.tenuo = {"warrant": <warrant_stack>, "signature": <b64 PoP>}``;
see README.md next to this file.
"""

import sys
import time
from collections.abc import Mapping
from typing import Any

import anyio
import httpx
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from tenuo import Authorizer, PublicKey, SignedRevocationList
from tenuo.mcp import MCPVerifier
from tenuo.nonce import NonceStore

from pact.keys import b64url_decode

REFRESH_SECONDS = 30
MAX_AGE_SECONDS = 60
NONCE_TTL_SECONDS = 150
"""How long a used signature is remembered: longer than Tenuo's acceptance window (30 s × 5)."""


class BoardTrust:
    """Trusted roots and revocation list from one board, kept fresh; fails closed when stale."""

    def __init__(self, board_url: str = "") -> None:
        self.board_url = board_url.rstrip("/")
        self.version = -1
        self.loaded_at: float | None = None
        self._verifier: MCPVerifier | None = None
        self.nonces = NonceStore(ttl_seconds=NONCE_TTL_SECONDS)

    def load(self, jwks: Mapping[str, Any], srl: bytes, now: float | None = None) -> None:
        """Install the board's keys and revocation list. An older list than the one held is
        ignored, so a replayed response cannot un-revoke anything."""
        roots = [PublicKey.from_bytes(b64url_decode(k["x"])) for k in jwks["keys"] if k.get("crv") == "Ed25519"]
        if not roots:
            raise ValueError("the board published no Ed25519 keys")
        revocations = SignedRevocationList.from_bytes(srl)
        if revocations.version < self.version:
            return
        authorizer = Authorizer(trusted_roots=roots)
        authorizer.set_revocation_list(revocations)  # checks the list is signed by a trusted root
        self._verifier = MCPVerifier(authorizer=authorizer, nonce_store=self.nonces)
        self.version = revocations.version
        self.loaded_at = time.monotonic() if now is None else now

    async def refresh(self, http: httpx.AsyncClient) -> None:
        keys = await http.get(f"{self.board_url}/.well-known/pact-keys.json")
        keys.raise_for_status()
        srl = await http.get(f"{self.board_url}/.well-known/pact-revocations/tenuo")
        srl.raise_for_status()
        self.load(keys.json(), srl.content)

    async def keep_fresh(self, http: httpx.AsyncClient) -> None:
        while True:
            try:
                await self.refresh(http)
            except (httpx.HTTPError, ValueError) as err:
                print(f"refresh failed, still on version {self.version}: {err}", file=sys.stderr)
            await anyio.sleep(REFRESH_SECONDS)

    def verifier(self, now: float | None = None) -> MCPVerifier | None:
        """The verifier to use now, or None when the list is too old to trust (fail closed)."""
        now = time.monotonic() if now is None else now
        if self.loaded_at is None or now - self.loaded_at > MAX_AGE_SECONDS:
            return None
        return self._verifier


def build_server(trust: BoardTrust) -> MCPServer:
    server = MCPServer("pact-tenuo-verifier-demo")

    def guard(tool: str, args: dict[str, Any], ctx: Context) -> dict[str, Any]:
        verifier = trust.verifier()
        if verifier is None:
            raise ToolError("unavailable: the board's revocation list is stale; refusing every call")
        result = verifier.verify(tool, args, meta=ctx.request_context.meta)
        if not result.allowed:
            raise ToolError(f"{result.error_type}: {result.denial_reason}")
        return {"ok": True, "tool": tool, "warrant_id": result.warrant_id, "arguments": result.clean_arguments}

    @server.tool(name="task.work")
    async def task_work(project: str, task_id: str, ctx: Context, cost_usd: float | None = None) -> dict[str, Any]:
        """Do work on a task. Pass cost_usd only when the mandate limits it (every limit is required then)."""
        args: dict[str, Any] = {"project": project, "task_id": task_id}
        if cost_usd is not None:
            args["cost_usd"] = cost_usd
        return guard("task.work", args, ctx)

    @server.tool(name="task.read")
    async def task_read(project: str, task_id: str, ctx: Context, cost_usd: float | None = None) -> dict[str, Any]:
        """Read a task. Like every tool, it takes each limit the mandate sets."""
        args: dict[str, Any] = {"project": project, "task_id": task_id}
        if cost_usd is not None:
            args["cost_usd"] = cost_usd
        return guard("task.read", args, ctx)

    return server


async def main(board_url: str) -> None:
    trust = BoardTrust(board_url)
    server = build_server(trust)
    async with httpx.AsyncClient(timeout=10) as http:
        await trust.refresh(http)
        async with anyio.create_task_group() as tg:
            tg.start_soon(trust.keep_fresh, http)
            await server.run_streamable_http_async(host="127.0.0.1", port=8790)


if __name__ == "__main__":
    anyio.run(main, sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787")
