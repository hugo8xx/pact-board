"""Spike 2: toy MCP server (mcp 2.x MCPServer) verifying Tenuo warrants offline, in-process.

Transport: client puts {"tenuo": {"warrant": <b64 WarrantStack root..leaf>, "signature": <b64 PoP>}}
into params._meta (the MCP spec extension point). We also try the arguments._tenuo fallback.
"""
import asyncio
import base64
import time

import tenuo  # noqa: F401
from mcp import Client
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from tenuo import Exact, Range, SigningKey, Warrant, Wildcard, encode_warrant_stack
from tenuo.mcp import MCPVerifier
from tenuo_core import Authorizer

board, agent_a, agent_b, rogue = (SigningKey.generate() for _ in range(4))

root = (Warrant.mint_builder()
        .capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(50), task_id=Wildcard())
        .capability("task.read", project=Exact("pact"), task_id=Wildcard())
        .holder(agent_a.public_key).ttl(8 * 3600).mint(board))
child = (root.grant_builder()
         .capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(10), task_id=Wildcard())
         .holder(agent_b.public_key).ttl(3600).grant(agent_a))

# ---------------- server ----------------
authorizer = Authorizer(trusted_roots=[board.public_key])
verifier = MCPVerifier(authorizer=authorizer)
server = MCPServer("pact-toy")
SEEN_META = {}


def _guard(tool: str, args: dict, ctx: Context) -> dict:
    meta = ctx.request_context.meta
    SEEN_META["last"] = meta
    res = verifier.verify(tool, args, meta=meta)
    if not res.allowed:
        raise ToolError(f"{res.jsonrpc_error_code} {res.error_type}: {res.denial_reason}")
    return {"warrant_id": res.warrant_id, "clean": res.clean_arguments}


@server.tool(name="task.work")
async def task_work(project: str, task_id: str, cost_usd: float, ctx: Context) -> dict:
    return _guard("task.work", {"project": project, "task_id": task_id, "cost_usd": cost_usd}, ctx)


# NOTE: mcp 2.x MCPServer rejects a tool parameter named `_tenuo`
# (InvalidSignature: "cannot start with '_'"), so the arguments._tenuo carrier only
# works with the low-level Server (raw params.arguments). We use _meta.tenuo.
try:
    @server.tool(name="task.work.argcarrier")
    async def task_work_arg(project: str, ctx: Context, _tenuo: dict | None = None) -> dict:
        return {}
except Exception as e:
    print("declaring _tenuo param on MCPServer tool ->", type(e).__name__, e)


@server.tool(name="task.read")
async def task_read(project: str, task_id: str, ctx: Context) -> dict:
    return _guard("task.read", {"project": project, "task_id": task_id}, ctx)


# ---------------- client helpers ----------------
def envelope(chain, key, tool, args):
    sig = chain[-1].sign(key, tool, args, int(time.time()))
    return {"tenuo": {"warrant": encode_warrant_stack(chain), "signature": base64.b64encode(bytes(sig)).decode()}}


async def call(client, label, tool, args, meta=None, via_args=False):
    a = dict(args)
    if via_args and meta:
        a["_tenuo"] = meta["tenuo"]
        meta = None
    r = await client.call_tool(tool, a, meta=meta)
    text = r.content[0].text if r.content else r
    status = "DENIED " if r.is_error else "ALLOWED"
    print(f"[{label}] {status} {str(text)[:230]}")


async def main():
    async with Client(server) as client:
        ok = {"project": "pact", "task_id": "T-1", "cost_usd": 5.0}
        int_args = {"project": "pact", "task_id": "T-1", "cost_usd": 5}
        await call(client, "GOTCHA int 5 coerced to float by pydantic", "task.work", int_args, envelope([root, child], agent_b, "task.work", int_args))
        await call(client, "child chain, in scope", "task.work", ok, envelope([root, child], agent_b, "task.work", ok))
        await call(client, "child chain via arguments._tenuo (typed tool w/o _tenuo)", "task.work", ok,
                   envelope([root, child], agent_b, "task.work", ok), via_args=True)
        rd = {"project": "pact", "task_id": "T-1"}
        await call(client, "child: task.read (not delegated)", "task.read", rd, envelope([root, child], agent_b, "task.read", rd))
        bad_proj = {"project": "web", "task_id": "T-1", "cost_usd": 5.0}
        await call(client, "child: other project", "task.work", bad_proj, envelope([root, child], agent_b, "task.work", bad_proj))
        big = {"project": "pact", "task_id": "T-1", "cost_usd": 20.0}
        await call(client, "child: cost 20 > 10", "task.work", big, envelope([root, child], agent_b, "task.work", big))
        await call(client, "root holder: cost 20 <= 50", "task.work", big, envelope([root], agent_a, "task.work", big))
        await call(client, "no warrant", "task.work", ok, None)
        await call(client, "leaf only (no parent in stack)", "task.work", ok, envelope([child], agent_b, "task.work", ok))
        await call(client, "PoP signed by wrong key", "task.work", ok, envelope([root, child], rogue, "task.work", ok))
        # stolen warrant w/o key: signature over different args
        env = envelope([root, child], agent_b, "task.work", ok)
        await call(client, "PoP replay with altered args", "task.work", {**ok, "task_id": "T-2"}, env)
        print("server saw meta keys:", list((SEEN_META.get("last") or {}).keys()))


if __name__ == "__main__":
    asyncio.run(main())
