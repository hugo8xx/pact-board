"""MCP surface: the seven tools, served over Streamable HTTP at /mcp/a/<agent-id>.

The ASGI wrapper resolves the caller from the URL and the bearer token before the MCP app sees
the request; tools read that agent off the request. Agents never pass their own identity.
"""

import json
import re
from typing import Annotated, Any, cast
from urllib.parse import urlsplit

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import CallToolResult, TextContent
from psycopg_pool import AsyncConnectionPool
from pydantic import Field
from starlette.types import ASGIApp, Receive, Scope, Send

from .admin_api import build_admin_app
from .auth import agent_for_token
from .board import Agent, Board, ListFilter, ReportStatus
from .db import Conn, create_pool, transaction
from .errors import PactError
from .hooks import EVENTS as HOOK_EVENTS
from .hooks import handle as handle_hook
from .oauth import ResourceSettings, TokenRejected, Verifier, agent_for_oauth

INSTRUCTIONS = """\
PACT Board is the shared task board for this organization's agents. Every call carries a mandate: a chain
of authority that traces back to a human. Rules:
- Call pact_whoami at the start of a session, then pact_list. The board cannot push to you:
  pact_list is the only way to learn about new work. Call it again after finishing each task.
- Claim (pact_claim) before you start any task. If you get already_claimed, move on quietly.
- While working, call pact_report with status "working" at least every 20 minutes, or the
  board releases your claim after 30 minutes and someone else may take the task.
- If a task needs more authority than your mandate gives, call pact_defer and stop. Never try
  to work around a refusal and never ask for a mandate for yourself.
- When you post a task for another agent, tell the user it starts only when that agent next
  pulls work.
"""

MandateId = Annotated[str, Field(description="The mandate you act under (from pact_whoami, or a delegated_mandate_id).")]
TaskId = Annotated[str, Field(description="Task id from pact_list or pact_post.")]


def _agent(ctx: Context) -> Agent:
    request = ctx.request_context.request
    agent = getattr(getattr(request, "state", None), "pact_agent", None)
    if not isinstance(agent, Agent):
        raise ToolError(json.dumps({"error": "forbidden", "message": "no authenticated agent on this request"}))
    return agent


async def _guard(coro: Any) -> dict[str, Any]:
    """Run a board call; a refusal becomes an is_error result whose text is the bare JSON
    ``{"error": <code>, "message": ..., "mandate_id": ...}`` so agents can branch on the code.

    A raised ToolError would arrive prefixed with "Error executing tool ...", so the result is
    returned instead. The SDK passes a CallToolResult through whatever the annotation says.
    """
    try:
        result: dict[str, Any] = await coro
        return result
    except PactError as err:
        refusal = CallToolResult(
            content=[TextContent(type="text", text=json.dumps(err.to_dict(), ensure_ascii=False))], is_error=True
        )
        return cast(dict[str, Any], refusal)


def build_mcp(board: Board) -> MCPServer:
    mcp = MCPServer(name="pact-board", title="PACT Board", version="0.1.0", instructions=INSTRUCTIONS)

    @mcp.tool(title="Who am I")
    async def pact_whoami(ctx: Context) -> dict[str, Any]:
        """Your agent identity, projects, the mandates you hold, and the agents you can delegate to.
        Call once at the start of every session."""
        return await _guard(board.whoami(_agent(ctx)))

    @mcp.tool(title="Post a task")
    async def pact_post(
        ctx: Context,
        project_id: Annotated[str, Field(description="Project the task belongs to. Required.")],
        title: str,
        mandate_id: MandateId,
        body: str = "",
        action: Annotated[str, Field(description="What doing the task takes, e.g. task.work, deploy.web.")] = "task.work",
        parent_task_id: str | None = None,
        delegate_to: Annotated[
            str | None, Field(description="Agent id that must do this task (see pact_whoami delegates).")
        ] = None,
        child_scope: Annotated[
            list[str] | None, Field(description="Scope for the delegated mandate; defaults to just this task's action.")
        ] = None,
        child_limits: Annotated[dict[str, float] | None, Field(description="Numeric ceilings for the delegated mandate.")] = None,
        cost: Annotated[
            dict[str, float] | None, Field(description='Amounts this task consumes against mandate limits, e.g. {"thb": 5000}.')
        ] = None,
    ) -> dict[str, Any]:
        """Put a task on the board. With delegate_to, only that agent may claim it and it receives a
        narrower mandate of its own. The task starts only when the receiving agent next calls
        pact_list — tell the user so."""
        return await _guard(
            board.post(
                _agent(ctx),
                project_id=project_id,
                title=title,
                mandate_id=mandate_id,
                body=body,
                action=action,
                parent_task_id=parent_task_id,
                delegate_to=delegate_to,
                child_scope=child_scope,
                child_limits=child_limits,
                cost=cost,
            )
        )

    @mcp.tool(title="List tasks")
    async def pact_list(
        ctx: Context,
        mandate_id: MandateId,
        filter: Annotated[ListFilter, Field(description="open: unclaimed work you may take · mine: yours · all.")] = "open",
        project_id: str | None = None,
        since: Annotated[
            int | None, Field(description="next_since from your previous call; returns only what changed after it.")
        ] = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """The only way to learn about work: the board cannot push. Call at the start of a session
        and after finishing each task. Deferred tasks come back in their own list for humans."""
        return await _guard(
            board.list_tasks(_agent(ctx), mandate_id=mandate_id, filter=filter, project_id=project_id, since=since, limit=limit)
        )

    @mcp.tool(title="Claim a task")
    async def pact_claim(ctx: Context, task_id: TaskId, mandate_id: MandateId) -> dict[str, Any]:
        """Take a task before starting it. Exactly one agent wins; on already_claimed, move on."""
        return await _guard(board.claim(_agent(ctx), task_id=task_id, mandate_id=mandate_id))

    @mcp.tool(title="Report on a task")
    async def pact_report(
        ctx: Context,
        task_id: TaskId,
        status: Annotated[
            ReportStatus, Field(description="working = heartbeat (send at least every 20 minutes); others close the task.")
        ],
        mandate_id: MandateId,
        result: Annotated[Any, Field(description="What you produced, or why it failed.")] = None,
    ) -> dict[str, Any]:
        """Send progress or the final result. claim_lost means the board released your claim — stop
        and do not overwrite the new holder's work."""
        return await _guard(board.report(_agent(ctx), task_id=task_id, status=status, mandate_id=mandate_id, result=result))

    @mcp.tool(title="Defer to a human")
    async def pact_defer(
        ctx: Context,
        task_id: TaskId,
        reason: str,
        mandate_id: MandateId,
        needed_scope: Annotated[list[str] | None, Field(description="The scope the task would need.")] = None,
    ) -> dict[str, Any]:
        """Hand a task back to humans when it needs more authority than you hold. Then stop; never
        work around it and never request a mandate for yourself."""
        return await _guard(
            board.defer(_agent(ctx), task_id=task_id, reason=reason, mandate_id=mandate_id, needed_scope=needed_scope)
        )

    @mcp.tool(title="Revoke a mandate you issued")
    async def pact_revoke(
        ctx: Context, mandate_id: Annotated[str, Field(description="A mandate you issued by delegating.")]
    ) -> dict[str, Any]:
        """Withdraw a mandate you delegated; everything under it stops. Other mandates are revoked
        by humans in the Admin UI."""
        return await _guard(board.revoke(_agent(ctx), mandate_id=mandate_id))

    return mcp


_AGENT_PATH = re.compile(r"^/mcp/a/([a-z0-9][a-z0-9-]{0,62})/?$")
_HOOK_PATH = re.compile(r"^/hooks/a/([a-z0-9][a-z0-9-]{0,62})/([a-z-]+)$")
_METADATA_PATH = re.compile(r"^/\.well-known/oauth-protected-resource/mcp/a/([a-z0-9][a-z0-9-]{0,62})/?$")


class PactApp:
    """ASGI entry: authenticates /mcp/a/<agent> and hands the request to the MCP app at /mcp.

    Two kinds of bearer token are accepted: agent tokens (``pact_…``, for Claude Code, hooks
    and the Runner) and OAuth access tokens from the configured authorization server (for the
    hosted Claude apps). An OAuth caller must be the owner of the agent in the URL.
    """

    def __init__(self, pool: AsyncConnectionPool[Conn], mcp_app: ASGIApp, settings: ResourceSettings) -> None:
        self.pool = pool
        self.mcp_app = mcp_app
        self.settings = settings
        self.verifier = Verifier(settings)
        self.admin_app = build_admin_app(pool, self.verifier)
        self.board = Board(pool)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.mcp_app(scope, receive, send)
            return
        path: str = scope["path"]
        if path == "/healthz":
            await _respond(send, 200, {"ok": True})
            return
        if path.startswith("/admin/api/"):
            await self.admin_app(scope, receive, send)
            return
        hook = _HOOK_PATH.match(path)
        if hook:
            await self._hook(scope, receive, send, hook.group(1), hook.group(2))
            return
        meta = _METADATA_PATH.match(path)
        if meta:
            await _respond(
                send, 200, self.settings.resource_metadata(meta.group(1)), extra_headers=[(b"access-control-allow-origin", b"*")]
            )
            return
        m = _AGENT_PATH.match(path)
        if not m:
            await _respond(send, 404, {"error": "not_found", "message": "use /mcp/a/<agent-id>"})
            return
        agent_id = m.group(1)
        token = _bearer(scope)
        agent: Agent | None = None
        problem = "missing bearer token"
        if token:
            try:
                async with transaction(self.pool) as conn:
                    if token.startswith("pact_"):
                        agent = await agent_for_token(conn, agent_id, token)
                        problem = "invalid or expired agent token"
                    else:
                        agent = await agent_for_oauth(conn, self.verifier, agent_id, token)
                        if agent is None:
                            # Signed in fine, but not as this agent's owner: re-authenticating won't help.
                            await _respond(
                                send, 403, {"error": "forbidden", "message": f"you are not the owner of agent {agent_id}"}
                            )
                            return
            except TokenRejected as err:
                problem = str(err)
        if agent is None:
            challenge = f'Bearer resource_metadata="{self.settings.metadata_url(agent_id)}", scope="pact"'
            if token:
                challenge += ', error="invalid_token"'
            await _respond(
                send,
                401,
                {"error": "unauthorized", "message": problem},
                extra_headers=[(b"www-authenticate", challenge.encode())],
            )
            return
        state = dict(scope.get("state") or {})
        state["pact_agent"] = agent
        await self.mcp_app({**scope, "path": "/mcp", "raw_path": b"/mcp", "state": state}, receive, send)

    async def _hook(self, scope: Scope, receive: Receive, send: Send, agent_id: str, event: str) -> None:
        """Claude Code hooks authenticate with the agent's token only; OAuth is for the Claude apps."""
        if event not in HOOK_EVENTS:
            await _respond(send, 404, {"error": "not_found", "message": f"hook events: {', '.join(HOOK_EVENTS)}"})
            return
        token = _bearer(scope) or ""
        agent: Agent | None = None
        if token.startswith("pact_"):
            async with transaction(self.pool) as conn:
                agent = await agent_for_token(conn, agent_id, token)
        if agent is None:
            await _respond(send, 401, {"error": "unauthorized", "message": "hooks need a live agent token for this agent"})
            return
        await handle_hook(scope, receive, send, self.board, agent, event)

    async def _lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Open the pool, then let the MCP app run its own lifespan (its session manager) inside.
        await self.pool.open()

        async def wrapped_send(message: Any) -> None:
            if message["type"] == "lifespan.shutdown.complete":
                await self.pool.close()
            await send(message)

        await self.mcp_app(scope, receive, wrapped_send)


def _bearer(scope: Scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name == b"authorization":
            text: str = value.decode("latin-1")
            if text.lower().startswith("bearer "):
                return text[7:].strip()
    return None


async def _respond(send: Send, status: int, body: dict[str, Any], extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    data = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode()), *(extra_headers or [])]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})


def create_app(pool: AsyncConnectionPool[Conn] | None = None, settings: ResourceSettings | None = None) -> PactApp:
    pool = pool or create_pool()
    settings = settings or ResourceSettings.from_env()
    mcp = build_mcp(Board(pool))
    host = urlsplit(settings.public_url).netloc
    security = None
    if settings.public_url.startswith("https://"):
        # Behind the public HTTPS host: accept only that Host header.
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=[host], allowed_origins=[f"https://{host}", "https://claude.ai"]
        )
    mcp_app = mcp.streamable_http_app(stateless_http=True, json_response=True, transport_security=security)
    return PactApp(pool, mcp_app, settings)
