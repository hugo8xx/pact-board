"""Admin API: the HTTP surface the Admin UI calls, at /admin/api.

Humans only. A caller presents an OAuth access token minted for ``<public_url>/admin`` (agent
tokens and tokens for agent URLs are refused), signed in with a second factor. Every write goes
through `Admin`, which checks the caller's role and logs the action.
"""

import json
from collections.abc import Awaitable, Callable
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import context as notes
from .admin import Admin
from .db import Conn, fetchall, fetchone, transaction
from .errors import PactError
from .oauth import TokenRejected, Verifier, human_for

Handler = Callable[[Request, str], Awaitable[Any]]

_STATUS = {
    "forbidden": 403,
    "not_found": 404,
    "invalid_request": 400,
    "project_required": 400,
    "project_mismatch": 400,
    "scope_exceeded": 400,
    "limit_exceeded": 400,
    "note_pinned": 409,
}


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return None
    return value


def _instant(name: str, value: str) -> datetime:
    """An ISO 8601 instant with its offset. A bare local time would be read in the server's zone,
    which is never what the person meant."""
    try:
        at = datetime.fromisoformat(value.strip().replace(" ", "+"))
    except ValueError:
        raise PactError("invalid_request", f"{name} must be an ISO 8601 time, e.g. 2026-10-01T09:00:00+07:00") from None
    if at.tzinfo is None:
        raise PactError("invalid_request", f"{name} needs a UTC offset (Z or +07:00): {value}")
    return at


def _ok(body: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(_jsonable(body), status_code=status, headers={"Cache-Control": "no-store"})


async def _body(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


class AdminApi:
    def __init__(self, pool: AsyncConnectionPool[Conn], verifier: Verifier) -> None:
        self.pool = pool
        self.verifier = verifier
        self.admin = Admin(pool)

    def route(self, fn: Handler) -> Callable[[Request], Awaitable[Response]]:
        """Authenticate the human, run the handler, map refusals to HTTP statuses."""

        async def endpoint(request: Request) -> Response:
            auth = request.headers.get("authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if not token or token.startswith("pact_"):
                return _ok({"error": "unauthorized", "message": "the Admin API takes a person's OAuth token"}, 401)
            try:
                claims = await self.verifier.verify_admin(token)
                async with transaction(self.pool) as conn:
                    human = await human_for(conn, self.verifier, token, claims)
            except TokenRejected as err:
                return _ok({"error": "unauthorized", "message": str(err)}, 401)
            if human is None:
                return _ok({"error": "forbidden", "message": "this account is not a registered person on the board"}, 403)
            try:
                return _ok(await fn(request, human))
            except PactError as err:
                return _ok(err.to_dict(), _STATUS.get(err.code, 409))

        return endpoint

    # ── reads (any role) ─────────────────────────────────────────────────────

    async def me(self, _r: Request, human: str) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchone(conn, "SELECT id, name, role, email FROM humans WHERE id = %s", (human,))

    async def overview(self, _r: Request, _h: str) -> Any:
        async with transaction(self.pool) as conn:
            state = await fetchone(conn, "SELECT halted FROM system_state")
            agents = await fetchall(conn, "SELECT status, count(*) AS n FROM agents GROUP BY status")
            tasks = await fetchall(
                conn,
                """SELECT project_id, status, count(*) AS n FROM tasks
                   WHERE status IN ('submitted', 'working', 'input_required', 'auth_required')
                      OR updated_at > now() - interval '7 days'
                   GROUP BY project_id, status ORDER BY project_id, status""",
            )
            approvals = await fetchone(conn, "SELECT count(*) AS n FROM tasks WHERE status = 'auth_required'")
            deferred = await fetchone(conn, "SELECT count(*) AS n FROM tasks WHERE deferred")
            active = await fetchall(
                conn,
                """SELECT id, client, last_seen FROM agents
                   WHERE status = 'active' AND last_seen > now() - interval '1 hour' ORDER BY last_seen DESC""",
            )
        return {
            "halted": bool(state and state["halted"]),
            "agents_by_status": {r["status"]: r["n"] for r in agents},
            "tasks": tasks,
            "pending_approvals": approvals["n"] if approvals else 0,
            "deferred": deferred["n"] if deferred else 0,
            "active_agents": active,
        }

    async def humans(self, _r: Request, _h: str) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchall(conn, "SELECT id, name, role, email, created_at FROM humans ORDER BY created_at")

    async def agents(self, _r: Request, _h: str) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                """SELECT a.id, a.owner, a.client, a.status, a.last_seen, a.created_at, a.root_mandate_id,
                          coalesce(array_agg(ap.project_id ORDER BY ap.project_id)
                                   FILTER (WHERE ap.project_id IS NOT NULL), '{}') AS projects,
                          (SELECT count(*) FROM agent_tokens t
                            WHERE t.agent_id = a.id AND t.revoked_at IS NULL AND t.expires_at > now()) AS live_tokens
                   FROM agents a LEFT JOIN agent_projects ap ON ap.agent_id = a.id
                   GROUP BY a.id ORDER BY a.id""",
            )

    async def projects(self, _r: Request, _h: str) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                """SELECT p.id, p.name, p.production, p.frozen, p.created_by, p.created_at,
                          (SELECT count(*) FROM tasks t WHERE t.project_id = p.id
                             AND t.status IN ('submitted', 'working', 'input_required', 'auth_required')) AS open_tasks
                   FROM projects p ORDER BY p.id""",
            )

    async def mandates(self, request: Request, _h: str) -> Any:
        include_dead = request.query_params.get("all") == "1"
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                f"""SELECT id, parent_id, issuer_kind, issuer, holder, scope, limits, delegations_left, depth,
                           expires_at, revoked_at, created_at,
                           (SELECT coalesce(jsonb_object_agg(limit_key, used), '{{}}') FROM limit_usage u
                             WHERE u.mandate_id = m.id) AS usage
                    FROM mandates m
                    {"" if include_dead else "WHERE revoked_at IS NULL AND expires_at > now()"}
                    ORDER BY depth, created_at""",
            )

    async def tasks(self, request: Request, _h: str) -> Any:
        q = request.query_params
        where: list[str] = ["true"]
        params: list[str] = []
        if q.get("status"):
            where.append("status = %s")
            params.append(q["status"])
        if q.get("project"):
            where.append("project_id = %s")
            params.append(q["project"])
        if q.get("deferred") == "1":
            where.append("deferred")
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                f"""SELECT id, project_id, title, body, action, status, created_by, delegate_to, assignee, deferred,
                           defer_reason, needed_scope, result, approved_by, approved_at, claimed_at, created_at, updated_at
                    FROM tasks WHERE {" AND ".join(where)} ORDER BY updated_at DESC LIMIT 200""",
                params,
            )

    async def task_trace(self, request: Request, _h: str) -> Any:
        """A task, every entry about it, and each entry's chain back to the human root."""
        task_id = request.path_params["task_id"]
        async with transaction(self.pool) as conn:
            task = await fetchone(conn, "SELECT * FROM tasks WHERE id::text = %s", (task_id,))
            if task is None:
                raise PactError("not_found", f"task {task_id} does not exist")
            entries = await fetchall(
                conn,
                """SELECT e.id, e.at, e.actor, e.agent_id, e.action, e.outcome, e.mandate_chain, p.content AS payload,
                          p.erased_at IS NOT NULL AS payload_erased
                   FROM entries e LEFT JOIN payloads p ON p.id = e.payload_ref
                   WHERE e.task_id = %s ORDER BY e.id""",
                (task_id,),
            )
            ids = sorted({str(m) for e in entries for m in e["mandate_chain"]})
            mandates = await fetchall(
                conn,
                """SELECT id, parent_id, issuer_kind, issuer, holder, scope, revoked_at, expires_at
                   FROM mandates WHERE id = ANY(%s::uuid[])""",
                (ids,),
            )
        return {"task": task, "entries": entries, "mandates": mandates}

    async def entries(self, request: Request, _h: str) -> Any:
        q = request.query_params
        where: list[str] = ["true"]
        params: list[str | int | datetime] = []
        for key, column in (
            ("project", "e.project_id"),
            ("agent", "e.agent_id"),
            ("action", "e.action"),
            ("outcome", "e.outcome"),
        ):
            if q.get(key):
                where.append(f"{column} = %s")
                params.append(q[key])
        if q.get("task"):
            where.append("e.task_id::text = %s")
            params.append(q["task"])
        if q.get("refused") == "1":
            where.append("e.outcome <> 'ok'")
        if q.get("before"):
            where.append("e.id < %s")
            params.append(int(q["before"]))
        for key, op in (("from", ">="), ("to", "<")):
            if q.get(key):
                where.append(f"e.at {op} %s")
                params.append(_instant(key, q[key]))
        limit = min(int(q.get("limit") or 100), 500)
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                f"""SELECT e.id, e.at, e.chain_key, e.project_id, e.task_id, e.agent_id, e.actor, e.action, e.outcome,
                           e.mandate_chain, p.content AS payload, p.erased_at IS NOT NULL AS payload_erased
                    FROM entries e LEFT JOIN payloads p ON p.id = e.payload_ref
                    WHERE {" AND ".join(where)} ORDER BY e.id DESC LIMIT {limit}""",
                params,
            )

    async def verify_log(self, _r: Request, _h: str) -> Any:
        return await self.admin.verify_log()

    # ── writes (role checked inside Admin) ───────────────────────────────────

    async def add_human(self, request: Request, human: str) -> Any:
        b = await _body(request)
        await self.admin.add_human(
            str(b.get("id", "")), str(b.get("name", "")), b.get("role", "viewer"), by=human, email=b.get("email")
        )
        return {"ok": True}

    async def add_project(self, request: Request, human: str) -> Any:
        b = await _body(request)
        await self.admin.add_project(str(b.get("id", "")), str(b.get("name", "")), by=human, production=bool(b.get("production")))
        return {"ok": True}

    async def update_project(self, request: Request, human: str) -> Any:
        b = await _body(request)
        await self.admin.set_project_flags(
            request.path_params["project_id"], by=human, production=b.get("production"), frozen=b.get("frozen")
        )
        return {"ok": True}

    async def context_list(self, request: Request, _h: str) -> Any:
        async with transaction(self.pool) as conn:
            return await notes.list_notes(
                conn, request.path_params["project_id"], archived=request.query_params.get("archived") == "1"
            )

    async def context_note(self, request: Request, _h: str) -> Any:
        p, k = request.path_params["project_id"], request.path_params["key"]
        async with transaction(self.pool) as conn:
            return {"note": await notes.read_note(conn, p, k, archived=True), "versions": await notes.versions(conn, p, k)}

    async def context_write(self, request: Request, human: str) -> Any:
        b = await _body(request)
        return await self.admin.write_note(
            request.path_params["project_id"], request.path_params["key"], by=human, title=b.get("title"), body=b.get("body")
        )

    async def context_action(self, request: Request, human: str) -> Any:
        p, k, action = request.path_params["project_id"], request.path_params["key"], request.path_params["action"]
        if action in ("pin", "unpin"):
            await self.admin.pin_note(p, k, action == "pin", by=human)
            return {"ok": True}
        if action == "archive":
            return await self.admin.write_note(p, k, by=human, archive=True)
        raise PactError("not_found", f"unknown action {action}")

    async def context_erase(self, request: Request, human: str) -> Any:
        return await self.admin.erase_note_version(int(request.path_params["version_id"]), by=human)

    async def register_agent(self, request: Request, human: str) -> Any:
        b = await _body(request)
        return await self.admin.register_agent(
            str(b.get("id", "")),
            by=human,
            client=b.get("client", "code"),
            projects=list(b.get("projects") or []),
            scope=b.get("scope") or None,
            limits=b.get("limits") or None,
            delegations=int(b.get("delegations", 2)),
            mandate_days=float(b.get("days", 30)),
            token_days=float(b.get("days", 30)),
        )

    async def agent_status(self, request: Request, human: str) -> Any:
        b = await _body(request)
        await self.admin.set_agent_status(request.path_params["agent_id"], b.get("status", "active"), by=human)
        return {"ok": True}

    async def issue_token(self, request: Request, human: str) -> Any:
        b = await _body(request)
        return {"token": await self.admin.issue_token(request.path_params["agent_id"], by=human, days=float(b.get("days", 30)))}

    async def revoke_tokens(self, request: Request, human: str) -> Any:
        return {"revoked": await self.admin.revoke_tokens(request.path_params["agent_id"], by=human)}

    async def issue_mandate(self, request: Request, human: str) -> Any:
        b = await _body(request)
        return {
            "mandate_id": await self.admin.issue_mandate(
                str(b.get("holder", "")),
                by=human,
                scope=list(b.get("scope") or []),
                limits=b.get("limits") or None,
                delegations=int(b.get("delegations", 1)),
                days=float(b.get("days", 30)),
            )
        }

    async def revoke_mandate(self, request: Request, human: str) -> Any:
        return await self.admin.revoke_mandate(request.path_params["mandate_id"], by=human)

    async def decide_task(self, request: Request, human: str) -> Any:
        decision = request.path_params["decision"]
        task_id = request.path_params["task_id"]
        if decision in ("approve", "reject"):
            await self.admin.approve_task(task_id, by=human, approve=decision == "approve")
        elif decision == "resume":
            await self.admin.resume_task(task_id, by=human)
        else:
            raise PactError("not_found", f"unknown decision {decision}")
        return {"ok": True}

    async def kill_switch(self, request: Request, human: str) -> Any:
        b = await _body(request)
        await self.admin.set_halted(bool(b.get("halted")), by=human)
        return {"halted": bool(b.get("halted"))}

    async def erase_payload(self, request: Request, human: str) -> Any:
        return {"erased": await self.admin.erase_payload(int(request.path_params["entry_id"]), by=human)}


def build_admin_app(pool: AsyncConnectionPool[Conn], verifier: Verifier) -> Starlette:
    a = AdminApi(pool, verifier)
    r = a.route
    p = "/admin/api"
    return Starlette(
        routes=[
            Route(f"{p}/me", r(a.me)),
            Route(f"{p}/overview", r(a.overview)),
            Route(f"{p}/humans", r(a.humans)),
            Route(f"{p}/humans", r(a.add_human), methods=["POST"]),
            Route(f"{p}/projects", r(a.projects)),
            Route(f"{p}/projects", r(a.add_project), methods=["POST"]),
            Route(f"{p}/projects/{{project_id}}", r(a.update_project), methods=["PATCH"]),
            Route(f"{p}/projects/{{project_id}}/context", r(a.context_list)),
            Route(f"{p}/projects/{{project_id}}/context/{{key}}", r(a.context_note)),
            Route(f"{p}/projects/{{project_id}}/context/{{key}}", r(a.context_write), methods=["PUT"]),
            Route(f"{p}/projects/{{project_id}}/context/{{key}}/{{action}}", r(a.context_action), methods=["POST"]),
            Route(f"{p}/context-versions/{{version_id:int}}/erase", r(a.context_erase), methods=["POST"]),
            Route(f"{p}/agents", r(a.agents)),
            Route(f"{p}/agents", r(a.register_agent), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/status", r(a.agent_status), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/tokens", r(a.issue_token), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/tokens", r(a.revoke_tokens), methods=["DELETE"]),
            Route(f"{p}/mandates", r(a.mandates)),
            Route(f"{p}/mandates", r(a.issue_mandate), methods=["POST"]),
            Route(f"{p}/mandates/{{mandate_id}}/revoke", r(a.revoke_mandate), methods=["POST"]),
            Route(f"{p}/tasks", r(a.tasks)),
            Route(f"{p}/tasks/{{task_id}}", r(a.task_trace)),
            Route(f"{p}/tasks/{{task_id}}/{{decision}}", r(a.decide_task), methods=["POST"]),
            Route(f"{p}/entries", r(a.entries)),
            Route(f"{p}/entries/{{entry_id:int}}/erase", r(a.erase_payload), methods=["POST"]),
            Route(f"{p}/log/verify", r(a.verify_log)),
            Route(f"{p}/kill-switch", r(a.kill_switch), methods=["POST"]),
        ]
    )
