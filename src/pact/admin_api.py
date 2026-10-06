"""Admin API: the HTTP surface the Admin UI calls, at /admin/api.

Humans only. A caller presents an OAuth access token minted for ``<public_url>/admin`` (agent
tokens and tokens for agent URLs are refused), signed in with a second factor. Every write goes
through `Admin`, which checks the caller's role and logs the action.
"""

import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
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
from . import credentials
from .admin import Admin
from .board import TERMINAL_STATUSES, export_format
from .db import Conn, fetchall, fetchone, transaction
from .errors import PactError
from .oauth import TokenRejected, Verifier, sign_in


@dataclass(frozen=True)
class Actor:
    """The person calling and the organization they belong to. Every read and write is limited to it."""

    id: str
    org: str


Handler = Callable[[Request, Actor], Awaitable[Any]]

_STATUS = {
    "forbidden": 403,
    "not_found": 404,
    "invalid_request": 400,
    "project_required": 400,
    "project_mismatch": 400,
    "scope_exceeded": 400,
    "limit_exceeded": 400,
    "note_pinned": 409,
    "id_taken": 409,
    "not_registered": 403,
    "account_disabled": 403,
    "already_registered": 409,
    "signup_closed": 403,
    "signup_busy": 429,
}

_NOT_REGISTERED = {
    "error": "not_registered",
    "message": "this account is not a registered person on the board; sign up or ask an owner to invite you",
}
_DISABLED = {"error": "account_disabled", "message": "this account has been disabled; ask the owner of your organization"}


def signup_enabled() -> bool:
    """Self-service sign-up is off unless PACT_SIGNUP_ENABLED says otherwise."""
    return os.environ.get("PACT_SIGNUP_ENABLED", "").strip().lower() in ("1", "true", "yes")


def signup_max_per_hour() -> int:
    """A circuit breaker against a flood of sign-ups, not a cap on organizations."""
    try:
        return max(0, int(os.environ.get("PACT_SIGNUP_MAX_PER_HOUR", "30")))
    except ValueError:
        return 30


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
                    who = await sign_in(conn, self.verifier, token, claims)
            except TokenRejected as err:
                return _ok({"error": "unauthorized", "message": str(err)}, 401)
            if who.human is None:
                return _ok(_NOT_REGISTERED, 403)
            if who.disabled:
                return _ok(_DISABLED, 403)
            async with transaction(self.pool) as conn:
                row = await fetchone(conn, "SELECT org_id FROM humans WHERE id = %s", (who.human,))
            if row is None:
                return _ok(_NOT_REGISTERED, 403)
            human = who.human
            try:
                return _ok(await fn(request, Actor(human, str(row["org_id"]))))
            except PactError as err:
                return _ok(err.to_dict(), _STATUS.get(err.code, 409))

        return endpoint

    async def signup(self, request: Request) -> Response:
        """POST /signup: someone signed in but not yet on the board starts an organization. It cannot go
        through route(), which turns such a caller away."""
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token or token.startswith("pact_"):
            return _ok({"error": "unauthorized", "message": "the Admin API takes a person's OAuth token"}, 401)
        try:
            claims = await self.verifier.verify_admin(token)
            async with transaction(self.pool) as conn:
                who = await sign_in(conn, self.verifier, token, claims)
        except TokenRejected as err:
            return _ok({"error": "unauthorized", "message": str(err)}, 401)
        if who.disabled:
            return _ok(_DISABLED, 403)
        if who.human is not None:
            return _ok({"error": "already_registered", "message": "this account already belongs to an organization"}, 409)
        if not signup_enabled():
            return _ok({"error": "signup_closed", "message": "sign-up is not open yet"}, 403)
        if not who.email:
            return _ok({"error": "invalid_request", "message": "this sign-in has no verified email"}, 400)
        body = await _body(request)
        if body.get("accept_terms") is not True:
            return _ok({"error": "invalid_request", "message": "accept the terms to sign up"}, 400)
        fields = {k: body.get(k) for k in ("org_name", "display_name", "terms_version")}
        if not all(isinstance(v, str) for v in fields.values()):
            return _ok({"error": "invalid_request", "message": "org_name, display_name and terms_version are required"}, 400)
        issuer = self.verifier.settings.issuer
        assert issuer, "verify_admin accepted a token with no issuer configured"
        try:
            out = await self.admin.sign_up(
                issuer=issuer,
                sub=str(claims["sub"]),
                email=who.email,
                org_name=str(fields["org_name"]),
                display_name=str(fields["display_name"]),
                terms_version=str(fields["terms_version"]),
                max_per_hour=signup_max_per_hour(),
            )
        except PactError as err:
            return _ok(err.to_dict(), _STATUS.get(err.code, 409))
        return _ok(out, 201)

    # ── reads (any role) ─────────────────────────────────────────────────────

    async def me(self, _r: Request, actor: Actor) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchone(
                conn,
                """SELECT h.id, h.name, h.role, h.email,
                          jsonb_build_object('id', o.id, 'name', o.name, 'halted', o.halted) AS org
                   FROM humans h JOIN orgs o ON o.id = h.org_id WHERE h.id = %s""",
                (actor.id,),
            )

    async def overview(self, _r: Request, actor: Actor) -> Any:
        async with transaction(self.pool) as conn:
            org = (actor.org,)
            state = await fetchone(conn, "SELECT o.halted OR s.halted AS halted FROM orgs o, system_state s WHERE o.id = %s", org)
            agents = await fetchall(conn, "SELECT status, count(*) AS n FROM agents WHERE org_id = %s GROUP BY status", org)
            mine = "project_id IN (SELECT id FROM projects WHERE org_id = %s)"
            tasks = await fetchall(
                conn,
                f"""SELECT project_id, status, count(*) AS n FROM tasks
                    WHERE {mine} AND (status IN ('submitted', 'working', 'input_required', 'auth_required')
                                      OR updated_at > now() - interval '7 days')
                    GROUP BY project_id, status ORDER BY project_id, status""",
                org,
            )
            approvals = await fetchone(conn, f"SELECT count(*) AS n FROM tasks WHERE {mine} AND status = 'auth_required'", org)
            deferred = await fetchone(conn, f"SELECT count(*) AS n FROM tasks WHERE {mine} AND deferred", org)
            active = await fetchall(
                conn,
                """SELECT id, client, last_seen FROM agents
                   WHERE org_id = %s AND status = 'active' AND last_seen > now() - interval '1 hour'
                   ORDER BY last_seen DESC""",
                org,
            )
        return {
            "halted": bool(state and state["halted"]),
            "agents_by_status": {r["status"]: r["n"] for r in agents},
            "tasks": tasks,
            "pending_approvals": approvals["n"] if approvals else 0,
            "deferred": deferred["n"] if deferred else 0,
            "active_agents": active,
        }

    async def humans(self, _r: Request, actor: Actor) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                "SELECT id, name, role, email, created_at, disabled_at FROM humans WHERE org_id = %s ORDER BY created_at",
                (actor.org,),
            )

    async def agents(self, _r: Request, actor: Actor) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                """SELECT a.id, a.owner, a.client, a.status, a.last_seen, a.created_at, a.root_mandate_id, a.preferences,
                          a.role_id, a.replaced_by,
                          coalesce(array_agg(ap.project_id ORDER BY ap.project_id)
                                   FILTER (WHERE ap.project_id IS NOT NULL), '{}') AS projects,
                          (SELECT count(*) FROM agent_tokens t
                            WHERE t.agent_id = a.id AND t.revoked_at IS NULL AND t.expires_at > now()) AS live_tokens,
                          (SELECT count(*) FROM mandates m
                            WHERE m.holder = a.id AND m.revoked_at IS NULL AND m.expires_at > now()) AS live_mandates,
                          (SELECT count(*) FROM agent_keys k WHERE k.agent_id = a.id AND k.revoked_at IS NULL) AS keys
                   FROM agents a LEFT JOIN agent_projects ap ON ap.agent_id = a.id
                   WHERE a.org_id = %s
                   GROUP BY a.id ORDER BY a.id""",
                (actor.org,),
            )

    async def agent_connection(self, request: Request, actor: Actor) -> Any:
        """Whether an agent has connected yet, for the Connection Wizard to poll. Shows when its
        latest setup code was made, expires and was used, never the code or its hash."""
        agent_id = request.path_params["agent_id"]
        async with transaction(self.pool) as conn:
            row = await fetchone(
                conn,
                """SELECT a.id, a.last_seen, a.created_at, now() AS now,
                          (SELECT count(*) FROM agent_tokens t
                            WHERE t.agent_id = a.id AND t.revoked_at IS NULL AND t.expires_at > now()) AS live_tokens
                   FROM agents a WHERE a.id = %s AND a.org_id = %s""",
                (agent_id, actor.org),
            )
            if row is None:
                raise PactError("not_found", f"agent {agent_id} does not exist")
            code = await fetchone(
                conn,
                """SELECT created_at, expires_at, used_at FROM setup_codes
                   WHERE agent_id = %s ORDER BY created_at DESC LIMIT 1""",
                (agent_id,),
            )
        seen, hired = row["last_seen"], row["created_at"]
        used = code["used_at"] if code else None
        if seen is not None and ((used is not None and seen >= used) or (code is None and seen >= hired)):
            state = "connected"
        elif used is not None:
            state = "code_redeemed"
        elif code is not None and code["expires_at"] <= row["now"]:
            state = "expired"
        else:
            state = "waiting_for_code"
        return {
            "agent_id": row["id"],
            "state": state,
            "setup_code": dict(code) if code else None,
            "live_tokens": row["live_tokens"],
            "last_seen": seen,
            "hired_at": hired,
        }

    async def projects(self, _r: Request, actor: Actor) -> Any:
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                """SELECT p.id, p.name, p.production, p.frozen, p.created_by, p.created_at,
                          (SELECT count(*) FROM tasks t WHERE t.project_id = p.id
                             AND t.status IN ('submitted', 'working', 'input_required', 'auth_required')) AS open_tasks
                   FROM projects p WHERE p.org_id = %s ORDER BY p.id""",
                (actor.org,),
            )

    async def mandates(self, request: Request, actor: Actor) -> Any:
        include_dead = request.query_params.get("all") == "1"
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                f"""SELECT id, parent_id, issuer_kind, issuer, holder, scope, limits, delegations_left, depth,
                           expires_at, revoked_at, created_at, format, exported_as, external_id, issuer_principal,
                           EXISTS (SELECT 1 FROM credential_links l JOIN credential_revocations r
                                     ON r.external_id = l.external_id AND r.format = l.format
                                   WHERE l.mandate_id = m.id) AS revocation_published,
                           (SELECT coalesce(jsonb_object_agg(limit_key, used), '{{}}') FROM limit_usage u
                             WHERE u.mandate_id = m.id) AS usage,
                           (SELECT jsonb_build_object('id', t.id, 'title', t.title, 'status', t.status) FROM tasks t
                             WHERE t.delegated_mandate_id = m.id LIMIT 1) AS task
                    FROM mandates m
                    WHERE m.holder IN (SELECT id FROM agents WHERE org_id = %s)
                    {"" if include_dead else "AND revoked_at IS NULL AND expires_at > now()"}
                    ORDER BY depth, created_at""",
                (actor.org,),
            )

    async def credentials_status(self, _r: Request, actor: Actor) -> Any:
        """Each registered format's published revocation list (version, ids on it now, where it is
        served) and the format handed to agents on claim."""
        formats = credentials.names()
        async with transaction(self.pool) as conn:
            versions = {
                r["format"]: r["version"]
                for r in await fetchall(conn, "SELECT format, version FROM credential_revocation_version")
            }
            counts = {
                r["format"]: r["n"]
                for r in await fetchall(
                    conn,
                    """SELECT format, count(*) AS n FROM credential_revocations
                       WHERE expires_at IS NULL OR expires_at > now() GROUP BY format""",
                )
            }
        return {
            "export_format": export_format(),
            "formats": [
                {
                    "format": f,
                    "version": int(versions.get(f, 0)),
                    "revoked_count": int(counts.get(f, 0)),
                    "published_path": credentials.SRL_PREFIX + f,
                }
                for f in formats
            ],
        }

    async def mandate_impact(self, request: Request, actor: Actor) -> Any:
        return await self.admin.revoke_mandate_impact(request.path_params["mandate_id"], actor.org)

    async def tasks(self, request: Request, actor: Actor) -> Any:
        q = request.query_params
        where: list[str] = ["project_id IN (SELECT id FROM projects WHERE org_id = %s)"]
        params: list[Any] = [actor.org]
        if q.get("status"):
            where.append("status = %s")
            params.append(q["status"])
        if q.get("project"):
            where.append("project_id = %s")
            params.append(q["project"])
        if q.get("deferred") == "1":
            where.append("deferred")
        if q.get("open") == "1":
            where.append("status <> ALL(%s)")
            params.append(list(TERMINAL_STATUSES))
        if q.get("agent"):
            where.append("(assignee = %s OR delegate_to = %s OR created_by = %s)")
            params.extend([q["agent"]] * 3)
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                f"""SELECT id, project_id, title, body, action, status, created_by, delegate_to, assignee, deferred,
                           defer_reason, needed_scope, answer, result, approved_by, approved_at, claimed_at, parent_task_id,
                           created_at, updated_at
                    FROM tasks WHERE {" AND ".join(where)} ORDER BY updated_at DESC LIMIT 200""",
                params,
            )

    async def task_trace(self, request: Request, actor: Actor) -> Any:
        """A task, every entry about it, and each entry's chain back to the human root."""
        task_id = request.path_params["task_id"]
        async with transaction(self.pool) as conn:
            task = await fetchone(
                conn,
                """SELECT * FROM tasks WHERE id::text = %s
                   AND project_id IN (SELECT id FROM projects WHERE org_id = %s)""",
                (task_id, actor.org),
            )
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
                   FROM mandates WHERE id = ANY(%s::uuid[]) AND holder IN (SELECT id FROM agents WHERE org_id = %s)""",
                (ids, actor.org),
            )
        return {"task": task, "entries": entries, "mandates": mandates}

    async def entries(self, request: Request, actor: Actor) -> Any:
        q = request.query_params
        where: list[str] = ["e.org_id = %s"]
        params: list[str | int | datetime] = [actor.org]
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

    async def verify_log(self, _r: Request, actor: Actor) -> Any:
        return await self.admin.verify_log(actor.org)

    # ── writes (role checked inside Admin) ───────────────────────────────────

    async def add_human(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        await self.admin.add_human(
            str(b.get("id", "")), str(b.get("name", "")), b.get("role", "viewer"), by=actor.id, email=b.get("email")
        )
        return {"ok": True}

    async def add_project(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        await self.admin.add_project(
            str(b.get("id", "")), str(b.get("name", "")), by=actor.id, production=bool(b.get("production"))
        )
        return {"ok": True}

    async def update_project(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        await self.admin.set_project_flags(
            request.path_params["project_id"], by=actor.id, production=b.get("production"), frozen=b.get("frozen")
        )
        return {"ok": True}

    async def context_list(self, request: Request, actor: Actor) -> Any:
        async with transaction(self.pool) as conn:
            await self.admin._in_org(conn, "project", request.path_params["project_id"], actor.org)
            return await notes.list_notes(
                conn, request.path_params["project_id"], archived=request.query_params.get("archived") == "1"
            )

    async def context_note(self, request: Request, actor: Actor) -> Any:
        p, k = request.path_params["project_id"], request.path_params["key"]
        async with transaction(self.pool) as conn:
            await self.admin._in_org(conn, "project", p, actor.org)
            return {"note": await notes.read_note(conn, p, k, archived=True), "versions": await notes.versions(conn, p, k)}

    async def context_write(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return await self.admin.write_note(
            request.path_params["project_id"], request.path_params["key"], by=actor.id, title=b.get("title"), body=b.get("body")
        )

    async def context_action(self, request: Request, actor: Actor) -> Any:
        p, k, action = request.path_params["project_id"], request.path_params["key"], request.path_params["action"]
        if action in ("pin", "unpin"):
            await self.admin.pin_note(p, k, action == "pin", by=actor.id)
            return {"ok": True}
        if action == "archive":
            return await self.admin.write_note(p, k, by=actor.id, archive=True)
        raise PactError("not_found", f"unknown action {action}")

    async def context_erase(self, request: Request, actor: Actor) -> Any:
        return await self.admin.erase_note_version(int(request.path_params["version_id"]), by=actor.id)

    async def register_agent(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return await self.admin.register_agent(
            str(b.get("id", "")),
            by=actor.id,
            client=b.get("client", "code"),
            projects=list(b.get("projects") or []),
            scope=b.get("scope") or None,
            limits=b.get("limits") or None,
            delegations=int(b.get("delegations", 2)),
            mandate_days=float(b.get("days", 30)),
            token_days=float(b.get("days", 30)),
        )

    async def agent_status(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        await self.admin.set_agent_status(request.path_params["agent_id"], b.get("status", "active"), by=actor.id)
        return {"ok": True}

    async def agent_preferences(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        prefs = await self.admin.set_agent_preferences(request.path_params["agent_id"], b.get("preferences"), by=actor.id)
        return {"ok": True, "preferences": prefs}

    async def roles(self, request: Request, actor: Actor) -> Any:
        return await self.admin.list_roles(actor.org, archived=request.query_params.get("archived") == "1")

    async def save_role(self, request: Request, actor: Actor) -> Any:
        return await self.admin.save_role(request.path_params["role_id"], await _body(request), by=actor.id)

    async def archive_role(self, request: Request, actor: Actor) -> Any:
        await self.admin.archive_role(request.path_params["role_id"], by=actor.id)
        return {"ok": True}

    async def hire(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        limits = b.get("limits")
        return await self.admin.hire(
            str(b.get("role", "")),
            str(b.get("project", "")),
            by=actor.id,
            agent_id=(str(b["id"]).strip() or None) if b.get("id") else None,
            limits={k: float(v) for k, v in limits.items()} if isinstance(limits, dict) else None,
            delegations=int(b["delegations"]) if b.get("delegations") is not None else None,
            days=float(b["days"]) if b.get("days") is not None else None,
            replaces=b.get("replaces") or None,
            owner=b.get("owner") or None,
        )

    async def renew(self, request: Request, actor: Actor) -> Any:
        return await self.admin.renew(request.path_params["agent_id"], by=actor.id)

    async def update_agent(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        projects = b.get("projects")
        return await self.admin.update_agent(
            request.path_params["agent_id"],
            by=actor.id,
            role_id=b.get("role_id") or None,
            owner=b.get("owner") or None,
            projects=[str(p) for p in projects] if isinstance(projects, list) else None,
        )

    async def update_human(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return await self.admin.update_human(
            request.path_params["human_id"],
            by=actor.id,
            name=b.get("name"),
            email=b.get("email"),
            role=b.get("role"),
            disabled=b.get("disabled") if isinstance(b.get("disabled"), bool) else None,
        )

    async def change_role(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return await self.admin.change_role(request.path_params["agent_id"], str(b.get("role_id") or ""), by=actor.id)

    async def setup_code(self, request: Request, actor: Actor) -> Any:
        return await self.admin.setup_code(request.path_params["agent_id"], by=actor.id)

    async def issue_token(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return {
            "token": await self.admin.issue_token(request.path_params["agent_id"], by=actor.id, days=float(b.get("days", 30)))
        }

    async def revoke_tokens(self, request: Request, actor: Actor) -> Any:
        return {"revoked": await self.admin.revoke_tokens(request.path_params["agent_id"], by=actor.id)}

    async def agent_keys(self, request: Request, actor: Actor) -> Any:
        async with transaction(self.pool) as conn:
            await self.admin._in_org(conn, "agent", request.path_params["agent_id"], actor.org)
            return await fetchall(
                conn,
                """SELECT kid, encode(public_key, 'base64') AS public_key_b64, created_at, created_by, revoked_at
                   FROM agent_keys WHERE agent_id = %s ORDER BY created_at""",
                (request.path_params["agent_id"],),
            )

    async def add_agent_key(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return await self.admin.add_agent_key(request.path_params["agent_id"], str(b.get("public_key", "")), by=actor.id)

    async def revoke_agent_key(self, request: Request, actor: Actor) -> Any:
        p = request.path_params
        return {"revoked": await self.admin.revoke_agent_key(p["agent_id"], p["kid"], by=actor.id)}

    async def trusted_roots(self, _r: Request, actor: Actor) -> Any:
        return await self.admin.list_trusted_roots(actor.org)

    async def add_trusted_root(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return await self.admin.add_trusted_root(
            str(b.get("public_key", "")), human=str(b.get("human", "")), by=actor.id, label=b.get("label") or None
        )

    async def revoke_trusted_root(self, request: Request, actor: Actor) -> Any:
        return {"revoked": await self.admin.revoke_trusted_root(request.path_params["principal"], by=actor.id)}

    async def import_credential(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        mandate_id = await self.admin.import_credential(
            request.path_params["agent_id"], str(b.get("format", "")), str(b.get("credential", "")), by=actor.id
        )
        return {"mandate_id": mandate_id}

    async def issue_mandate(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return {
            "mandate_id": await self.admin.issue_mandate(
                str(b.get("holder", "")),
                by=actor.id,
                scope=list(b.get("scope") or []),
                limits=b.get("limits") or None,
                delegations=int(b.get("delegations", 1)),
                days=float(b.get("days", 30)),
            )
        }

    async def replace_mandate(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        return await self.admin.replace_mandate(
            request.path_params["mandate_id"],
            by=actor.id,
            scope=list(b.get("scope") or []),
            limits=b.get("limits"),
            delegations=None if b.get("delegations") is None else int(b["delegations"]),
            days=float(b.get("days", 30)),
            revoke=bool(b.get("revoke")),
        )

    async def revoke_mandate(self, request: Request, actor: Actor) -> Any:
        return await self.admin.revoke_mandate(request.path_params["mandate_id"], by=actor.id)

    async def decide_task(self, request: Request, actor: Actor) -> Any:
        decision = request.path_params["decision"]
        task_id = request.path_params["task_id"]
        if decision in ("approve", "reject"):
            await self.admin.approve_task(task_id, by=actor.id, approve=decision == "approve")
        elif decision == "resume":
            answer = str((await _body(request)).get("answer") or "").strip() or None
            await self.admin.resume_task(task_id, by=actor.id, answer=answer)
        elif decision == "assign":
            agent = (await _body(request)).get("agent") or None
            return {"ok": True, **await self.admin.assign_task(task_id, agent, by=actor.id)}
        elif decision == "release":
            return {"ok": True, **await self.admin.release_task(task_id, by=actor.id)}
        elif decision == "edit":
            b = await _body(request)
            return await self.admin.edit_task(task_id, by=actor.id, title=b.get("title"), body=b.get("body"))
        elif decision == "cancel":
            reason = (await _body(request)).get("reason") or None
            return {"ok": True, **await self.admin.cancel_task(task_id, by=actor.id, reason=reason)}
        else:
            raise PactError("not_found", f"unknown decision {decision}")
        return {"ok": True}

    async def kill_switch(self, request: Request, actor: Actor) -> Any:
        b = await _body(request)
        await self.admin.set_halted(bool(b.get("halted")), by=actor.id)
        return {"halted": bool(b.get("halted"))}

    async def erase_payload(self, request: Request, actor: Actor) -> Any:
        return {"erased": await self.admin.erase_payload(int(request.path_params["entry_id"]), by=actor.id)}


def build_admin_app(pool: AsyncConnectionPool[Conn], verifier: Verifier) -> Starlette:
    a = AdminApi(pool, verifier)
    r = a.route
    p = "/admin/api"
    return Starlette(
        routes=[
            Route(f"{p}/signup", a.signup, methods=["POST"]),
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
            Route(f"{p}/agents/hire", r(a.hire), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/connection", r(a.agent_connection)),
            Route(f"{p}/agents/{{agent_id}}/renew", r(a.renew), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/role", r(a.change_role), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}", r(a.update_agent), methods=["PATCH"]),
            Route(f"{p}/humans/{{human_id}}", r(a.update_human), methods=["PATCH"]),
            Route(f"{p}/agents/{{agent_id}}/setup-code", r(a.setup_code), methods=["POST"]),
            Route(f"{p}/roles", r(a.roles)),
            Route(f"{p}/roles/{{role_id}}", r(a.save_role), methods=["PUT"]),
            Route(f"{p}/roles/{{role_id}}/archive", r(a.archive_role), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/status", r(a.agent_status), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/preferences", r(a.agent_preferences), methods=["PUT"]),
            Route(f"{p}/agents/{{agent_id}}/tokens", r(a.issue_token), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/tokens", r(a.revoke_tokens), methods=["DELETE"]),
            Route(f"{p}/agents/{{agent_id}}/keys", r(a.agent_keys)),
            Route(f"{p}/agents/{{agent_id}}/keys", r(a.add_agent_key), methods=["POST"]),
            Route(f"{p}/agents/{{agent_id}}/keys/{{kid}}", r(a.revoke_agent_key), methods=["DELETE"]),
            Route(f"{p}/agents/{{agent_id}}/credentials", r(a.import_credential), methods=["POST"]),
            Route(f"{p}/trusted-roots", r(a.trusted_roots)),
            Route(f"{p}/credentials/status", r(a.credentials_status)),
            Route(f"{p}/trusted-roots", r(a.add_trusted_root), methods=["POST"]),
            Route(f"{p}/trusted-roots/{{principal}}", r(a.revoke_trusted_root), methods=["DELETE"]),
            Route(f"{p}/mandates", r(a.mandates)),
            Route(f"{p}/mandates", r(a.issue_mandate), methods=["POST"]),
            Route(f"{p}/mandates/{{mandate_id}}/impact", r(a.mandate_impact)),
            Route(f"{p}/mandates/{{mandate_id}}/revoke", r(a.revoke_mandate), methods=["POST"]),
            Route(f"{p}/mandates/{{mandate_id}}/replace", r(a.replace_mandate), methods=["POST"]),
            Route(f"{p}/tasks", r(a.tasks)),
            Route(f"{p}/tasks/{{task_id}}", r(a.task_trace)),
            Route(f"{p}/tasks/{{task_id}}/{{decision}}", r(a.decide_task), methods=["POST"]),
            Route(f"{p}/entries", r(a.entries)),
            Route(f"{p}/entries/{{entry_id:int}}/erase", r(a.erase_payload), methods=["POST"]),
            Route(f"{p}/log/verify", r(a.verify_log)),
            Route(f"{p}/kill-switch", r(a.kill_switch), methods=["POST"]),
        ]
    )
