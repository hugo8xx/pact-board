"""The seven board tools, as plain async methods. The MCP layer only maps arguments onto them."""

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, TypeVar
from uuid import uuid4

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from .crypto import iso
from .db import Conn, fetchall, fetchone, transaction
from .entries import EntryInput, append_entry
from .errors import PactError
from .mandates import Chain, Limits, consume_limits, get_mandate, issue_child, revoke_subtree, verify_chain
from .scope import action_covers, any_covers, board_scope

Client = Literal["chat", "cowork", "code", "gemini", "runner"]
ListFilter = Literal["mine", "open", "all"]
ReportStatus = Literal["working", "completed", "failed", "canceled", "input_required"]

POST_ONLY_CLIENTS: tuple[Client, ...] = ("chat", "cowork")
"""Clients that post and watch work; they never claim it."""

TERMINAL_STATUSES = ("completed", "failed", "canceled", "rejected")
"""A task in one of these is done for good; the mandate delegated for it dies with it."""

T = TypeVar("T")


def stale_minutes() -> float:
    return float(os.environ.get("PACT_STALE_MINUTES", "30"))


@dataclass(frozen=True)
class Agent:
    id: str
    owner: str
    client: Client
    status: str


@dataclass(frozen=True)
class Project:
    id: str
    name: str
    production: bool
    frozen: bool


@dataclass
class _CallContext:
    """What the call has learned so far — written into the entry even when the call is refused."""

    project_id: str | None = None
    task_id: str | None = None
    chain: list[str] = field(default_factory=list)


class Board:
    def __init__(self, pool: AsyncConnectionPool[Conn]) -> None:
        self.pool = pool

    async def _call(self, agent: Agent, action: str, payload: Any, fn: Callable[[Conn, _CallContext], Awaitable[T]]) -> T:
        """Run one tool call: check the kill switch and the agent's status, do the work in one
        transaction, and write an Entry either way. A refused call rolls back its work and is
        logged in a fresh transaction with the error code as its outcome."""
        ctx = _CallContext()
        try:
            async with transaction(self.pool) as conn:
                gate = await fetchone(
                    conn, "SELECT s.halted, a.status FROM system_state s, agents a WHERE a.id = %s", (agent.id,)
                )
                if gate is None:
                    raise PactError("agent_unknown", f"agent {agent.id} is not registered")
                if gate["halted"]:
                    raise PactError("system_halted", "the kill switch is on; every call is refused until a human turns it off")
                if gate["status"] != "active":
                    raise PactError("agent_paused", f"agent {agent.id} is {gate['status']}")
                await conn.execute("UPDATE agents SET last_seen = now() WHERE id = %s", (agent.id,))
                result = await fn(conn, ctx)
                await self._log(conn, agent, action, payload, ctx, "ok")
                return result
        except PactError as err:
            async with transaction(self.pool) as conn:
                await self._log(conn, agent, action, payload, ctx, err.code)
            raise

    async def _log(self, conn: Conn, agent: Agent, action: str, payload: Any, ctx: _CallContext, outcome: str) -> None:
        # A project the call named but that does not exist cannot anchor a chain; that goes to _system.
        project_id = ctx.project_id if ctx.project_id and await _project_exists(conn, ctx.project_id) else None
        task_id = ctx.task_id if ctx.task_id and await _task_exists(conn, ctx.task_id) else None
        await append_entry(
            conn,
            EntryInput(
                project_id=project_id,
                task_id=task_id,
                agent_id=agent.id,
                actor=f"agent:{agent.id}",
                mandate_chain=ctx.chain,
                action=action,
                payload=payload,
                outcome=outcome,
            ),
        )
        if task_id and outcome == "ok":
            # Any entry by the assignee is a heartbeat for the stale-claim release.
            await conn.execute(
                """INSERT INTO task_activity (task_id, agent_id, at)
                   SELECT id, assignee, now() FROM tasks WHERE id = %s AND assignee = %s AND status = 'working'
                   ON CONFLICT (task_id) DO UPDATE SET agent_id = EXCLUDED.agent_id, at = EXCLUDED.at""",
                (task_id, agent.id),
            )

    async def _chain(self, conn: Conn, ctx: _CallContext, mandate_id: str, agent: Agent) -> Chain:
        chain = await verify_chain(conn, mandate_id, agent.id)
        ctx.chain = chain.ids
        return chain

    # ── tools ────────────────────────────────────────────────────────────────

    async def whoami(self, agent: Agent) -> dict[str, Any]:
        async def run(conn: Conn, _ctx: _CallContext) -> dict[str, Any]:
            projects = await agent_projects(conn, agent.id)
            mandates = await fetchall(
                conn,
                """SELECT id, parent_id, issuer, scope, limits, delegations_left, expires_at FROM mandates
                   WHERE holder = %s AND revoked_at IS NULL AND expires_at > now() ORDER BY depth, created_at""",
                (agent.id,),
            )
            delegates = await fetchall(
                conn,
                """SELECT a.id, a.client, array_agg(ap.project_id ORDER BY ap.project_id) AS projects
                   FROM agents a JOIN agent_projects ap ON ap.agent_id = a.id
                   WHERE a.status = 'active' AND a.id <> %(me)s
                     AND ap.project_id IN (SELECT project_id FROM agent_projects WHERE agent_id = %(me)s)
                   GROUP BY a.id, a.client ORDER BY a.id""",
                {"me": agent.id},
            )
            return {
                "agent": {"id": agent.id, "client": agent.client, "owner": agent.owner},
                "projects": [p.__dict__ for p in projects],
                "mandates": [
                    {
                        **m,
                        "id": str(m["id"]),
                        "parent_id": str(m["parent_id"]) if m["parent_id"] else None,
                        "expires_at": iso(m["expires_at"]),
                    }
                    for m in mandates
                ],
                "delegates": delegates,
            }

        return await self._call(agent, "pact_whoami", {}, run)

    async def post(
        self,
        agent: Agent,
        *,
        project_id: str | None,
        title: str,
        mandate_id: str,
        body: str = "",
        action: str = "task.work",
        parent_task_id: str | None = None,
        delegate_to: str | None = None,
        child_scope: list[str] | None = None,
        child_limits: Limits | None = None,
        cost: Limits | None = None,
    ) -> dict[str, Any]:
        payload = {
            "project_id": project_id,
            "title": title,
            "body": body,
            "mandate_id": mandate_id,
            "action": action,
            "parent_task_id": parent_task_id,
            "delegate_to": delegate_to,
            "child_scope": child_scope,
            "child_limits": child_limits,
            "cost": cost,
        }

        async def run(conn: Conn, ctx: _CallContext) -> dict[str, Any]:
            if not project_id:
                raise PactError("project_required", "pact_post needs project_id")
            ctx.project_id = project_id
            chain = await self._chain(conn, ctx, mandate_id, agent)
            project = await self._project_for(conn, agent, project_id)
            if project.frozen:
                raise PactError("project_frozen", f"project {project.id} is frozen")
            _refuse_runner_on_production(agent, project)
            _require_scope(chain, board_scope("task.post", project.id))

            if parent_task_id:
                parent = await _get_task(conn, parent_task_id)
                if parent is None or parent["project_id"] != project.id:
                    raise PactError("project_mismatch", f"parent task {parent_task_id} is not in project {project.id}")

            delegated_id: str | None = None
            if delegate_to:
                target = await get_agent(conn, delegate_to)
                target_projects = [p.id for p in await agent_projects(conn, delegate_to)] if target else []
                if target is None or target.status == "banned" or project.id not in target_projects or target.id == agent.id:
                    raise PactError("agent_unknown", f"agent {delegate_to} is not registered in project {project.id}")
                child = await issue_child(
                    conn,
                    chain,
                    holder=target.id,
                    scope=child_scope or [board_scope(action, project.id), board_scope("task.read", project.id)],
                    limits=child_limits,
                )
                delegated_id = child.id

            await consume_limits(conn, chain, {"tasks": 1, **(cost or {})})

            needs_approval = await _requires_approval(conn, action)
            status = "auth_required" if needs_approval else "submitted"
            task_id = str(uuid4())
            await conn.execute(
                """INSERT INTO tasks (id, project_id, title, body, action, created_by, mandate_id, delegate_to,
                                      delegated_mandate_id, status, parent_task_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    task_id,
                    project.id,
                    title,
                    body,
                    action,
                    agent.id,
                    chain.leaf.id,
                    delegate_to,
                    delegated_id,
                    status,
                    parent_task_id,
                ),
            )
            ctx.task_id = task_id
            notes = []
            if needs_approval:
                notes.append(f'Action "{action}" needs a human approval in the Admin UI before anyone can claim it.')
            if delegate_to:
                notes.append(
                    f"Tell the user: {delegate_to} starts this when it next pulls work (its next session, or its "
                    "Runner). The board cannot push to it."
                )
            else:
                notes.append("Tell the user: the task waits on the board until an agent in this project pulls it.")
            out: dict[str, Any] = {"task_id": task_id, "status": status, "note": " ".join(notes)}
            if delegated_id:
                out["delegated_mandate_id"] = delegated_id
            return out

        return await self._call(agent, "pact_post", payload, run)

    async def list_tasks(
        self,
        agent: Agent,
        *,
        mandate_id: str,
        filter: ListFilter = "open",
        project_id: str | None = None,
        since: int | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        payload = {"mandate_id": mandate_id, "filter": filter, "project_id": project_id, "since": since, "limit": limit}

        async def run(conn: Conn, ctx: _CallContext) -> dict[str, Any]:
            chain = await self._chain(conn, ctx, mandate_id, agent)
            readable = [
                p.id for p in await agent_projects(conn, agent.id) if any_covers(chain.leaf.scope, board_scope("task.read", p.id))
            ]
            if project_id:
                ctx.project_id = project_id
                if project_id not in readable:
                    raise PactError("project_mismatch", f"agent {agent.id} cannot read project {project_id}")
                readable = [project_id]
            elif len(readable) == 1:
                ctx.project_id = readable[0]
            await release_stale(conn, readable)

            n = min(max(limit, 1), 200)
            cursor = since or 0
            where = {
                "open": "status = 'submitted' AND assignee IS NULL AND (delegate_to IS NULL OR delegate_to = %(me)s)",
                "mine": "(assignee = %(me)s OR delegate_to = %(me)s OR created_by = %(me)s)",
                "all": "true",
            }[filter]
            params = {"projects": readable, "me": agent.id, "since": cursor, "limit": n}
            rows = await fetchall(
                conn,
                f"""SELECT * FROM tasks WHERE project_id = ANY(%(projects)s) AND change_seq > %(since)s AND {where}
                    ORDER BY change_seq LIMIT %(limit)s""",
                params,
            )
            deferred = await fetchall(
                conn,
                """SELECT * FROM tasks WHERE project_id = ANY(%(projects)s) AND deferred AND change_seq > %(since)s
                   ORDER BY change_seq LIMIT 200""",
                params,
            )
            return {
                "tasks": [_summary(t) for t in rows],
                "deferred": [_summary(t) for t in deferred],
                "next_since": max([cursor, *(t["change_seq"] for t in rows)]),
                "has_more": len(rows) == n,
            }

        return await self._call(agent, "pact_list", payload, run)

    async def claim(self, agent: Agent, *, task_id: str, mandate_id: str) -> dict[str, Any]:
        async def run(conn: Conn, ctx: _CallContext) -> dict[str, Any]:
            chain = await self._chain(conn, ctx, mandate_id, agent)
            task = await self._visible_task(conn, ctx, agent, task_id)
            project = await _get_project(conn, task["project_id"])
            if project.frozen:
                raise PactError("project_frozen", f"project {project.id} is frozen")
            _refuse_runner_on_production(agent, project)
            if agent.client in POST_ONLY_CLIENTS:
                raise PactError("scope_exceeded", f"{agent.client} agents post and watch tasks; they do not claim them")
            if task["delegate_to"] and task["delegate_to"] != agent.id:
                raise PactError("wrong_agent", f"task {task_id} is delegated to {task['delegate_to']}")
            if task["status"] == "auth_required":
                raise PactError("approval_pending", f"task {task_id} waits for a human approval")
            _require_scope(chain, board_scope(task["action"], project.id))
            await release_stale(conn, [project.id])

            # Compare-and-set: the row changes only while nobody holds it.
            claimed = await fetchone(
                conn,
                """UPDATE tasks SET assignee = %s, assignee_mandate_id = %s, status = 'working', claimed_at = now()
                   WHERE id = %s AND assignee IS NULL AND status = 'submitted' RETURNING id""",
                (agent.id, chain.leaf.id, task_id),
            )
            if claimed is None:
                now = await _get_task(conn, task_id)
                if now and now["assignee"]:
                    raise PactError("already_claimed", f"task {task_id} is already claimed by {now['assignee']}")
                state = f"{now['status']}{' (deferred)' if now['deferred'] else ''}" if now else "gone"
                raise PactError("invalid_request", f"task {task_id} is {state} and cannot be claimed")
            return {"ok": True, "task_id": task_id, "status": "working"}

        return await self._call(agent, "pact_claim", {"task_id": task_id, "mandate_id": mandate_id}, run)

    async def report(
        self, agent: Agent, *, task_id: str, status: ReportStatus, mandate_id: str, result: Any = None
    ) -> dict[str, Any]:
        payload = {"task_id": task_id, "status": status, "result": result, "mandate_id": mandate_id}

        async def run(conn: Conn, ctx: _CallContext) -> dict[str, Any]:
            chain = await self._chain(conn, ctx, mandate_id, agent)
            task = await self._visible_task(conn, ctx, agent, task_id)
            project = await _get_project(conn, task["project_id"])
            if project.frozen:
                raise PactError("project_frozen", f"project {project.id} is frozen")
            _refuse_runner_on_production(agent, project)
            await release_stale(conn, [project.id])
            now = await _get_task(conn, task_id)
            if now is None or now["assignee"] != agent.id or now["status"] != "working":
                holder = f" (now with {now['assignee']})" if now and now["assignee"] else ""
                raise PactError(
                    "claim_lost",
                    f"task {task_id} is no longer claimed by {agent.id}{holder}; do not overwrite the new holder's work",
                )
            _require_scope(chain, board_scope(task["action"], project.id))
            if status == "working":
                return {"ok": True, "task_id": task_id, "status": "working", "note": "heartbeat recorded"}
            await conn.execute(
                """UPDATE tasks SET status = %(status)s, result = %(result)s,
                          assignee = CASE WHEN %(status)s = 'input_required' THEN NULL ELSE assignee END
                   WHERE id = %(id)s""",
                {"status": status, "result": Jsonb(result) if result is not None else None, "id": task_id},
            )
            out: dict[str, Any] = {"ok": True, "task_id": task_id, "status": status}
            closed = await revoke_closed_task_mandates(conn, [task_id])
            if closed:
                out["revoked_mandate"] = closed[0]["mandate_id"]
                out["subtasks_canceled"] = sum(len(c["tasks_stopped"]) for c in closed)
            return out

        return await self._call(agent, "pact_report", payload, run)

    async def defer(
        self, agent: Agent, *, task_id: str, reason: str, mandate_id: str, needed_scope: list[str] | None = None
    ) -> dict[str, Any]:
        payload = {"task_id": task_id, "reason": reason, "needed_scope": needed_scope, "mandate_id": mandate_id}

        async def run(conn: Conn, ctx: _CallContext) -> dict[str, Any]:
            await self._chain(conn, ctx, mandate_id, agent)
            task = await self._visible_task(conn, ctx, agent, task_id)
            project = await _get_project(conn, task["project_id"])
            if project.frozen:
                raise PactError("project_frozen", f"project {project.id} is frozen")
            mine = task["status"] == "working" and task["assignee"] == agent.id
            unclaimed = task["status"] == "submitted" and task["assignee"] is None
            if not (mine or unclaimed):
                raise PactError("invalid_request", f"task {task_id} is {task['status']} and cannot be deferred by {agent.id}")
            await conn.execute(
                """UPDATE tasks SET status = 'input_required', deferred = true, defer_reason = %s, needed_scope = %s,
                          assignee = NULL, assignee_mandate_id = NULL
                   WHERE id = %s""",
                (reason, needed_scope, task_id),
            )
            return {
                "ok": True,
                "task_id": task_id,
                "status": "input_required",
                "note": "A human sees this in the deferred list and decides. Stop working on it.",
            }

        return await self._call(agent, "pact_defer", payload, run)

    async def revoke(self, agent: Agent, *, mandate_id: str) -> dict[str, Any]:
        async def run(conn: Conn, ctx: _CallContext) -> dict[str, Any]:
            target = await get_mandate(conn, mandate_id)
            if target is None:
                raise PactError("not_found", f"mandate {mandate_id} does not exist")
            ctx.chain = [target.id]
            if target.issuer_kind != "agent" or target.issuer != agent.id:
                raise PactError(
                    "not_issuer", f"agent {agent.id} did not issue mandate {target.id}; revoke it in the Admin UI", target.id
                )
            r = await revoke_subtree(conn, target.id)
            await revoke_closed_task_mandates(conn, [tid for tid, _ in r["stopped"]])
            return {"revoked": target.id, "descendant_mandates": r["descendant_mandates"], "tasks_stopped": r["tasks_stopped"]}

        return await self._call(agent, "pact_revoke", {"mandate_id": mandate_id}, run)

    # ── Claude Code hooks (not MCP tools; see hooks.py) ──────────────────────

    async def record_tool_use(self, agent: Agent, summary: dict[str, Any]) -> dict[str, Any]:
        """Log one PostToolUse summary as an Entry on the task the agent is working on.

        The hook cannot know the task, so the board picks the one task the agent holds. With
        none, or with several, nothing is logged: Claude Code work outside a claimed task stays
        off the board. The entry runs under the mandate the task was claimed with, and like any
        entry by the assignee it is a heartbeat, so a task worked on for hours is not released.
        """
        async with transaction(self.pool) as conn:
            held = await fetchall(conn, "SELECT id FROM tasks WHERE assignee = %s AND status = 'working' LIMIT 2", (agent.id,))
        if len(held) != 1:
            return {"logged": False, "reason": "no task held" if not held else "several tasks held"}
        task_id = str(held[0]["id"])

        async def run(conn: Conn, ctx: _CallContext) -> dict[str, Any]:
            task = await self._visible_task(conn, ctx, agent, task_id)
            if task["assignee"] != agent.id or task["status"] != "working":
                raise PactError("claim_lost", f"task {task_id} is no longer claimed by {agent.id}")
            await self._chain(conn, ctx, str(task["assignee_mandate_id"]), agent)
            project = await _get_project(conn, task["project_id"])
            if project.frozen:
                raise PactError("project_frozen", f"project {project.id} is frozen")
            return {"logged": True, "task_id": task_id}

        return await self._call(agent, "hook.post_tool_use", summary, run)

    async def new_tasks_for_session(self, agent: Agent, session_id: str) -> dict[str, Any]:
        """Open tasks this Claude Code session has not been told about yet (Stop hook).

        Reads like ``pact_list(filter="open", since=…)`` under the agent's own mandate, with the
        cursor kept on the board per session. It only reports; it never claims.
        """
        async with transaction(self.pool) as conn:
            mandate = await fetchone(
                conn,
                """SELECT m.id::text FROM mandates m JOIN agents a ON a.id = m.holder
                   WHERE m.holder = %s AND m.revoked_at IS NULL AND m.expires_at > now()
                   ORDER BY (m.id = a.root_mandate_id) DESC, m.depth, m.created_at LIMIT 1""",
                (agent.id,),
            )
            cursor = await fetchone(
                conn, "SELECT since FROM hook_cursors WHERE agent_id = %s AND session_id = %s", (agent.id, session_id)
            )
        if mandate is None:
            raise PactError("mandate_expired", f"agent {agent.id} holds no live mandate")
        listed = await self.list_tasks(
            agent, mandate_id=mandate["id"], filter="open", since=cursor["since"] if cursor else None, limit=50
        )
        async with transaction(self.pool) as conn:
            await conn.execute(
                """INSERT INTO hook_cursors (agent_id, session_id, since) VALUES (%s, %s, %s)
                   ON CONFLICT (agent_id, session_id) DO UPDATE SET since = EXCLUDED.since, updated_at = now()""",
                (agent.id, session_id, listed["next_since"]),
            )
            await conn.execute("DELETE FROM hook_cursors WHERE updated_at < now() - interval '30 days'")
        return listed

    # ── helpers ──────────────────────────────────────────────────────────────

    async def _project_for(self, conn: Conn, agent: Agent, project_id: str) -> Project:
        for p in await agent_projects(conn, agent.id):
            if p.id == project_id:
                return p
        raise PactError("project_mismatch", f"agent {agent.id} is not registered in project {project_id}")

    async def _visible_task(self, conn: Conn, ctx: _CallContext, agent: Agent, task_id: str) -> dict[str, Any]:
        task = await _get_task(conn, task_id)
        if task is None:
            raise PactError("not_found", f"task {task_id} does not exist")
        ctx.project_id = task["project_id"]
        ctx.task_id = task_id
        await self._project_for(conn, agent, task["project_id"])
        return task


def _refuse_runner_on_production(agent: Agent, project: Project) -> None:
    if agent.client == "runner" and project.production:
        raise PactError(
            "project_mismatch", f"project {project.id} is production; a Runner may not touch it — a human opens Claude Code"
        )


def _require_scope(chain: Chain, needed: str) -> None:
    if not any_covers(chain.leaf.scope, needed):
        raise PactError("scope_exceeded", f"mandate {chain.leaf.id} does not cover {needed}", chain.leaf.id)


def _summary(t: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": str(t["id"]),
        "project_id": t["project_id"],
        "title": t["title"],
        "body": t["body"],
        "action": t["action"],
        "status": t["status"],
        "created_by": t["created_by"],
        "delegate_to": t["delegate_to"],
        "delegated_mandate_id": str(t["delegated_mandate_id"]) if t["delegated_mandate_id"] else None,
        "assignee": t["assignee"],
        "deferred": t["deferred"],
        "result": t["result"],
        "parent_task_id": str(t["parent_task_id"]) if t["parent_task_id"] else None,
        "seq": t["change_seq"],
        "updated_at": iso(t["updated_at"]),
    }
    if t["deferred"]:
        out["defer_reason"] = t["defer_reason"]
        out["needed_scope"] = t["needed_scope"]
    return out


async def get_agent(conn: Conn, agent_id: str) -> Agent | None:
    row = await fetchone(conn, "SELECT id, owner, client, status FROM agents WHERE id = %s", (agent_id,))
    return Agent(**row) if row else None


async def agent_projects(conn: Conn, agent_id: str) -> list[Project]:
    rows = await fetchall(
        conn,
        """SELECT p.id, p.name, p.production, p.frozen FROM projects p JOIN agent_projects ap ON ap.project_id = p.id
           WHERE ap.agent_id = %s ORDER BY p.id""",
        (agent_id,),
    )
    return [Project(**r) for r in rows]


async def _get_project(conn: Conn, project_id: str) -> Project:
    row = await fetchone(conn, "SELECT id, name, production, frozen FROM projects WHERE id = %s", (project_id,))
    if row is None:
        raise PactError("not_found", f"project {project_id} does not exist")
    return Project(**row)


async def _project_exists(conn: Conn, project_id: str) -> bool:
    return await fetchone(conn, "SELECT 1 FROM projects WHERE id = %s", (project_id,)) is not None


async def _task_exists(conn: Conn, task_id: str) -> bool:
    return await _get_task(conn, task_id) is not None


async def _get_task(conn: Conn, task_id: str) -> dict[str, Any] | None:
    from .mandates import _is_uuid

    if not _is_uuid(task_id):
        return None
    return await fetchone(conn, "SELECT * FROM tasks WHERE id = %s", (task_id,))


async def _requires_approval(conn: Conn, action: str) -> bool:
    rows = await fetchall(conn, "SELECT action FROM approval_actions")
    return any(action_covers(r["action"], action) for r in rows)


async def revoke_closed_task_mandates(conn: Conn, task_ids: list[str] | None = None) -> list[dict[str, Any]]:
    """Revoke the mandate delegated for each closed task, and everything under it.

    A task in a terminal status needs no more authority, so the child mandate issued for it
    must not outlive it. Open tasks posted under that mandate are canceled, as with any
    revoke; each of those is closed in turn, so the sweep continues down the tree. Tasks that
    are still open (deferred, waiting for approval, …) keep their mandate. ``None`` sweeps
    every closed task, for mandates left behind before this rule existed.
    """
    done: list[dict[str, Any]] = []
    queue = task_ids
    while queue is None or queue:
        rows = await fetchall(
            conn,
            f"""WITH RECURSIVE up AS (
                  SELECT t.id AS task_id, m.id, m.parent_id, m.revoked_at
                  FROM tasks t JOIN mandates m ON m.id = t.delegated_mandate_id
                  WHERE t.status = ANY(%(terminal)s) {"" if queue is None else "AND t.id = ANY(%(ids)s::uuid[])"}
                  UNION ALL
                  SELECT up.task_id, p.id, p.parent_id, p.revoked_at FROM mandates p JOIN up ON p.id = up.parent_id
                )
                SELECT t.id, t.project_id, t.status, t.delegated_mandate_id FROM tasks t
                WHERE t.id IN (SELECT task_id FROM up GROUP BY task_id HAVING bool_and(revoked_at IS NULL))
                ORDER BY t.change_seq""",
            {"terminal": list(TERMINAL_STATUSES), "ids": queue or []},
        )
        queue = []
        for r in rows:
            mandate_id = str(r["delegated_mandate_id"])
            revoked = await revoke_subtree(conn, mandate_id)
            stopped = [tid for tid, _ in revoked["stopped"]]
            lineage = await fetchall(
                conn,
                """WITH RECURSIVE up AS (
                     SELECT id, parent_id, depth FROM mandates WHERE id = %s
                     UNION ALL
                     SELECT p.id, p.parent_id, p.depth FROM mandates p JOIN up ON p.id = up.parent_id
                   ) SELECT id::text FROM up ORDER BY depth""",
                (mandate_id,),
            )
            await append_entry(
                conn,
                EntryInput(
                    project_id=r["project_id"],
                    task_id=str(r["id"]),
                    agent_id=None,
                    actor="system",
                    mandate_chain=[m["id"] for m in lineage],
                    action="mandate.revoke_on_close",
                    payload={
                        "task_status": r["status"],
                        "mandate_id": mandate_id,
                        "descendant_mandates": revoked["descendant_mandates"],
                        "tasks_stopped": stopped,
                    },
                    outcome="ok",
                ),
            )
            done.append({"task_id": str(r["id"]), "mandate_id": mandate_id, "tasks_stopped": stopped})
            queue.extend(stopped)
    return done


async def release_stale(conn: Conn, project_ids: list[str]) -> int:
    """Release claims whose assignee has written no entry for PACT_STALE_MINUTES.

    The agent may have closed its session and nobody else can tell the board. Each release is logged.
    """
    if not project_ids:
        return 0
    rows = await fetchall(
        conn,
        """UPDATE tasks t SET assignee = NULL, assignee_mandate_id = NULL, status = 'submitted', claimed_at = NULL
           FROM (SELECT t2.id, t2.assignee AS agent_id FROM tasks t2 LEFT JOIN task_activity a ON a.task_id = t2.id
                 WHERE t2.project_id = ANY(%s) AND t2.status = 'working'
                   AND COALESCE(a.at, t2.claimed_at) < now() - make_interval(secs => %s)
                 FOR UPDATE OF t2) stale
           WHERE t.id = stale.id
           RETURNING t.id, t.project_id, stale.agent_id""",
        (project_ids, stale_minutes() * 60),
    )
    for r in rows:
        await append_entry(
            conn,
            EntryInput(
                project_id=r["project_id"],
                task_id=str(r["id"]),
                agent_id=None,
                actor="system",
                mandate_chain=[],
                action="task.release_stale",
                payload={"released_from": r["agent_id"], "after_minutes": stale_minutes()},
                outcome="ok",
            ),
        )
    return len(rows)
