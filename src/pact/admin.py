"""Human-only operations. The Admin UI (phase 3) calls these; until then the `pact-admin` CLI does.

Agents never reach this module: nothing here is exposed over MCP.
"""

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from psycopg_pool import AsyncConnectionPool

from .board import Client, agent_projects, revoke_closed_task_mandates
from .crypto import new_token, sha256
from .db import Conn, fetchall, fetchone, transaction
from .entries import SYSTEM_CHAIN, EntryInput, append_entry, erase_payload, verify_entry_chain
from .errors import PactError
from .mandates import Limits, get_mandate, issue_root, revoke_subtree
from .scope import board_scope, is_valid_scope

Role = Literal["owner", "approver", "viewer"]
_RANK: dict[str, int] = {"viewer": 0, "approver": 1, "owner": 2}

DEFAULT_MANDATE_DAYS = 30
DEFAULT_TOKEN_DAYS = 30


def default_scope(client: Client, projects: list[str]) -> list[str]:
    """What a fresh registration grants. Post-only clients still carry task.work so they can
    delegate it; the board refuses their own claims by client type."""
    return [board_scope(a, p) for p in projects for a in ("task.read", "task.post", "task.work")]


class Admin:
    def __init__(self, pool: AsyncConnectionPool[Conn]) -> None:
        self.pool = pool

    async def _require(self, conn: Conn, human: str, role: Role) -> None:
        row = await fetchone(conn, "SELECT role FROM humans WHERE id = %s", (human,))
        if row is None:
            raise PactError("forbidden", f"{human} is not a registered human")
        if _RANK[row["role"]] < _RANK[role]:
            raise PactError("forbidden", f"{human} is {row['role']}; this needs {role}")

    async def _log(
        self,
        conn: Conn,
        human: str,
        action: str,
        payload: Any,
        *,
        project_id: str | None = None,
        task_id: str | None = None,
        mandate_chain: list[str] | None = None,
    ) -> None:
        await append_entry(
            conn,
            EntryInput(
                project_id=project_id,
                task_id=task_id,
                agent_id=None,
                actor=f"human:{human}",
                mandate_chain=mandate_chain or [],
                action=action,
                payload=payload,
                outcome="ok",
            ),
        )

    async def add_human(self, human_id: str, name: str, role: Role, *, by: str | None = None, email: str | None = None) -> None:
        """Add a person. The very first one bootstraps as owner without `by`.

        `email` is how an OAuth sign-in finds this person; without it they can only use agent tokens.
        """
        async with transaction(self.pool) as conn:
            count = (await fetchone(conn, "SELECT count(*) AS n FROM humans"))["n"]  # type: ignore[index]
            if count > 0:
                if by is None:
                    raise PactError("forbidden", "only an owner can add people once the first owner exists")
                await self._require(conn, by, "owner")
            elif role != "owner":
                raise PactError("invalid_request", "the first person must be an owner")
            await conn.execute(
                "INSERT INTO humans (id, name, role, email) VALUES (%s, %s, %s, %s)", (human_id, name, role, email)
            )
            await self._log(conn, by or human_id, "admin.human.add", {"id": human_id, "role": role, "email": email})

    async def add_project(self, project_id: str, name: str, *, by: str, production: bool = False) -> None:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            await conn.execute(
                "INSERT INTO projects (id, name, production, created_by) VALUES (%s, %s, %s, %s)",
                (project_id, name, production, by),
            )
            await self._log(conn, by, "admin.project.add", {"id": project_id, "production": production}, project_id=project_id)

    async def set_project_flags(
        self, project_id: str, *, by: str, production: bool | None = None, frozen: bool | None = None
    ) -> None:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            cur = await conn.execute(
                "UPDATE projects SET production = COALESCE(%s, production), frozen = COALESCE(%s, frozen) WHERE id = %s",
                (production, frozen, project_id),
            )
            if cur.rowcount == 0:
                raise PactError("not_found", f"project {project_id} does not exist")
            await self._log(conn, by, "admin.project.flags", {"production": production, "frozen": frozen}, project_id=project_id)

    async def register_agent(
        self,
        agent_id: str,
        *,
        by: str,
        client: Client,
        projects: list[str],
        scope: list[str] | None = None,
        limits: Limits | None = None,
        delegations: int = 2,
        mandate_days: float = DEFAULT_MANDATE_DAYS,
        token_days: float = DEFAULT_TOKEN_DAYS,
        owner: str | None = None,
    ) -> dict[str, Any]:
        """Register an agent: its root mandate (issued by `by`) and a bearer token.

        The token is shown once; only its hash is stored.
        """
        if not projects:
            raise PactError("project_required", "an agent needs at least one project")
        if client in ("code", "runner") and len(projects) != 1:
            raise PactError("invalid_request", f"a {client} agent belongs to exactly one project")
        scope = scope or default_scope(client, projects)
        bad = [s for s in scope if not is_valid_scope(s)]
        if bad:
            raise PactError("invalid_request", f"invalid scope: {', '.join(bad)}")
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            for p in projects:
                row = await fetchone(conn, "SELECT production FROM projects WHERE id = %s", (p,))
                if row is None:
                    raise PactError("not_found", f"project {p} does not exist")
                if client == "runner" and row["production"]:
                    raise PactError("project_mismatch", f"project {p} is production; a Runner may not be registered on it")
            await conn.execute("INSERT INTO agents (id, owner, client) VALUES (%s, %s, %s)", (agent_id, owner or by, client))
            for p in projects:
                await conn.execute("INSERT INTO agent_projects (agent_id, project_id) VALUES (%s, %s)", (agent_id, p))
            mandate = await issue_root(
                conn,
                human=by,
                holder=agent_id,
                scope=scope,
                limits=limits or {},
                delegations=delegations,
                expires_at=datetime.now(UTC) + timedelta(days=mandate_days),
            )
            await conn.execute("UPDATE agents SET root_mandate_id = %s WHERE id = %s", (mandate.id, agent_id))
            token = await self._issue_token(conn, agent_id, token_days)
            await self._log(
                conn,
                by,
                "admin.agent.register",
                {"agent": agent_id, "client": client, "projects": projects, "scope": scope, "limits": limits or {}},
                project_id=projects[0] if len(projects) == 1 else None,
                mandate_chain=[mandate.id],
            )
        return {"agent_id": agent_id, "root_mandate_id": mandate.id, "token": token, "connector_path": f"/mcp/a/{agent_id}"}

    async def _issue_token(self, conn: Conn, agent_id: str, days: float) -> str:
        token = new_token()
        await conn.execute(
            "INSERT INTO agent_tokens (token_hash, agent_id, expires_at) VALUES (%s, %s, %s)",
            (sha256(token), agent_id, datetime.now(UTC) + timedelta(days=days)),
        )
        return token

    async def issue_token(self, agent_id: str, *, by: str, days: float = DEFAULT_TOKEN_DAYS) -> str:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            token = await self._issue_token(conn, agent_id, days)
            await self._log(conn, by, "admin.token.issue", {"agent": agent_id, "days": days})
            return token

    async def revoke_tokens(self, agent_id: str, *, by: str) -> int:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            cur = await conn.execute(
                "UPDATE agent_tokens SET revoked_at = now() WHERE agent_id = %s AND revoked_at IS NULL", (agent_id,)
            )
            await self._log(conn, by, "admin.token.revoke", {"agent": agent_id})
            return cur.rowcount

    async def issue_mandate(
        self,
        holder: str,
        *,
        by: str,
        scope: list[str],
        limits: Limits | None = None,
        delegations: int = 1,
        days: float = DEFAULT_MANDATE_DAYS,
    ) -> str:
        """A further root mandate for an existing agent, e.g. after a deferred task asked for more scope."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            projects = {p.id for p in await agent_projects(conn, holder)}
            foreign = [s for s in scope if "@project:" in s and s.split("@project:", 1)[1] not in projects]
            if foreign:
                raise PactError("project_mismatch", f"{holder} is not registered in: {', '.join(foreign)}")
            m = await issue_root(
                conn,
                human=by,
                holder=holder,
                scope=scope,
                limits=limits or {},
                delegations=delegations,
                expires_at=datetime.now(UTC) + timedelta(days=days),
            )
            await self._log(
                conn, by, "admin.mandate.issue", {"holder": holder, "scope": scope, "limits": limits or {}}, mandate_chain=[m.id]
            )
            return m.id

    async def revoke_mandate(self, mandate_id: str, *, by: str) -> dict[str, Any]:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            if await get_mandate(conn, mandate_id) is None:
                raise PactError("not_found", f"mandate {mandate_id} does not exist")
            r = await revoke_subtree(conn, mandate_id)
            await self._log(conn, by, "admin.mandate.revoke", {"mandate_id": mandate_id}, mandate_chain=[mandate_id])
            await revoke_closed_task_mandates(conn, [tid for tid, _ in r["stopped"]])
            return {"descendant_mandates": r["descendant_mandates"], "tasks_stopped": r["tasks_stopped"]}

    async def set_agent_status(self, agent_id: str, status: Literal["active", "paused", "banned"], *, by: str) -> None:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner" if status == "banned" else "approver")
            cur = await conn.execute("UPDATE agents SET status = %s WHERE id = %s", (status, agent_id))
            if cur.rowcount == 0:
                raise PactError("not_found", f"agent {agent_id} does not exist")
            await self._log(conn, by, "admin.agent.status", {"agent": agent_id, "status": status})

    async def set_halted(self, halted: bool, *, by: str) -> None:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            await conn.execute("UPDATE system_state SET halted = %s", (halted,))
            await self._log(conn, by, "admin.kill_switch", {"halted": halted})

    async def approve_task(self, task_id: str, *, by: str, approve: bool = True) -> None:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            row = await fetchone(
                conn,
                """UPDATE tasks SET status = %s, approved_by = %s, approved_at = now()
                   WHERE id = %s AND status = 'auth_required' RETURNING project_id""",
                ("submitted" if approve else "rejected", by, task_id),
            )
            if row is None:
                raise PactError("invalid_request", f"task {task_id} is not waiting for approval")
            await self._log(conn, by, "admin.task.approve", {"approve": approve}, project_id=row["project_id"], task_id=task_id)
            if not approve:
                await revoke_closed_task_mandates(conn, [task_id])

    async def resume_task(self, task_id: str, *, by: str) -> None:
        """Put a deferred task back on the board, unchanged, once a human has decided."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            row = await fetchone(
                conn,
                """UPDATE tasks SET status = 'submitted', deferred = false
                   WHERE id = %s AND deferred RETURNING project_id""",
                (task_id,),
            )
            if row is None:
                raise PactError("invalid_request", f"task {task_id} is not deferred")
            await self._log(conn, by, "admin.task.resume", {}, project_id=row["project_id"], task_id=task_id)

    async def erase_payload(self, entry_id: int, *, by: str) -> bool:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            erased = await erase_payload(conn, entry_id)
            await self._log(conn, by, "admin.payload.erase", {"entry_id": entry_id})
            return erased

    async def verify_log(self, chain_key: str | None = None) -> list[dict[str, Any]]:
        async with transaction(self.pool) as conn:
            keys = (
                [chain_key]
                if chain_key
                else [r["chain_key"] for r in await fetchall(conn, "SELECT chain_key FROM entry_chain_heads ORDER BY chain_key")]
            )
            return [(await verify_entry_chain(conn, k)).__dict__ for k in keys or [SYSTEM_CHAIN]]

    async def sweep_closed_task_mandates(self) -> list[dict[str, Any]]:
        """Revoke mandates still alive under tasks that already closed. Idempotent; runs with
        every migrate so a deploy cleans up what was left behind."""
        async with transaction(self.pool) as conn:
            return await revoke_closed_task_mandates(conn)
