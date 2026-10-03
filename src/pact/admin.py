"""Human-only operations. The Admin UI (phase 3) calls these; until then the `pact-admin` CLI does.

Agents never reach this module: nothing here is exposed over MCP.
"""

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from . import context as notes
from . import credentials
from .board import (
    POST_ONLY_CLIENTS,
    TERMINAL_STATUSES,
    Client,
    agent_projects,
    get_agent,
    revoke_closed_task_mandates,
)
from .crypto import new_token, sha256
from .db import Conn, fetchall, fetchone, transaction
from .entries import SYSTEM_CHAIN, EntryInput, append_entry, erase_payload, verify_entry_chain
from .errors import PactError
from .keys import b64url, b64url_decode, public_key_from_text
from .mandates import MAX_DEPTH, ImportedLink, Limits, get_mandate, issue_root, revoke_impact, revoke_subtree
from .scope import board_scope, is_valid_scope

Role = Literal["owner", "approver", "viewer"]
_RANK: dict[str, int] = {"viewer": 0, "approver": 1, "owner": 2}

DEFAULT_MANDATE_DAYS = 30
DEFAULT_TOKEN_DAYS = 30
KEY_CLIENTS: tuple[Client, ...] = ("code", "runner")
"""Clients that hold an Ed25519 key for verifiers outside the board (owner decision 2026-10-02)."""


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

    async def add_agent_key(self, agent_id: str, public_key: str, *, by: str) -> dict[str, Any]:
        """Register an agent's Ed25519 public key (base64url of the raw 32 bytes).

        Verifiers outside the board check each call against the holder's key, so an agent that
        uses exported credentials needs one. Only code and runner agents run on machines that can
        keep a private key; the Claude apps cannot, so they keep working through the board only.
        """
        try:
            raw = public_key_from_text(public_key)
        except ValueError as err:
            raise PactError("invalid_request", str(err)) from err
        kid = b64url(hashlib.sha256(raw).digest())[:16]
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            agent = await get_agent(conn, agent_id)
            if agent is None:
                raise PactError("not_found", f"agent {agent_id} does not exist")
            if agent.client not in KEY_CLIENTS:
                raise PactError("invalid_request", f"{agent.client} agents do not hold keys; only {', '.join(KEY_CLIENTS)} do")
            taken = await fetchone(conn, "SELECT agent_id FROM agent_keys WHERE public_key = %s", (raw,))
            if taken:
                raise PactError("invalid_request", f"this public key is already registered for {taken['agent_id']}")
            await conn.execute(
                "INSERT INTO agent_keys (agent_id, kid, public_key, created_by) VALUES (%s, %s, %s, %s)", (agent_id, kid, raw, by)
            )
            await self._log(conn, by, "admin.agent_key.add", {"agent": agent_id, "kid": kid})
        return {"agent_id": agent_id, "kid": kid}

    async def revoke_agent_key(self, agent_id: str, kid: str, *, by: str) -> int:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            cur = await conn.execute(
                "UPDATE agent_keys SET revoked_at = now() WHERE agent_id = %s AND kid = %s AND revoked_at IS NULL",
                (agent_id, kid),
            )
            await self._log(conn, by, "admin.agent_key.revoke", {"agent": agent_id, "kid": kid})
            return cur.rowcount

    async def add_trusted_root(self, public_key: str, *, human: str, by: str, label: str | None = None) -> dict[str, Any]:
        """Trust an outside Ed25519 key (base64url of its raw 32 bytes) to issue credentials on
        behalf of ``human``. Owners only: a trusted root can grant agents authority in that
        person's name, so adding one is as weighty as adding the person."""
        try:
            raw = public_key_from_text(public_key)
        except ValueError as err:
            raise PactError("invalid_request", str(err)) from err
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            if await fetchone(conn, "SELECT 1 FROM humans WHERE id = %s", (human,)) is None:
                raise PactError("not_found", f"{human} is not a registered human")
            if await fetchone(conn, "SELECT 1 FROM trusted_roots WHERE principal = %s", (raw,)):
                raise PactError("invalid_request", "this key is already a trusted root (a revoked one cannot come back)")
            await conn.execute(
                "INSERT INTO trusted_roots (principal, human, label, created_by) VALUES (%s, %s, %s, %s)", (raw, human, label, by)
            )
            principal = b64url(raw)
            await self._log(conn, by, "admin.trusted_root.add", {"principal": principal, "human": human, "label": label})
        return {"principal": principal, "human": human, "label": label}

    async def revoke_trusted_root(self, principal: str, *, by: str) -> int:
        """Stop trusting a key. Every mandate imported under it fails its chain check from now on."""
        try:
            raw = b64url_decode(principal.strip())
        except ValueError as err:
            raise PactError("invalid_request", "a principal is base64url of a 32-byte public key") from err
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            cur = await conn.execute(
                "UPDATE trusted_roots SET revoked_at = now() WHERE principal = %s AND revoked_at IS NULL", (raw,)
            )
            if cur.rowcount == 0 and await fetchone(conn, "SELECT 1 FROM trusted_roots WHERE principal = %s", (raw,)) is None:
                raise PactError("not_found", f"{principal} is not a trusted root")
            await self._log(conn, by, "admin.trusted_root.revoke", {"principal": principal})
            return cur.rowcount

    async def list_trusted_roots(self) -> list[dict[str, Any]]:
        async with transaction(self.pool) as conn:
            rows = await fetchall(
                conn,
                "SELECT principal, human, label, created_by, created_at, revoked_at FROM trusted_roots ORDER BY created_at",
            )
        return [{**r, "principal": b64url(bytes(r["principal"]))} for r in rows]

    async def import_credential(self, agent_id: str, format_name: str, credential: str, *, by: str) -> str:
        """Turn an outside credential held by ``agent_id`` into a root mandate in the ledger.

        The credential must be rooted at a live trusted root; the mandate's issuer is the human
        that root stands for, so the chain still traces to a person. The credential's holder must
        be one of the agent's live registered keys (so the agent holds the private key), and every
        scope must fall within the agent's projects. People do this, never agents: no MCP tool
        reaches it.
        """
        fmt = credentials.get(format_name)
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            if await get_agent(conn, agent_id) is None:
                raise PactError("not_found", f"agent {agent_id} does not exist")
            roots = [
                credentials.TrustedRoot(principal=b64url(bytes(r["principal"])), human=r["human"])
                for r in await fetchall(conn, "SELECT principal, human FROM trusted_roots WHERE revoked_at IS NULL")
            ]
            got = fmt.ingest(credential.strip().encode(), trusted_roots=roots)
            keys = {
                b64url(bytes(r["public_key"]))
                for r in await fetchall(
                    conn, "SELECT public_key FROM agent_keys WHERE agent_id = %s AND revoked_at IS NULL", (agent_id,)
                )
            }
            if got.holder_key is None or got.holder_key not in keys:
                raise PactError("invalid_request", f"the credential is held by {got.holder_key}, not a live key of {agent_id}")
            projects = {p.id for p in await agent_projects(conn, agent_id)}
            foreign = [s for s in got.scope if s.split("@project:", 1)[-1] not in projects]
            if foreign:
                raise PactError("project_mismatch", f"{agent_id} is not registered in: {', '.join(foreign)}")
            dup = await fetchone(
                conn,
                "SELECT id FROM mandates WHERE coalesce(exported_as, format) = %s AND external_id = %s",
                (got.format, got.external_id),
            )
            if dup:
                raise PactError("invalid_request", f"credential {got.external_id} is already on the board as mandate {dup['id']}")
            m = await issue_root(
                conn,
                human=got.human,
                holder=agent_id,
                scope=got.scope,
                limits=got.limits,
                delegations=min(MAX_DEPTH, got.delegations),
                expires_at=got.expires_at,
                imported=ImportedLink(
                    format=got.format,
                    external_id=got.external_id,
                    credential=got.credential,
                    issuer_principal=got.issuer_principal,
                ),
            )
            await self._log(
                conn,
                by,
                "admin.credential.import",
                {
                    "agent": agent_id,
                    "format": got.format,
                    "external_id": got.external_id,
                    "issuer_principal": got.issuer_principal,
                    "human": got.human,
                    "scope": got.scope,
                    "limits": got.limits,
                    "delegations": m.delegations_left,
                },
                mandate_chain=[m.id],
            )
            return m.id

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

    async def replace_mandate(
        self,
        mandate_id: str,
        *,
        by: str,
        scope: list[str],
        limits: Limits | None = None,
        delegations: int | None = None,
        days: float = DEFAULT_MANDATE_DAYS,
        revoke: bool = False,
    ) -> dict[str, Any]:
        """Change an agent's permissions. Mandates are signed and never edited, so this issues a new
        root mandate, makes it the agent's own, and (with ``revoke``) revokes the old one with
        everything delegated under it. Without ``revoke`` the old one lives on until it expires,
        so work already delegated under it keeps going."""
        bad = [s for s in scope if not is_valid_scope(s)]
        if not scope or bad:
            raise PactError("invalid_request", f"invalid scope: {', '.join(bad)}" if bad else "scope is empty")
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            old = await get_mandate(conn, mandate_id)
            if old is None:
                raise PactError("not_found", f"mandate {mandate_id} does not exist")
            if old.parent_id is not None or old.revoked_at is not None:
                raise PactError("invalid_request", f"mandate {mandate_id} is not a live root mandate")
            projects = {p.id for p in await agent_projects(conn, old.holder)}
            foreign = [s for s in scope if "@project:" in s and s.split("@project:", 1)[1] not in projects]
            if foreign:
                raise PactError("project_mismatch", f"{old.holder} is not registered in: {', '.join(foreign)}")
            new = await issue_root(
                conn,
                human=by,
                holder=old.holder,
                scope=scope,
                limits=old.limits if limits is None else limits,
                delegations=old.delegations_left if delegations is None else delegations,
                expires_at=datetime.now(UTC) + timedelta(days=days),
            )
            await conn.execute("UPDATE agents SET root_mandate_id = %s WHERE id = %s", (new.id, old.holder))
            revoked = {"descendant_mandates": 0, "tasks_stopped": 0}
            if revoke:
                r = await revoke_subtree(conn, mandate_id)
                await revoke_closed_task_mandates(conn, [tid for tid, _ in r["stopped"]])
                revoked = {"descendant_mandates": r["descendant_mandates"], "tasks_stopped": r["tasks_stopped"]}
            await self._log(
                conn,
                by,
                "admin.mandate.replace",
                {"holder": old.holder, "replaces": mandate_id, "scope": scope, "was": old.scope, "revoked": revoke},
                mandate_chain=[new.id],
            )
            return {"mandate_id": new.id, "replaced": mandate_id, "revoked": revoke, **revoked}

    async def revoke_mandate(self, mandate_id: str, *, by: str) -> dict[str, Any]:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            if await get_mandate(conn, mandate_id) is None:
                raise PactError("not_found", f"mandate {mandate_id} does not exist")
            r = await revoke_subtree(conn, mandate_id)
            await self._log(conn, by, "admin.mandate.revoke", {"mandate_id": mandate_id}, mandate_chain=[mandate_id])
            await revoke_closed_task_mandates(conn, [tid for tid, _ in r["stopped"]])
            return {"descendant_mandates": r["descendant_mandates"], "tasks_stopped": r["tasks_stopped"]}

    async def revoke_mandate_impact(self, mandate_id: str) -> dict[str, Any]:
        """A dry run of revoke_mandate, for the confirmation people see before they revoke."""
        async with transaction(self.pool) as conn:
            if await get_mandate(conn, mandate_id) is None:
                raise PactError("not_found", f"mandate {mandate_id} does not exist")
            return await revoke_impact(conn, mandate_id)

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

    async def resume_task(self, task_id: str, *, by: str, answer: str | None = None) -> None:
        """Put a deferred task back on the board once a human has decided, with their answer to
        the agent's question if they gave one. The agent reads it as the task's `answer`."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            row = await fetchone(
                conn,
                """UPDATE tasks SET status = 'submitted', deferred = false, answer = coalesce(%s, answer)
                   WHERE id = %s AND deferred RETURNING project_id""",
                (answer, task_id),
            )
            if row is None:
                raise PactError("invalid_request", f"task {task_id} is not deferred")
            await self._log(conn, by, "admin.task.resume", {"answer": answer}, project_id=row["project_id"], task_id=task_id)

    async def _open_task(self, conn: Conn, task_id: str) -> dict[str, Any]:
        """Lock a task a person is about to change; closed tasks are left as they ended."""
        row = await fetchone(conn, "SELECT * FROM tasks WHERE id::text = %s FOR UPDATE", (task_id,))
        if row is None:
            raise PactError("not_found", f"task {task_id} does not exist")
        if row["status"] in TERMINAL_STATUSES:
            raise PactError("invalid_request", f"task {task_id} is {row['status']} and cannot change")
        return row

    async def assign_task(self, task_id: str, agent_id: str | None, *, by: str) -> dict[str, Any]:
        """Name the one agent that may claim a task, or open it to any agent of the project (None).

        Only while nobody holds it: release it first. The new agent claims with its own mandate.
        A mandate delegated to the previous agent for this task is revoked, since that agent no
        longer has the task.
        """
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            task = await self._open_task(conn, task_id)
            if task["assignee"]:
                raise PactError("invalid_request", f"task {task_id} is held by {task['assignee']}; release it first")
            if agent_id is not None:
                agent = await get_agent(conn, agent_id)
                if agent is None or task["project_id"] not in {p.id for p in await agent_projects(conn, agent_id)}:
                    raise PactError("agent_unknown", f"agent {agent_id} is not registered in project {task['project_id']}")
                if agent.client in POST_ONLY_CLIENTS:
                    raise PactError(
                        "invalid_request", f"{agent_id} is a {agent.client} agent; it posts tasks but cannot claim them"
                    )
                if agent.status == "banned":
                    raise PactError("agent_paused", f"agent {agent_id} is banned")
            old_mandate = task["delegated_mandate_id"] if task["delegate_to"] != agent_id else None
            await conn.execute(
                "UPDATE tasks SET delegate_to = %s, delegated_mandate_id = %s WHERE id = %s",
                (agent_id, None if old_mandate else task["delegated_mandate_id"], task["id"]),
            )
            revoked: dict[str, Any] = {"descendant_mandates": 0, "tasks_stopped": 0, "stopped": []}
            if old_mandate:
                revoked = await revoke_subtree(conn, str(old_mandate))
            await self._log(
                conn,
                by,
                "admin.task.assign",
                {"from": task["delegate_to"], "to": agent_id, "revoked_mandate": str(old_mandate) if old_mandate else None},
                project_id=task["project_id"],
                task_id=str(task["id"]),
            )
            await revoke_closed_task_mandates(conn, [tid for tid, _ in revoked["stopped"]])
            return {"delegate_to": agent_id, "revoked_mandate": str(old_mandate) if old_mandate else None}

    async def release_task(self, task_id: str, *, by: str) -> dict[str, Any]:
        """Take a task back from the agent holding it; it returns to the board as submitted.

        The agent's next report gets claim_lost, so it stops without overwriting anyone.
        """
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            task = await self._open_task(conn, task_id)
            if task["status"] != "working" or not task["assignee"]:
                raise PactError("invalid_request", f"task {task_id} is not held by an agent")
            await conn.execute(
                """UPDATE tasks SET assignee = NULL, assignee_mandate_id = NULL, status = 'submitted', claimed_at = NULL
                   WHERE id = %s""",
                (task["id"],),
            )
            await self._log(
                conn,
                by,
                "admin.task.release",
                {"released_from": task["assignee"]},
                project_id=task["project_id"],
                task_id=str(task["id"]),
            )
            return {"released_from": task["assignee"]}

    async def cancel_task(self, task_id: str, *, by: str, reason: str | None = None) -> dict[str, Any]:
        """Close a task nobody should do any more. Its delegated mandate dies with it, as with any close."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            task = await self._open_task(conn, task_id)
            await conn.execute(
                "UPDATE tasks SET status = 'canceled', deferred = false, result = %s WHERE id = %s",
                (Jsonb({"reason": "canceled_by_human", "by": by, "note": reason}), task["id"]),
            )
            await self._log(
                conn,
                by,
                "admin.task.cancel",
                {"reason": reason, "status_was": task["status"], "assignee": task["assignee"]},
                project_id=task["project_id"],
                task_id=str(task["id"]),
            )
            done = await revoke_closed_task_mandates(conn, [str(task["id"])])
            return {"revoked": done}

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

    async def write_note(
        self, project_id: str, key: str, *, by: str, title: str | None = None, body: str | None = None, archive: bool = False
    ) -> dict[str, Any]:
        """A person writes project context; pinned notes too."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            out = await notes.write_note(
                conn, project_id, key, by=f"human:{by}", title=title, body=body, archive=archive, human=True
            )
            await self._log(
                conn,
                by,
                "admin.context.write",
                {"key": key, "title": title, "body": body, "archive": archive},
                project_id=project_id,
            )
            return out

    async def pin_note(self, project_id: str, key: str, pinned: bool, *, by: str) -> None:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            await notes.set_pinned(conn, project_id, key, pinned)
            await self._log(conn, by, "admin.context.pin", {"key": key, "pinned": pinned}, project_id=project_id)

    async def erase_note_version(self, version_id: int, *, by: str) -> dict[str, Any]:
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            out = await notes.erase_version(conn, version_id)
            await self._log(conn, by, "admin.context.erase", {"version_id": version_id}, project_id=out["project_id"])
            return out

    async def sweep_closed_task_mandates(self) -> list[dict[str, Any]]:
        """Revoke mandates still alive under tasks that already closed. Idempotent; runs with
        every migrate so a deploy cleans up what was left behind."""
        async with transaction(self.pool) as conn:
            return await revoke_closed_task_mandates(conn)
