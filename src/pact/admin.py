"""Human-only operations. The Admin UI (phase 3) calls these; until then the `pact-admin` CLI does.

Agents never reach this module: nothing here is exposed over MCP.
"""

import hashlib
import json
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import psycopg
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
from .crypto import iso, new_token, sha256
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
PREFERENCES_MAX = 4000
"""Characters of JSON an agent's preferences may take: they ride along in every pact_whoami."""
KEY_CLIENTS: tuple[Client, ...] = ("code", "runner")
AGENT_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
OAUTH_CLIENTS: tuple[Client, ...] = ("chat", "cowork", "design")
"""Clients that sign in through OAuth in a Claude app; the rest connect with a token."""
SETUP_CODE_MINUTES = 15
ROLE_SETTING = re.compile(r"PACT_RUNNER_[A-Z0-9_]+|DATABASE_URL")
"""Settings a role may write into a Runner's env file: the runner's own and its test database."""
CLIENT_NAMES = ("chat", "cowork", "design", "code", "gemini", "runner")


def board_url() -> str:
    """The board's public URL, for connector URLs and setup commands. The Admin API runs as its own
    service, so it is told (``PACT_BOARD_URL``) or reads it off the admin audience."""
    explicit = os.environ.get("PACT_BOARD_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    audience = os.environ.get("PACT_ADMIN_AUDIENCE", "").strip()
    if audience.endswith("/admin"):
        return audience.removesuffix("/admin")
    return os.environ.get("PACT_PUBLIC_URL", "http://127.0.0.1:8787").rstrip("/")


def role_scope(actions: list[str], project: str) -> list[str]:
    return [board_scope(a, project) for a in actions]


def render_settings(settings: dict[str, Any], project: str) -> dict[str, str]:
    """A role's Runner settings for one project: ``{project}`` filled in, everything a string."""
    return {k: str(v).replace("{project}", project) for k, v in settings.items()}


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
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            out = await self._register(
                conn,
                agent_id,
                by=by,
                client=client,
                projects=projects,
                scope=scope,
                limits=limits,
                delegations=delegations,
                mandate_days=mandate_days,
                owner=owner,
            )
            out["token"] = await self._issue_token(conn, agent_id, token_days)
            return out

    async def _register(
        self,
        conn: Conn,
        agent_id: str,
        *,
        by: str,
        client: Client,
        projects: list[str],
        scope: list[str] | None,
        limits: Limits | None,
        delegations: int,
        mandate_days: float,
        owner: str | None = None,
        role_id: str | None = None,
    ) -> dict[str, Any]:
        """Create the agent, its project links and its root mandate, in the caller's transaction."""
        if not projects:
            raise PactError("project_required", "an agent needs at least one project")
        if not AGENT_ID.fullmatch(agent_id):
            raise PactError("invalid_request", f"agent id {agent_id!r} must be lowercase letters, digits and dashes")
        if client in ("code", "runner") and len(projects) != 1:
            raise PactError("invalid_request", f"a {client} agent belongs to exactly one project")
        scope = scope or default_scope(client, projects)
        bad = [s for s in scope if not is_valid_scope(s)]
        if bad:
            raise PactError("invalid_request", f"invalid scope: {', '.join(bad)}")
        if await fetchone(conn, "SELECT 1 FROM agents WHERE id = %s", (agent_id,)):
            raise PactError("invalid_request", f"agent {agent_id} already exists; pick another name")
        for p in projects:
            row = await fetchone(conn, "SELECT production FROM projects WHERE id = %s", (p,))
            if row is None:
                raise PactError("not_found", f"project {p} does not exist")
            if client == "runner" and row["production"]:
                raise PactError("project_mismatch", f"project {p} is production; a Runner may not be registered on it")
        await conn.execute(
            "INSERT INTO agents (id, owner, client, role_id) VALUES (%s, %s, %s, %s)", (agent_id, owner or by, client, role_id)
        )
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
        await self._log(
            conn,
            by,
            "admin.agent.register",
            {
                "agent": agent_id,
                "client": client,
                "projects": projects,
                "scope": scope,
                "limits": limits or {},
                "role": role_id,
            },
            project_id=projects[0] if len(projects) == 1 else None,
            mandate_chain=[mandate.id],
        )
        return {"agent_id": agent_id, "root_mandate_id": mandate.id, "connector_path": f"/mcp/a/{agent_id}"}

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
        person's name, so adding one is as weighty as adding the person.

        A key that was revoked can be trusted again (a mistaken or temporary revoke should not
        force the organization to rotate its key), but only from now on: mandates imported under
        it before stay dead, since they were imported before this activation."""
        try:
            raw = public_key_from_text(public_key)
        except ValueError as err:
            raise PactError("invalid_request", str(err)) from err
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "owner")
            if await fetchone(conn, "SELECT 1 FROM humans WHERE id = %s", (human,)) is None:
                raise PactError("not_found", f"{human} is not a registered human")
            existing = await fetchone(conn, "SELECT revoked_at FROM trusted_roots WHERE principal = %s FOR UPDATE", (raw,))
            principal = b64url(raw)
            if existing is not None and existing["revoked_at"] is None:
                raise PactError("invalid_request", "this key is already a trusted root")
            if existing is None:
                await conn.execute(
                    "INSERT INTO trusted_roots (principal, human, label, created_by) VALUES (%s, %s, %s, %s)",
                    (raw, human, label, by),
                )
            else:
                await conn.execute(
                    """UPDATE trusted_roots SET human = %s, label = %s, revoked_at = NULL, active_since = now()
                       WHERE principal = %s""",
                    (human, label, raw),
                )
            action = "admin.trusted_root.add" if existing is None else "admin.trusted_root.reactivate"
            await self._log(conn, by, action, {"principal": principal, "human": human, "label": label})
        return {"principal": principal, "human": human, "label": label, "reactivated": existing is not None}

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
                """SELECT principal, human, label, created_by, created_at, active_since, revoked_at
                   FROM trusted_roots ORDER BY created_at""",
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

    async def set_agent_preferences(self, agent_id: str, preferences: Any, *, by: str) -> dict[str, Any]:
        """Replace an agent's preferences: how it should work, handed to it by pact_whoami. They
        reach every session the agent opens, so they stay small."""
        if not isinstance(preferences, dict):
            raise PactError("invalid_request", "preferences must be a JSON object")
        if len(json.dumps(preferences, ensure_ascii=False)) > PREFERENCES_MAX:
            raise PactError("invalid_request", f"preferences are longer than {PREFERENCES_MAX} characters")
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            cur = await conn.execute("UPDATE agents SET preferences = %s WHERE id = %s", (Jsonb(preferences), agent_id))
            if cur.rowcount == 0:
                raise PactError("not_found", f"agent {agent_id} does not exist")
            await self._log(conn, by, "admin.agent.preferences", {"agent": agent_id, "preferences": preferences})
        return preferences

    # ── hiring from roles ──────────────────────────────────────────────────

    async def list_roles(self, *, archived: bool = False) -> list[dict[str, Any]]:
        async with transaction(self.pool) as conn:
            return await fetchall(
                conn,
                f"""SELECT id, name, description, client, actions, limits, delegations, mandate_days, token_days,
                           settings, instructions, position, archived_at, updated_at, updated_by
                    FROM agent_roles {"" if archived else "WHERE archived_at IS NULL"} ORDER BY position, id""",
            )

    async def save_role(self, role_id: str, fields: dict[str, Any], *, by: str) -> dict[str, Any]:
        """Create or replace a role. Everything a hire will grant is checked here, once."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", role_id):
            raise PactError("invalid_request", f"role id {role_id!r} must be lowercase letters, digits and dashes")
        name = str(fields.get("name") or "").strip()
        client = fields.get("client")
        actions = [str(a).strip() for a in fields.get("actions") or [] if str(a).strip()]
        if not name or client not in CLIENT_NAMES or not actions:
            raise PactError("invalid_request", "a role needs a name, a client and at least one action")
        bad = [a for a in actions if "@" in a or not is_valid_scope(board_scope(a, "p"))]
        if bad:
            raise PactError("invalid_request", f"actions are project-relative, like task.work: {', '.join(bad)}")
        limits = fields.get("limits") or {}
        if not isinstance(limits, dict) or any(
            not isinstance(v, int | float) or isinstance(v, bool) or v < 0 for v in limits.values()
        ):
            raise PactError("invalid_request", "limits must map names to numbers of at least 0")
        settings = {str(k): str(v) for k, v in (fields.get("settings") or {}).items()}
        wrong = [k for k in settings if not ROLE_SETTING.fullmatch(k)]
        if wrong:
            raise PactError("invalid_request", f"settings may only be PACT_RUNNER_* or DATABASE_URL: {', '.join(wrong)}")
        row = (
            role_id,
            name,
            str(fields.get("description") or ""),
            client,
            actions,
            Jsonb(limits),
            int(fields.get("delegations", 1)),
            float(fields.get("mandate_days", 30)),
            float(fields.get("token_days", 90)),
            Jsonb(settings),
            str(fields.get("instructions") or ""),
            int(fields.get("position", 100)),
            by,
        )
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            try:
                await conn.execute(
                    """INSERT INTO agent_roles (id, name, description, client, actions, limits, delegations, mandate_days,
                                                token_days, settings, instructions, position, updated_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
                         client = EXCLUDED.client, actions = EXCLUDED.actions, limits = EXCLUDED.limits,
                         delegations = EXCLUDED.delegations, mandate_days = EXCLUDED.mandate_days,
                         token_days = EXCLUDED.token_days, settings = EXCLUDED.settings,
                         instructions = EXCLUDED.instructions, position = EXCLUDED.position,
                         archived_at = NULL, updated_at = now(), updated_by = EXCLUDED.updated_by""",
                    row,
                )
            except psycopg.errors.CheckViolation as err:
                raise PactError("invalid_request", f"role {role_id} is out of range: {err.diag.constraint_name}") from None
            await self._log(conn, by, "admin.role.save", {"role": role_id, **{k: v for k, v in fields.items()}})
        return {"ok": True, "role": role_id}

    async def archive_role(self, role_id: str, *, by: str) -> None:
        """Retire a role: no new hires. Agents already hired keep working."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            cur = await conn.execute("UPDATE agent_roles SET archived_at = now() WHERE id = %s", (role_id,))
            if cur.rowcount == 0:
                raise PactError("not_found", f"role {role_id} does not exist")
            await self._log(conn, by, "admin.role.archive", {"role": role_id})

    async def _role(self, conn: Conn, role_id: str) -> dict[str, Any]:
        role = await fetchone(conn, "SELECT * FROM agent_roles WHERE id = %s", (role_id,))
        if role is None:
            raise PactError("not_found", f"role {role_id} does not exist")
        return role

    async def hire(
        self,
        role_id: str,
        project: str,
        *,
        by: str,
        agent_id: str | None = None,
        limits: Limits | None = None,
        delegations: int | None = None,
        days: float | None = None,
        replaces: str | None = None,
        owner: str | None = None,
    ) -> dict[str, Any]:
        """Hire an agent into a role for one project: register it with the role's scope, budget and
        term, and say how it connects. An agent that signs in through a Claude app gets its
        connector URL; one that uses a token gets a one-time setup code, never the token itself.
        With ``replaces``, the old agent is banned and points to the new one. ``owner`` hires it for
        another registered person: an agent that signs in through OAuth answers only to its owner."""
        agent_id = agent_id or f"{role_id}-{project}"
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            if owner and not await fetchone(conn, "SELECT 1 FROM humans WHERE id = %s", (owner,)):
                raise PactError("not_found", f"{owner} is not a registered person")
            role = await self._role(conn, role_id)
            if role["archived_at"]:
                raise PactError("invalid_request", f"role {role_id} is archived")
            out = await self._register(
                conn,
                agent_id,
                by=by,
                client=role["client"],
                projects=[project],
                scope=role_scope(list(role["actions"]), project),
                limits=limits if limits is not None else {k: float(v) for k, v in role["limits"].items()},
                delegations=delegations if delegations is not None else role["delegations"],
                mandate_days=days if days is not None else role["mandate_days"],
                owner=owner,
                role_id=role_id,
            )
            if replaces:
                old = await fetchone(conn, "SELECT id FROM agents WHERE id = %s", (replaces,))
                if old is None:
                    raise PactError("not_found", f"agent {replaces} does not exist")
                await conn.execute("UPDATE agents SET status = 'banned', replaced_by = %s WHERE id = %s", (agent_id, replaces))
                await conn.execute(
                    "UPDATE agent_tokens SET revoked_at = now() WHERE agent_id = %s AND revoked_at IS NULL", (replaces,)
                )
                await self._log(conn, by, "admin.agent.replace", {"agent": replaces, "replaced_by": agent_id})
            out["role"] = role_id
            out["connect"] = await self._connect_info(conn, agent_id, role["client"], by)
            return out

    async def _connect_info(self, conn: Conn, agent_id: str, client: str, by: str) -> dict[str, Any]:
        url = f"{board_url()}/mcp/a/{agent_id}"
        if client in OAUTH_CLIENTS:
            return {"kind": "oauth", "url": url}
        code = "pcs_" + secrets.token_urlsafe(18)
        expires = datetime.now(UTC) + timedelta(minutes=SETUP_CODE_MINUTES)
        await conn.execute(
            "INSERT INTO setup_codes (code_hash, agent_id, created_by, expires_at) VALUES (%s, %s, %s, %s)",
            (sha256(code), agent_id, by, expires),
        )
        return {
            "kind": "setup_code",
            "code": code,
            "expires_at": expires.isoformat(),
            "command": f"pact-connect {board_url()} {code}",
        }

    async def setup_code(self, agent_id: str, *, by: str) -> dict[str, Any]:
        """A fresh way to connect an agent that uses a token, e.g. on a new machine. Tokens it already
        has keep working until revoked."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            agent = await get_agent(conn, agent_id)
            if agent is None or agent.status == "banned":
                raise PactError("not_found", f"agent {agent_id} does not exist or is banned")
            info = await self._connect_info(conn, agent_id, agent.client, by)
            await self._log(conn, by, "admin.agent.setup_code", {"agent": agent_id, "kind": info["kind"]})
            return info

    async def redeem_setup_code(self, code: str) -> dict[str, Any]:
        """Trade a setup code for a token, once, within its time. Called by ``pact-connect`` on the
        machine the agent will run on, so the token goes straight into its config."""
        async with transaction(self.pool) as conn:
            row = await fetchone(
                conn,
                """SELECT s.agent_id, s.created_by, a.client, a.status, a.role_id,
                          (SELECT project_id FROM agent_projects p WHERE p.agent_id = a.id ORDER BY project_id LIMIT 1) AS project
                   FROM setup_codes s JOIN agents a ON a.id = s.agent_id
                   WHERE s.code_hash = %s AND s.used_at IS NULL AND s.expires_at > now()
                   FOR UPDATE OF s""",
                (sha256(code),),
            )
            if row is None or row["status"] == "banned":
                raise PactError("forbidden", "this setup code is unknown, used or expired; get a new one in the Admin UI")
            await conn.execute("UPDATE setup_codes SET used_at = now() WHERE code_hash = %s", (sha256(code),))
            role = await self._role(conn, row["role_id"]) if row["role_id"] else None
            token = await self._issue_token(conn, row["agent_id"], float(role["token_days"]) if role else DEFAULT_TOKEN_DAYS)
            await self._log(conn, row["created_by"], "admin.agent.connect", {"agent": row["agent_id"]})
            project = row["project"] or ""
            return {
                "agent_id": row["agent_id"],
                "client": row["client"],
                "project": project,
                "board_url": board_url(),
                "mcp_url": f"{board_url()}/mcp/a/{row['agent_id']}",
                "token": token,
                "role": role["id"] if role else None,
                "settings": render_settings(role["settings"], project) if role else {},
                "instructions": role["instructions"] if role else "",
            }

    async def renew(self, agent_id: str, *, by: str) -> dict[str, Any]:
        """Renew an agent's term: a new root mandate with its role's scope, budget and length. The old
        one keeps running until it expires; a Runner moves to the new one when it does."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            agent = await fetchone(
                conn,
                """SELECT a.id, a.status, a.role_id, (SELECT project_id FROM agent_projects p WHERE p.agent_id = a.id
                   ORDER BY project_id LIMIT 1) AS project FROM agents a WHERE a.id = %s""",
                (agent_id,),
            )
            if agent is None or agent["status"] == "banned":
                raise PactError("not_found", f"agent {agent_id} does not exist or is banned")
            if not agent["role_id"]:
                raise PactError("invalid_request", f"agent {agent_id} was not hired into a role; change its permissions instead")
            role = await self._role(conn, agent["role_id"])
            mandate = await issue_root(
                conn,
                human=by,
                holder=agent_id,
                scope=role_scope(list(role["actions"]), agent["project"]),
                limits={k: float(v) for k, v in role["limits"].items()},
                delegations=role["delegations"],
                expires_at=datetime.now(UTC) + timedelta(days=float(role["mandate_days"])),
            )
            await conn.execute("UPDATE agents SET root_mandate_id = %s WHERE id = %s", (mandate.id, agent_id))
            await self._log(conn, by, "admin.agent.renew", {"agent": agent_id, "role": role["id"]}, mandate_chain=[mandate.id])
            return {"agent_id": agent_id, "mandate_id": mandate.id, "expires_at": iso(mandate.expires_at)}

    async def change_role(self, agent_id: str, role_id: str, *, by: str) -> dict[str, Any]:
        """Move an agent to another role of its client. It gets a new root mandate from that role at
        once, and every root mandate it held before is revoked, so the old role's wider rights do not
        linger until they expire; open tasks under them stop. Its tokens and connection stay."""
        async with transaction(self.pool) as conn:
            await self._require(conn, by, "approver")
            agent = await fetchone(
                conn,
                """SELECT a.id, a.client, a.status, a.role_id, (SELECT project_id FROM agent_projects p
                   WHERE p.agent_id = a.id ORDER BY project_id LIMIT 1) AS project FROM agents a WHERE a.id = %s""",
                (agent_id,),
            )
            if agent is None or agent["status"] == "banned":
                raise PactError("not_found", f"agent {agent_id} does not exist or is banned")
            role = await self._role(conn, role_id)
            if role["archived_at"]:
                raise PactError("invalid_request", f"role {role_id} is archived")
            if role["client"] != agent["client"]:
                raise PactError(
                    "invalid_request", f"role {role_id} is for {role['client']} agents; {agent_id} is a {agent['client']} agent"
                )
            old = await fetchall(
                conn,
                """SELECT id FROM mandates WHERE holder = %s AND parent_id IS NULL AND revoked_at IS NULL
                   AND expires_at > now()""",
                (agent_id,),
            )
            mandate = await issue_root(
                conn,
                human=by,
                holder=agent_id,
                scope=role_scope(list(role["actions"]), agent["project"]),
                limits={k: float(v) for k, v in role["limits"].items()},
                delegations=role["delegations"],
                expires_at=datetime.now(UTC) + timedelta(days=float(role["mandate_days"])),
            )
            await conn.execute(
                "UPDATE agents SET role_id = %s, root_mandate_id = %s WHERE id = %s", (role_id, mandate.id, agent_id)
            )
            stopped: list[Any] = []
            for row in old:
                stopped += (await revoke_subtree(conn, str(row["id"])))["stopped"]
            await revoke_closed_task_mandates(conn, [tid for tid, _ in stopped])
            await self._log(
                conn,
                by,
                "admin.agent.role",
                {"agent": agent_id, "from": agent["role_id"], "to": role_id, "revoked": [str(r["id"]) for r in old]},
                mandate_chain=[mandate.id],
            )
            return {
                "agent_id": agent_id,
                "role": role_id,
                "mandate_id": mandate.id,
                "expires_at": iso(mandate.expires_at),
                "revoked_mandates": len(old),
                "tasks_stopped": len(stopped),
            }

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
