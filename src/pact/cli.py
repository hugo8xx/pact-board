"""`pact-admin`: the human-side commands until the Admin UI exists (phase 3).

Every command except `migrate` and the first `human add` needs `--by <human-id>`.
"""

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from typing import Any

from .admin import Admin
from .db import create_pool, migrate
from .errors import PactError
from .keys import new_seed


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pact-admin", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("migrate", help="apply database migrations, then revoke mandates of closed tasks")

    h = sub.add_parser("human-add", help="add a person (the first one becomes the bootstrap owner)")
    h.add_argument("id")
    h.add_argument("name")
    h.add_argument("role", choices=["owner", "approver", "viewer"])
    h.add_argument("--by")
    h.add_argument("--email", help="the address this person signs in with")

    pr = sub.add_parser("project-add")
    pr.add_argument("id")
    pr.add_argument("name")
    pr.add_argument("--by", required=True)
    pr.add_argument("--production", action="store_true")

    pf = sub.add_parser("project-set", help="set production / frozen")
    pf.add_argument("id")
    pf.add_argument("--by", required=True)
    pf.add_argument("--production", choices=["true", "false"])
    pf.add_argument("--frozen", choices=["true", "false"])

    ar = sub.add_parser("agent-register")
    ar.add_argument("id")
    ar.add_argument("--by", required=True)
    ar.add_argument("--client", required=True, choices=["chat", "cowork", "design", "code", "gemini", "runner"])
    ar.add_argument("--projects", required=True, type=_csv, help="comma-separated project ids")
    ar.add_argument("--scope", type=_csv, help="comma-separated scopes (default: read/post/work on each project)")
    ar.add_argument("--limits", type=json.loads, help='JSON, e.g. {"thb": 100000}')
    ar.add_argument("--delegations", type=int, default=2)
    ar.add_argument("--days", type=float, default=30, help="mandate and token lifetime")
    ar.add_argument("--owner", help="the human who owns the agent (default: --by)")

    ast = sub.add_parser("agent-status")
    ast.add_argument("id")
    ast.add_argument("status", choices=["active", "paused", "banned"])
    ast.add_argument("--by", required=True)

    apf = sub.add_parser("agent-prefs", help="replace an agent's preferences (handed to it by pact_whoami)")
    apf.add_argument("id")
    apf.add_argument("preferences", type=json.loads, help='JSON object, e.g. {"language": "th"}')
    apf.add_argument("--by", required=True)

    ti = sub.add_parser("token-issue")
    ti.add_argument("agent")
    ti.add_argument("--by", required=True)
    ti.add_argument("--days", type=float, default=30)
    tr = sub.add_parser("token-revoke")
    tr.add_argument("agent")
    tr.add_argument("--by", required=True)

    ka = sub.add_parser("agent-key-add", help="register an agent's Ed25519 public key (code and runner agents only)")
    ka.add_argument("agent")
    ka.add_argument("public_key", help="base64url of the raw 32-byte public key")
    ka.add_argument("--by", required=True)
    kr = sub.add_parser("agent-key-revoke")
    kr.add_argument("agent")
    kr.add_argument("kid")
    kr.add_argument("--by", required=True)
    sub.add_parser("key-new", help="print a fresh entry for PACT_BOARD_KEYS; put it first to rotate the board's signing key")

    ta = sub.add_parser("trusted-root-add", help="trust an outside Ed25519 key to issue credentials for a person (owner)")
    ta.add_argument("public_key", help="base64url of the raw 32-byte public key")
    ta.add_argument("--human", required=True, help="the registered person this key stands for")
    ta.add_argument("--label")
    ta.add_argument("--by", required=True)
    trr = sub.add_parser("trusted-root-revoke", help="stop trusting a key; mandates imported under it stop working")
    trr.add_argument("principal")
    trr.add_argument("--by", required=True)
    sub.add_parser("trusted-root-list")
    ci = sub.add_parser("credential-import", help="turn an outside credential an agent holds into a root mandate")
    ci.add_argument("agent")
    ci.add_argument("credential", help="the credential as text (a Tenuo warrant stack is base64)")
    ci.add_argument("--format", default="tenuo")
    ci.add_argument("--by", required=True)

    mi = sub.add_parser("mandate-issue")
    mi.add_argument("holder")
    mi.add_argument("--by", required=True)
    mi.add_argument("--scope", required=True, type=_csv)
    mi.add_argument("--limits", type=json.loads)
    mi.add_argument("--delegations", type=int, default=1)
    mi.add_argument("--days", type=float, default=30)
    mr = sub.add_parser("mandate-revoke")
    mr.add_argument("id")
    mr.add_argument("--by", required=True)

    for name in ("task-approve", "task-reject", "task-resume"):
        t = sub.add_parser(name)
        t.add_argument("id")
        t.add_argument("--by", required=True)

    for name in ("halt", "unhalt"):
        sub.add_parser(name, help="kill switch").add_argument("--by", required=True)

    pe = sub.add_parser("payload-erase", help="PDPA erasure of one entry's payload")
    pe.add_argument("entry_id", type=int)
    pe.add_argument("--by", required=True)

    lv = sub.add_parser("log-verify", help="recompute the entry hash chains")
    lv.add_argument("--chain")
    return p


async def _run(args: argparse.Namespace) -> Any:
    if args.cmd == "key-new":  # needs no database
        return {"entry": f"{datetime.now(UTC):%Y%m%d}={new_seed()}", "how": "prepend to PACT_BOARD_KEYS; keep old entries"}
    pool = create_pool()
    await pool.open()
    try:
        if args.cmd == "migrate":
            applied = await migrate(pool)
            swept = await Admin(pool).sweep_closed_task_mandates()
            return {"applied": applied, "closed_task_mandates_revoked": [s["mandate_id"] for s in swept]}
        a = Admin(pool)
        match args.cmd:
            case "human-add":
                await a.add_human(args.id, args.name, args.role, by=args.by, email=args.email)
            case "project-add":
                await a.add_project(args.id, args.name, by=args.by, production=args.production)
            case "project-set":
                flag = {"true": True, "false": False, None: None}
                await a.set_project_flags(args.id, by=args.by, production=flag[args.production], frozen=flag[args.frozen])
            case "agent-register":
                return await a.register_agent(
                    args.id,
                    by=args.by,
                    client=args.client,
                    projects=args.projects,
                    scope=args.scope,
                    limits=args.limits,
                    delegations=args.delegations,
                    mandate_days=args.days,
                    token_days=args.days,
                    owner=args.owner,
                )
            case "agent-status":
                await a.set_agent_status(args.id, args.status, by=args.by)
            case "agent-prefs":
                return {"preferences": await a.set_agent_preferences(args.id, args.preferences, by=args.by)}
            case "token-issue":
                return {"token": await a.issue_token(args.agent, by=args.by, days=args.days)}
            case "agent-key-add":
                return await a.add_agent_key(args.agent, args.public_key, by=args.by)
            case "agent-key-revoke":
                return {"revoked": await a.revoke_agent_key(args.agent, args.kid, by=args.by)}
            case "trusted-root-add":
                return await a.add_trusted_root(args.public_key, human=args.human, by=args.by, label=args.label)
            case "trusted-root-revoke":
                return {"revoked": await a.revoke_trusted_root(args.principal, by=args.by)}
            case "trusted-root-list":
                return await a.list_trusted_roots()
            case "credential-import":
                return {"mandate_id": await a.import_credential(args.agent, args.format, args.credential, by=args.by)}
            case "token-revoke":
                return {"revoked": await a.revoke_tokens(args.agent, by=args.by)}
            case "mandate-issue":
                return {
                    "mandate_id": await a.issue_mandate(
                        args.holder,
                        by=args.by,
                        scope=args.scope,
                        limits=args.limits,
                        delegations=args.delegations,
                        days=args.days,
                    )
                }
            case "mandate-revoke":
                return await a.revoke_mandate(args.id, by=args.by)
            case "task-approve" | "task-reject":
                await a.approve_task(args.id, by=args.by, approve=args.cmd == "task-approve")
            case "task-resume":
                await a.resume_task(args.id, by=args.by)
            case "halt" | "unhalt":
                await a.set_halted(args.cmd == "halt", by=args.by)
            case "payload-erase":
                return {"erased": await a.erase_payload(args.entry_id, by=args.by)}
            case "log-verify":
                return await a.verify_log(args.chain)
        return {"ok": True}
    finally:
        await pool.close()


def main() -> None:
    args = _parser().parse_args()
    try:
        out = asyncio.run(_run(args))
    except PactError as err:
        print(json.dumps(err.to_dict(), ensure_ascii=False), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
