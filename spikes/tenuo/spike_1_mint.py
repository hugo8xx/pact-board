"""Spike 1: mint a PACT mandate chain as Tenuo warrants.

Mapping:
  scope "task.work@project:pact"  -> capability tool "task.work", constraint project=Exact("pact")
  limits {"cost_usd": 50}         -> constraint cost_usd=Range.max_value(50)   (per-call ceiling)
  expires_at                       -> ttl seconds (Tenuo only takes TTL, not absolute exp)
"""
import json
import time
from datetime import datetime, timedelta, timezone

import tenuo  # noqa: F401  (installs Python extensions on Warrant)
from tenuo import Exact, MonotonicityError, OneOf, Range, SigningKey, Warrant, Wildcard
from tenuo_core import Authorizer

def scope_to_caps(scopes: list[str], limits: dict[str, float]) -> dict:
    """Group 'action@project:P' -> {action: {project: Exact/OneOf, <limit>: Range}}."""
    by_action: dict[str, list[str]] = {}
    for s in scopes:
        action, proj = s.split("@project:")
        by_action.setdefault(action, []).append(proj)
    caps = {}
    for action, projs in by_action.items():
        c = {"project": Exact(projs[0]) if len(projs) == 1 else OneOf(projs)}
        for k, v in limits.items():
            c[k] = Range.max_value(v)
        caps[action] = c
    return caps

def ttl_from(expires_at: datetime) -> int:
    return max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))

board = SigningKey.generate()        # board key = issuer of root warrant
agent_a = SigningKey.generate()      # holder of root mandate
agent_b = SigningKey.generate()      # holder of delegated child

now = datetime.now(timezone.utc)
root_mandate = dict(
    scope=["task.work@project:pact", "task.read@project:pact"],
    limits={"cost_usd": 50},
    delegations_left=2,
    expires_at=now + timedelta(hours=8),
)
child_mandate = dict(
    scope=["task.work@project:pact"],
    limits={"cost_usd": 10},
    expires_at=now + timedelta(hours=1),
)

if __name__ == "__main__":
    b = Warrant.mint_builder()
    for tool, cons in scope_to_caps(root_mandate["scope"], root_mandate["limits"]).items():
        b = b.capability(tool, **cons)
    root = b.holder(agent_a.public_key).ttl(ttl_from(root_mandate["expires_at"])).mint(board)
    print("root id      :", root.id, "depth", root.depth, "max_depth", root.max_depth)
    print("root tools   :", root.tools)
    print("root caps    :", root.capabilities)
    print("root issuer==board:", root.issuer.to_bytes() == board.public_key.to_bytes())
    print("root holder==A    :", root.authorized_holder.to_bytes() == agent_a.public_key.to_bytes())
    print("root exp     :", root.expires_at(), "ttl", root.ttl_seconds())
    print("root size b64:", len(root.to_base64()))

    # --- child: who must sign? Try board first (board is NOT the parent holder) ---
    def child_builder():
        gb = root.grant_builder()
        for tool, cons in scope_to_caps(child_mandate["scope"], child_mandate["limits"]).items():
            gb = gb.capability(tool, **cons)
        return gb.holder(agent_b.public_key).ttl(ttl_from(child_mandate["expires_at"]))

    try:
        child_builder().grant(board)
        print("child signed by board: OK (unexpected)")
    except Exception as e:
        print("child signed by board -> ", type(e).__name__, ":", e)

    child = child_builder().grant(agent_a)
    print("child id     :", child.id, "depth", child.depth, "parent_hash", child.parent_hash)
    print("child caps   :", child.capabilities)
    print("child issuer==A:", child.issuer.to_bytes() == agent_a.public_key.to_bytes())

    auth = Authorizer(trusted_roots=[board.public_key])
    r = auth.verify_chain([root, child])
    print("verify_chain :", r.chain_length, r.leaf_depth)

    # --- Monotonicity checks ---
    def attempt(label, fn):
        try:
            fn()
            print(f"[{label}] ACCEPTED (!)")
        except MonotonicityError as e:
            print(f"[{label}] MonotonicityError: {e}")
        except Exception as e:
            print(f"[{label}] {type(e).__name__}: {e}")

    attempt("widen scope: new tool task.admin", lambda: root.grant_builder()
            .capability("task.admin", project=Exact("pact"), cost_usd=Range.max_value(10))
            .holder(agent_b.public_key).ttl(60).grant(agent_a))
    attempt("widen scope: other project", lambda: root.grant_builder()
            .capability("task.work", project=Exact("web"), cost_usd=Range.max_value(10))
            .holder(agent_b.public_key).ttl(60).grant(agent_a))
    attempt("widen scope: project Wildcard", lambda: root.grant_builder()
            .capability("task.work", project=Wildcard(), cost_usd=Range.max_value(10))
            .holder(agent_b.public_key).ttl(60).grant(agent_a))
    attempt("widen limit 50->100", lambda: root.grant_builder()
            .capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(100))
            .holder(agent_b.public_key).ttl(60).grant(agent_a))
    attempt("drop limit constraint", lambda: root.grant_builder()
            .capability("task.work", project=Exact("pact"))
            .holder(agent_b.public_key).ttl(60).grant(agent_a))
    attempt("widen TTL 8h->48h", lambda: root.grant_builder()
            .capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(10))
            .holder(agent_b.public_key).ttl(48 * 3600).grant(agent_a))

    # Is a child with longer TTL clamped instead of rejected?
    try:
        w = (root.grant_builder().capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(10))
             .holder(agent_b.public_key).ttl(48 * 3600).grant(agent_a))
        print("   long-ttl child exp", w.expires_at(), "vs root", root.expires_at())
    except Exception:
        pass

    # Wildcard action "task.*" -> is there tool-name glob support?
    try:
        wr = Warrant.mint_builder().capability("task.*", project=Exact("pact")).holder(agent_a.public_key).ttl(60).mint(board)
        a2 = Authorizer(trusted_roots=[board.public_key])
        sig = wr.sign(agent_a, "task.work", {"project": "pact"}, int(time.time()))
        a2.authorize_one(wr, "task.work", {"project": "pact"}, signature=bytes(sig))
        print("tool glob 'task.*' covers 'task.work': YES")
    except Exception as e:
        print("tool glob 'task.*' covers 'task.work': NO ->", type(e).__name__, str(e)[:160])

    # Persist for later spikes
    json.dump({
        "board_sk": board.secret_key_bytes().hex(),
        "a_sk": agent_a.secret_key_bytes().hex(),
        "b_sk": agent_b.secret_key_bytes().hex(),
        "root": root.to_base64(),
        "child": child.to_base64(),
    }, open("keys_and_warrants.json", "w"), indent=1)
    print("saved keys_and_warrants.json")
