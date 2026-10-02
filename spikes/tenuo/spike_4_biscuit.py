"""Spike 4: Biscuit (biscuit-python 0.4.0) — authority block + attenuation + authorizer + revocation ids."""
from datetime import datetime, timedelta, timezone

from biscuit_auth import (AuthorizerBuilder, Biscuit, BiscuitBuilder, BlockBuilder, KeyPair,
                          PublicKey, UnverifiedBiscuit)

board = KeyPair()
now = datetime.now(timezone.utc)
root_exp = now + timedelta(hours=8)
child_exp = now + timedelta(hours=1)

# Authority block = PACT root mandate. Holder identity is just a fact (no PoP in Biscuit core).
auth = BiscuitBuilder("""
  mandate({mid});
  holder({holder});
  right("pact", "task.work");
  right("pact", "task.read");
  limit("cost_usd", 50);
  check if time($t), $t <= {exp};
""", {"mid": "m-root-uuid", "holder": "agent-a", "exp": root_exp})
token = auth.build(board.private_key)

# Attenuation block = child mandate: restrict to task.work, cost <= 10, shorter expiry.
blk = BlockBuilder("""
  check if operation($proj, $op), ["task.work"].contains($op), $proj == "pact";
  check if cost($c), $c <= 10;
  check if time($t), $t <= {exp};
""", {"exp": child_exp})
child = token.append(blk)
b64 = child.to_base64()
print("blocks:", child.block_count(), "size b64:", len(b64))
print("revocation ids (root):", [r[:16] + "…" for r in token.revocation_ids])
print("revocation ids (child):", [r[:16] + "…" for r in child.revocation_ids])


def authorize(tok_b64, op, proj, cost, at=None):
    t = Biscuit.from_base64(tok_b64, board.public_key)
    a = AuthorizerBuilder("""
      operation({proj}, {op});
      cost({cost});
      time({now});
      allow if operation($p, $o), right($p, $o), limit("cost_usd", $max), cost($c), $c <= $max;
      deny if true;
    """, {"proj": proj, "op": op, "cost": cost, "now": at or datetime.now(timezone.utc)})
    a.add_token(t) if hasattr(a, "add_token") else None
    try:
        az = a.build(t)
        return f"ALLOW policy#{az.authorize()}"
    except Exception as e:
        return f"DENY {type(e).__name__}: {str(e)[:120]}"


print("child task.work pact cost 5 :", authorize(b64, "task.work", "pact", 5))
print("child task.read pact        :", authorize(b64, "task.read", "pact", 0))
print("child task.work web         :", authorize(b64, "task.work", "web", 5))
print("child cost 20               :", authorize(b64, "task.work", "pact", 20))
print("root  cost 20               :", authorize(token.to_base64(), "task.work", "pact", 20))
print("child at +2h (expired)      :", authorize(b64, "task.work", "pact", 5, now + timedelta(hours=2)))

# Can an attenuation block WIDEN? It can add facts, but facts from non-authority blocks
# are not trusted by the authorizer's default scope -> ignored.
widen = token.append(BlockBuilder('right("web", "task.admin");'))
print("appended right(web,task.admin):", authorize(widen.to_base64(), "task.admin", "web", 0))

# Wrong root key
other = KeyPair()
try:
    Biscuit.from_base64(b64, other.public_key)
    print("verify w/ wrong root: OK (!)")
except Exception as e:
    print("verify w/ wrong root:", type(e).__name__)

# Ingest-side inspection without the key
u = UnverifiedBiscuit.from_base64(b64)
print("unverified block_count:", u.block_count(), "root_key_id:", u.root_key_id())
print("authority block source:\n ", child.block_source(0).replace("\n", "\n  "))

# Revocation: Biscuit has no built-in revocation list; verifier must check revocation_ids itself.
revoked = set(token.revocation_ids[:1])  # revoke the authority block
hit = [r for r in child.revocation_ids if r in revoked]
print("child carries root's revocation id (cascade by set intersection):", bool(hit))
