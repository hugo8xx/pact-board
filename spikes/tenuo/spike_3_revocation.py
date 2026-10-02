"""Spike 3: SignedRevocationList — does revoking an ancestor reject descendants?"""
import time

import tenuo  # noqa: F401
from tenuo import Exact, SigningKey, SrlBuilder, SignedRevocationList, Warrant
from tenuo_core import Authorizer

board, a, b, c, rogue = (SigningKey.generate() for _ in range(5))
root = Warrant.mint_builder().capability("task.work", project=Exact("pact")).holder(a.public_key).ttl(3600).mint(board)
mid = root.grant_builder().capability("task.work", project=Exact("pact")).holder(b.public_key).ttl(1800).grant(a)
leaf = mid.grant_builder().capability("task.work", project=Exact("pact")).holder(c.public_key).ttl(600).grant(b)
sibling = root.grant_builder().capability("task.work", project=Exact("pact")).holder(c.public_key).ttl(600).grant(a)
ARGS = {"project": "pact"}
print("ids root/mid/leaf/sibling:", root.id, mid.id, leaf.id, sibling.id)


def check(auth, label, chain, key):
    sig = chain[-1].sign(key, "task.work", ARGS, int(time.time()))
    try:
        auth.check_chain(chain, "task.work", ARGS, signature=bytes(sig))
        print(f"   {label:32s} ALLOWED")
    except Exception as e:
        print(f"   {label:32s} DENIED  {type(e).__name__}: {e}")


def run(label, srl):
    auth = Authorizer(trusted_roots=[board.public_key])
    try:
        auth.set_revocation_list(srl)
    except Exception as e:
        print(f"== {label}: set_revocation_list -> {type(e).__name__}: {e}")
        return
    print(f"== {label} (srl v{srl.version}, revoked={srl.revoked_ids})")
    check(auth, "root (held by A)", [root], a)
    check(auth, "mid (held by B)", [root, mid], b)
    check(auth, "leaf (held by C)", [root, mid, leaf], c)
    check(auth, "sibling (held by C)", [root, sibling], c)


def srl(ids, version, key=board):
    bld = SrlBuilder()
    for i in ids:
        bld = bld.revoke(i)
    return bld.version(version).build(key)


run("empty SRL", srl([], 1))
run("revoke ROOT", srl([root.id], 2))
run("revoke MID", srl([mid.id], 3))
run("revoke LEAF only", srl([leaf.id], 4))
run("SRL signed by untrusted key", srl([root.id], 5, rogue))

# Version monotonicity: install v5 then try to roll back to v1
auth = Authorizer(trusted_roots=[board.public_key])
auth.set_revocation_list(srl([leaf.id], 5))
try:
    auth.set_revocation_list(srl([], 1))
    print("rollback v5 -> v1: ACCEPTED (no anti-rollback in Authorizer)")
except Exception as e:
    print("rollback v5 -> v1:", type(e).__name__, e)

# SRL serialisation / standalone verify for publishing
s = srl([root.id, mid.id], 9)
blob = s.to_bytes()
s2 = SignedRevocationList.from_bytes(blob)
s2.verify(board.public_key)
print("SRL bytes:", len(blob), "issuer==board:", s2.issuer.to_bytes() == board.public_key.to_bytes(),
      "issued_at:", s2.issued_at, "is_revoked(mid):", s2.is_revoked(mid.id))
try:
    s2.verify(rogue.public_key)
    print("verify with rogue key: OK (!)")
except Exception as e:
    print("verify with rogue key:", type(e).__name__)

# What about a verifier that has NO SRL installed? (fail-open check)
check(Authorizer(trusted_roots=[board.public_key]), "no SRL installed, leaf", [root, mid, leaf], c)

# Holder-signed RevocationRequest (for 'publish_revocations' via a control plane)
from tenuo import RevocationRequest
rr = RevocationRequest.new(warrant_id=mid.id, reason="mandate revoked in PACT ledger", requestor_keypair=board)
print("RevocationRequest bytes:", len(rr.to_bytes()), "sig ok:", rr.verify_signature() if callable(getattr(rr, 'verify_signature', None)) else '?')

# Same check through the MCP server-side verifier (what spike_2 uses)
import base64
from tenuo import encode_warrant_stack
from tenuo.mcp import MCPVerifier
auth = Authorizer(trusted_roots=[board.public_key])
auth.set_revocation_list(srl([root.id], 20))
v = MCPVerifier(authorizer=auth)
sig = leaf.sign(c, "task.work", ARGS, int(time.time()))
meta = {"tenuo": {"warrant": encode_warrant_stack([root, mid, leaf]), "signature": base64.b64encode(bytes(sig)).decode()}}
r = v.verify("task.work", dict(ARGS), meta=meta)
print("MCPVerifier leaf with ROOT revoked:", r.allowed, r.error_type, r.denial_reason)
