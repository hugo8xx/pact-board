"""Spike 1c: can the BOARD sign every link (intermediate holders = board key), leaf held by agent?
This avoids custodying agent private keys while keeping chain + cascade revocation."""
import time
import tenuo  # noqa
from tenuo import Exact, Range, SigningKey, SrlBuilder, Warrant
from tenuo_core import Authorizer
board, agent_b = SigningKey.generate(), SigningKey.generate()
caps = dict(project=Exact("pact"), cost_usd=Range.max_value(50))
root = Warrant.mint_builder().capability("task.work", **caps).holder(board.public_key).ttl(3600).mint(board)
mid = root.grant_builder().capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(20)).holder(board.public_key).ttl(1800).grant(board)
leaf = mid.grant_builder().capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(10)).holder(agent_b.public_key).ttl(600).grant(board)
args = {"project": "pact", "cost_usd": 5.0}
au = Authorizer(trusted_roots=[board.public_key])
r = au.check_chain([root, mid, leaf], "task.work", args, signature=bytes(leaf.sign(agent_b, "task.work", args, int(time.time()))))
print("board-signed chain, agent PoP on leaf: OK, length", r.chain_length)
au.set_revocation_list(SrlBuilder().revoke(mid.id).version(1).build(board))
try:
    au.check_chain([root, mid, leaf], "task.work", args, signature=bytes(leaf.sign(agent_b, "task.work", args, int(time.time()))))
    print("after revoking mid: ALLOWED (!)")
except Exception as e:
    print("after revoking mid:", type(e).__name__)
