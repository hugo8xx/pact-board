# Tenuo verifier demo

A tool server outside the board that accepts PACT credentials exported as Tenuo warrants. It
needs nothing from the board but two public URLs:

- `/.well-known/pact-keys.json`: the board's public keys, the only trusted roots;
- `/.well-known/pact-revocations/tenuo`: the board's signed revocation list, refetched every 30 s.
  If the list is more than 60 s old, every call is refused (fail closed).

```bash
uv run python examples/tenuo_verifier/server.py http://127.0.0.1:8787   # MCP at http://127.0.0.1:8790/mcp
```

It serves `task.work` and `task.read`, each taking `project`, `task_id` and, when the mandate sets
limits, each limit key (e.g. `cost_usd`) as a per-call ceiling.

## The agent side

With `PACT_EXPORT_FORMAT=tenuo` on the board and a key registered for the agent
(`pact-admin agent-key-add`), `pact_claim` returns:

```json
{ "ok": true, "task_id": "…", "status": "working",
  "credential": { "format": "tenuo", "external_id": "tnu_wrt_…", "warrant_stack": "<base64 stack>" } }
```

The agent signs each call with the private key it registered and sends the stack and signature in
`params._meta.tenuo`:

```python
import time
from tenuo import SigningKey, decode_warrant_stack_base64
from tenuo.meta import argument_json
from tenuo_core import sign_meta

key = SigningKey.from_bytes(seed)  # the agent's own Ed25519 seed
chain = decode_warrant_stack_base64(credential["warrant_stack"])
args = {"project": "web", "task_id": task_id}
tenuo = sign_meta(chain, key, "task.work", argument_json(args), int(time.time()))
await session.call_tool("task.work", args, meta={"tenuo": tenuo})
```

Sign `argument_json(args)`, Tenuo's canonical text of the arguments (an integral float such as
`5.0` is written `5`), not the dict itself, or the proof will not match. Every argument the tool
receives must be in the warrant: unknown arguments are refused, and so is a call that leaves out a
constrained one.

## Replays

Tenuo accepts a proof-of-possession signature for a short window (30 s × 5 by default). The demo
gives its verifier a `tenuo.nonce.NonceStore`, so each signature is accepted once and a replay
inside that window is refused. The store survives refreshes of the keys and revocation list. It is
in-process: run several workers and they need a shared backend (for example Redis), or a replay
can land on another worker. An agent that repeats a call must sign it again.
