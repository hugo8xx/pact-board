"""Spike 5: ingest a Tenuo warrant (stack) minted by a THIRD-PARTY key and map it to a PACT mandate row."""
import hashlib

import tenuo  # noqa: F401
from tenuo import (Exact, OneOf, Pattern, Range, SigningKey, Warrant, Wildcard,
                   decode_warrant_stack_base64, encode_warrant_stack)
from tenuo_core import Authorizer

# --- third party (e.g. a partner org's control plane) ---
partner = SigningKey.generate()
partner_agent = SigningKey.generate()
our_agent = SigningKey.generate()
p_root = (Warrant.mint_builder()
          .capability("task.work", project=OneOf(["pact", "web"]), cost_usd=Range.max_value(25))
          .capability("task.read", project=Exact("pact"))
          .holder(partner_agent.public_key).ttl(7200).mint(partner))
p_child = (p_root.grant_builder()
           .capability("task.work", project=Exact("pact"), cost_usd=Range.max_value(5))
           .holder(our_agent.public_key).ttl(3600).grant(partner_agent))
wire = encode_warrant_stack([p_root, p_child])          # what arrives at PACT
weird = Warrant.mint_builder().capability("fs.read", path=Pattern("/data/*")).ttl(60).mint(partner)


# --- PACT side ---
def constraint_to_projects(c):
    if isinstance(c, Exact):
        return [c.value]
    if isinstance(c, OneOf):
        return list(c.values)
    raise ValueError(f"unmappable project constraint {c!r}")


def to_mandate(w: Warrant) -> dict:
    scope, limits = [], {}
    for tool, cons in w.capabilities.items():
        for k, c in cons.items():
            if k == "project":
                scope += [f"{tool}@project:{p}" for p in constraint_to_projects(c)]
            elif isinstance(c, Range):
                limits[k] = min(limits.get(k, float("inf")), c.max)
            elif isinstance(c, Wildcard):
                pass
            else:
                raise ValueError(f"unmappable constraint {tool}.{k}={c!r}")
        if "project" not in cons:
            raise ValueError(f"tool {tool} has no project constraint -> would be cross-project")
    return {
        "external_id": w.id,
        "issuer_pubkey": w.issuer.to_bytes().hex(),
        "holder_pubkey": w.authorized_holder.to_bytes().hex(),
        "scope": sorted(scope),
        "limits": limits,
        "expires_at": w.expires_at(),
        "depth": w.depth,
        "parent_hash": w.parent_hash,
        "terminal": w.is_terminal(),
        "warrant_type": str(w.warrant_type),
    }


def ingest(wire_b64: str, trusted_roots):
    chain = decode_warrant_stack_base64(wire_b64)
    Authorizer(trusted_roots=trusted_roots).verify_chain(chain)  # sig + linkage + monotonicity + expiry
    return [to_mandate(w) for w in chain]


if __name__ == "__main__":
    # untrusted
    try:
        ingest(wire, [SigningKey.generate().public_key])
        print("untrusted root: ACCEPTED (!)")
    except Exception as e:
        print("untrusted root:", type(e).__name__, e)

    rows = ingest(wire, [partner.public_key])
    for r in rows:
        print({k: (v[:16] + "…" if isinstance(v, str) and len(v) > 40 else v) for k, v in r.items()})

    # parent linkage: what is parent_hash a hash of?
    cands = {"sha256(payload_bytes)": hashlib.sha256(bytes(p_root.payload_bytes)).hexdigest(),
             "sha256(to_bytes)": hashlib.sha256(p_root.to_bytes() if isinstance(p_root.to_bytes(), bytes) else bytes(p_root.to_bytes())).hexdigest()}
    for name, h in cands.items():
        print(f"child.parent_hash == {name}: {h == p_child.parent_hash}")
    print("parent id appears in child? ", p_root.id in str(p_child.to_base64()), "(id not carried; link is hash)")

    # id stability across re-serialisation
    again = Warrant.from_base64(p_child.to_base64())
    print("id stable after round-trip:", again.id == p_child.id)
    print("leaf-only wire, verify_chain:", end=" ")
    try:
        Authorizer(trusted_roots=[partner.public_key]).verify_chain([p_child])
        print("OK (!)")
    except Exception as e:
        print(type(e).__name__, e)
    try:
        to_mandate(weird)
    except ValueError as e:
        print("non-PACT-shaped warrant:", e)
    print("agent_id / session_id fields:", p_child.agent_id(), p_child.session_id)
