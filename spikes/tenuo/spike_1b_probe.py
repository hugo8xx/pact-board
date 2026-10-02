"""Spike 1b: PoP requirement, closed-world args, terminal (delegations_left=0), holder default."""
import time
import tenuo  # noqa
from tenuo import SigningKey, Warrant, Exact, Range
from tenuo_core import Authorizer
k=SigningKey.generate(); a=SigningKey.generate()
w=Warrant.issue(keypair=k, capabilities={"t":{"project":Exact("p")}}, ttl_seconds=60, holder=a.public_key)
au=Authorizer(trusted_roots=[k.public_key])
try: au.authorize_one(w,"t",{"project":"p"}); print("no-PoP: ALLOWED")
except Exception as e: print("no-PoP:", type(e).__name__, e)
sig=w.sign(a,"t",{"project":"p"},int(time.time()))
print("PoP by holder:", au.authorize_one(w,"t",{"project":"p"},signature=bytes(sig)).chain_length, "len", len(bytes(sig)))
sig2=w.sign(k,"t",{"project":"p"},int(time.time()))
try: au.authorize_one(w,"t",{"project":"p"},signature=bytes(sig2)); print("PoP by issuer(board) key: ALLOWED")
except Exception as e: print("PoP by issuer(board) key:", type(e).__name__, e)
w2=Warrant.issue(keypair=k, capabilities={"t":{}}, ttl_seconds=60)
print("no holder given -> holder==issuer?", w2.authorized_holder.to_bytes()==k.public_key.to_bytes())
w3=Warrant.issue(keypair=k, capabilities={"t":{"project":Exact("p"),"cost_usd":Range.max_value(10)}}, ttl_seconds=60, holder=a.public_key)
for args in [{"project":"p"},{"project":"p","cost_usd":5},{"project":"p","cost_usd":11},{"project":"p","cost_usd":5,"extra":1}]:
    s=w3.sign(a,"t",args,int(time.time()))
    try: au.authorize_one(w3,"t",args,signature=bytes(s)); print(args,"ALLOW")
    except Exception as e: print(args,"DENY",type(e).__name__, str(e)[:100])
c=w.grant_builder().capability("t",project=Exact("p")).holder(k.public_key).ttl(30).terminal().grant(a)
print("terminal child is_terminal:", c.is_terminal())
try: c.grant_builder().capability("t",project=Exact("p")).holder(a.public_key).ttl(10).grant(k); print("grandchild of terminal accepted")
except Exception as e: print("grandchild of terminal:", type(e).__name__, e)
# replay: same signature reused later within window?
time.sleep(2)
try: au.authorize_one(w,"t",{"project":"p"},signature=bytes(sig)); print("replayed PoP after 2s: ALLOWED (needs NonceStore)")
except Exception as e: print("replayed PoP:", type(e).__name__, e)
print("pop window:", au.pop_window_config())
