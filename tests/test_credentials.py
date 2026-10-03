"""Phase 0 of credential adapters: Ed25519 signatures with key rotation, agent keys, the adapter interface."""

from collections.abc import Mapping, Sequence
from typing import Any

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from pact import credentials
from pact.credentials import Exported, Imported, TrustedRoot
from pact.crypto import canonical_json, hmac_hex, signing_key
from pact.db import fetchone, transaction
from pact.errors import PactError
from pact.keys import Keyring, b64url, b64url_decode, keyring, new_seed, public_bytes
from pact.mandates import Chain, get_mandate, payload_of, verify_chain

from .conftest import World
from .test_http import server_url  # noqa: F401 — fixture

pytestmark = pytest.mark.anyio


async def setup(w: World) -> None:
    await w.project("web")
    await w.agent("code-web", "code", ["web"])
    await w.agent("chat-boss", "chat", ["web"])


async def signature_of(w: World, mandate_id: str) -> str:
    async with transaction(w.pool) as conn:
        row = await fetchone(conn, "SELECT signature FROM mandates WHERE id = %s", (mandate_id,))
    assert row is not None
    return str(row["signature"])


async def verify(w: World, mandate_id: str, holder: str = "code-web") -> Chain:
    async with transaction(w.pool) as conn:
        return await verify_chain(conn, mandate_id, holder)


# ── signatures ────────────────────────────────────────────────────────────────


async def test_new_mandates_are_signed_with_ed25519_that_anyone_can_check(world: World) -> None:
    await setup(world)
    root = world.roots["code-web"]
    signature = await signature_of(world, root)
    scheme, kid, sig = signature.split(":")
    assert (scheme, kid) == ("ed25519", "derived-1")  # no PACT_BOARD_KEYS: one key derived from PACT_SIGNING_KEY

    # Only the published public key is needed to check it.
    [jwk] = keyring().jwks()["keys"]
    assert jwk["kid"] == kid and jwk["crv"] == "Ed25519" and "d" not in jwk
    async with transaction(world.pool) as conn:
        mandate = await get_mandate(conn, root)
    assert mandate is not None
    Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"])).verify(b64url_decode(sig), payload_of(mandate).encode())


async def test_rotating_keeps_old_mandates_valid_until_their_key_is_dropped(world: World, monkeypatch: Any) -> None:
    old, new = new_seed(), new_seed()
    monkeypatch.setenv("PACT_BOARD_KEYS", f"k1={old}")
    await setup(world)
    signed_by_k1 = world.roots["code-web"]
    assert (await signature_of(world, signed_by_k1)).startswith("ed25519:k1:")

    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new},k1={old}")  # rotate: k2 signs, k1 still verifies
    await verify(world, signed_by_k1)
    await world.agent("code-web-2", "code", ["web"])
    assert (await signature_of(world, world.roots["code-web-2"])).startswith("ed25519:k2:")
    assert [k["kid"] for k in keyring().jwks()["keys"]] == ["k2", "k1"]

    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new}")  # k1 retired
    with pytest.raises(PactError) as info:
        await verify(world, signed_by_k1)
    assert info.value.code == "chain_broken" and info.value.mandate_id == signed_by_k1
    await verify(world, world.roots["code-web-2"], "code-web-2")


async def test_mandates_signed_before_ed25519_keep_verifying(world: World) -> None:
    await setup(world)
    root = world.roots["code-web"]
    async with transaction(world.pool) as conn:
        mandate = await get_mandate(conn, root)
        assert mandate is not None
        legacy = hmac_hex(signing_key(), payload_of(mandate))
        await conn.execute("UPDATE mandates SET signature = %s WHERE id = %s", (legacy, root))
    await verify(world, root)

    async with transaction(world.pool) as conn:  # and tampering still breaks them
        await conn.execute("UPDATE mandates SET delegations_left = delegations_left + 1 WHERE id = %s", (root,))
    with pytest.raises(PactError) as info:
        await verify(world, root)
    assert info.value.code == "chain_broken"


async def test_a_signature_from_a_key_outside_the_keyring_is_refused(world: World) -> None:
    await setup(world)
    root = world.roots["code-web"]
    async with transaction(world.pool) as conn:
        mandate = await get_mandate(conn, root)
        assert mandate is not None
        forged = Keyring(keys={"derived-1": Ed25519PrivateKey.generate()}, active="derived-1").sign(payload_of(mandate))
        await conn.execute("UPDATE mandates SET signature = %s WHERE id = %s", (forged, root))
    with pytest.raises(PactError) as info:
        await verify(world, root)
    assert info.value.code == "chain_broken"


def test_bad_keyring_config_is_refused_at_startup(monkeypatch: Any) -> None:
    for spec in ("k1", "k1=short", f"a:b={new_seed()}", f"k1={new_seed()},k1={new_seed()}"):
        monkeypatch.setenv("PACT_BOARD_KEYS", spec)
        with pytest.raises(RuntimeError):
            keyring()


async def test_public_keys_are_published(world: World, server_url: str) -> None:  # noqa: F811
    async with httpx2.AsyncClient(timeout=10) as http:
        r = await http.get(f"{server_url}/.well-known/pact-keys.json")
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == "*"
    assert r.json() == keyring().jwks()


# ── agent keys ────────────────────────────────────────────────────────────────


def public_key() -> str:
    return b64url(public_bytes(Ed25519PrivateKey.generate().public_key()))


async def test_code_agents_register_keys_and_the_newest_live_one_counts(world: World) -> None:
    await setup(world)
    first = await world.admin.add_agent_key("code-web", public_key(), by="boss")
    second_key = public_key()
    second = await world.admin.add_agent_key("code-web", second_key, by="boss")
    async with transaction(world.pool) as conn:
        keys = await credentials.holder_keys(conn, ["code-web", "chat-boss"])
    assert keys == {"code-web": b64url_decode(second_key)}

    assert await world.admin.revoke_agent_key("code-web", second["kid"], by="boss") == 1
    async with transaction(world.pool) as conn:
        keys = await credentials.holder_keys(conn, ["code-web"])
    assert list(keys) == ["code-web"] and keys["code-web"] != b64url_decode(second_key)
    assert first["kid"] != second["kid"]


@pytest.mark.parametrize(
    ("agent", "key", "message"),
    [
        ("chat-boss", None, "do not hold keys"),
        ("code-web", "not-a-key", "Ed25519 public key"),
        ("code-web", b64url(b"\x01" * 31), "Ed25519 public key"),
        ("nobody", None, "does not exist"),
    ],
)
async def test_agent_keys_are_refused_when_they_cannot_be_right(world: World, agent: str, key: str | None, message: str) -> None:
    await setup(world)
    with pytest.raises(PactError) as info:
        await world.admin.add_agent_key(agent, key or public_key(), by="boss")
    assert message in info.value.message


async def test_one_public_key_belongs_to_one_agent(world: World) -> None:
    await setup(world)
    await world.agent("code-web-2", "code", ["web"])
    key = public_key()
    await world.admin.add_agent_key("code-web", key, by="boss")
    with pytest.raises(PactError) as info:
        await world.admin.add_agent_key("code-web-2", key, by="boss")
    assert "already registered for code-web" in info.value.message


# ── the adapter interface ─────────────────────────────────────────────────────


class EchoFormat:
    """A stand-in adapter: the chain as signed JSON. Real formats (Tenuo, Biscuit) plug in the same way."""

    name = "tenuo"  # a format name the schema accepts

    def mint(self, chain: Chain, *, keyring: Keyring, holder_keys: Mapping[str, bytes]) -> Exported:
        if chain.leaf.holder not in holder_keys:
            raise PactError("invalid_request", f"{chain.leaf.holder} has no public key")
        body = canonical_json({"links": chain.ids, "holder_key": b64url(holder_keys[chain.leaf.holder])})
        return Exported(format=self.name, external_id=f"echo_{chain.leaf.id}", credential=keyring.sign(body).encode())

    def ingest(self, credential: bytes, *, trusted_roots: Sequence[TrustedRoot]) -> Imported:
        raise PactError("chain_broken", "echo credentials are never trusted")

    def revocation_ids(self, credential: bytes) -> list[str]:
        return [credential.decode()[-8:]]

    def revocation_list(self, revoked: Sequence[str], *, keyring: Keyring, version: int) -> bytes:
        return keyring.sign(canonical_json({"revoked": list(revoked), "version": version})).encode()


async def test_an_adapter_exports_a_chain_and_the_ledger_records_it(world: World, monkeypatch: Any) -> None:
    await setup(world)
    monkeypatch.setattr(credentials, "_FORMATS", {})  # leave the real registry alone
    credentials.register(EchoFormat())
    fmt = credentials.get("tenuo")
    chain = await verify(world, world.roots["code-web"])
    async with transaction(world.pool) as conn:
        with pytest.raises(PactError) as info:  # no key yet: nothing to bind the credential to
            fmt.mint(chain, keyring=keyring(), holder_keys=await credentials.holder_keys(conn, ["code-web"]))
    assert info.value.code == "invalid_request"

    await world.admin.add_agent_key("code-web", public_key(), by="boss")
    async with transaction(world.pool) as conn:
        exported = fmt.mint(chain, keyring=keyring(), holder_keys=await credentials.holder_keys(conn, ["code-web"]))
        await credentials.store_export(conn, chain.leaf.id, exported)
        row = await fetchone(conn, "SELECT format, exported_as, external_id FROM mandates WHERE id = %s", (chain.leaf.id,))
    assert row == {"format": "pact", "exported_as": "tenuo", "external_id": exported.external_id}
    await verify(world, chain.leaf.id)  # exporting changes nothing the ledger checks


def test_an_unknown_format_is_refused_with_a_known_code() -> None:
    with pytest.raises(PactError) as info:
        credentials.get("ucan")
    assert info.value.code == "invalid_request" and "not available" in info.value.message
