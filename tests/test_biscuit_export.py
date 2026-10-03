"""Biscuit-specific export behaviour: token shape, Datalog semantics, the board-signed revocation document.

What every format must do lives in test_credential_conformance.py."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from biscuit_auth import BlockBuilder, UnverifiedBiscuit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pact.credentials.biscuit import (
    BiscuitFormat,
    authorize,
    authorizer_for,
    micros,
    parse_token,
    root_key_id,
    trusted_keys,
    verify_revocation_list,
)
from pact.errors import PactError
from pact.keys import b64url, keyring, new_seed, public_bytes
from pact.mandates import Chain, Mandate

NOW = datetime.now(UTC)
AGENT = Ed25519PrivateKey.generate()
AGENT_KEY = public_bytes(AGENT.public_key())


def link(mid: str, scope: list[str], limits: dict[str, float], holder: str, *, days: float = 3) -> Mandate:
    return Mandate(
        id=mid,
        parent_id=None,
        issuer_kind="human",
        issuer="boss",
        holder=holder,
        scope=scope,
        limits=limits,
        delegations_left=1,
        depth=0,
        expires_at=NOW + timedelta(days=days),
        revoked_at=None,
        signature="",
    )


WEB = ["task.work@project:web", "task.read@project:web"]


def mint(*links: Mandate) -> Any:
    return BiscuitFormat().mint(Chain(list(links)), keyring=keyring(), holder_keys={links[-1].holder: AGENT_KEY})


def call(token: bytes | str, tool: str = "task.work", now: datetime | None = None, **args: Any) -> bool:
    return authorize(token, tool, {"project": "web", "task_id": "T-1", **args}, trusted=trusted_keys(keyring()), now=now)


def test_one_block_per_ledger_link_signed_by_the_board() -> None:
    ex = mint(link("root", WEB, {"cost_usd": 50}, "chat-boss"), link("child", ["task.work@project:web"], {}, "code-web", days=1))
    token = parse_token(ex.credential, trusted_keys(keyring()))
    assert token.block_count() == 2
    ids = list(token.revocation_ids)
    assert ex.links == (("root", ids[0]), ("child", ids[1])) and ex.external_id == ids[1]
    board = public_bytes(keyring().keys[keyring().active].public_key())
    assert UnverifiedBiscuit.from_base64(ex.credential.decode()).root_key_id() == root_key_id(board)

    authority, last = token.block_source(0), token.block_source(1)
    assert 'mandate("root")' in authority and 'right("web", "task.work")' in authority
    assert 'mandate("child")' in last and f'holder("{b64url(AGENT_KEY)}")' in last
    assert "holder(" not in authority and "right(" not in last  # only the authority block grants
    # The child's own scope narrows; its inherited ceiling is written into its block.
    assert call(ex.credential, cost_usd=5.0)
    assert not call(ex.credential, "task.read", cost_usd=5.0)
    assert not call(ex.credential, cost_usd=51.0)


def test_only_the_last_block_is_capped_at_the_export_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACT_EXPORT_TTL_HOURS", "2")
    ex = mint(link("root", WEB, {}, "chat-boss", days=30), link("child", WEB, {}, "code-web", days=10))
    assert call(ex.credential)
    assert call(ex.credential, now=NOW + timedelta(hours=1))
    assert not call(ex.credential, now=NOW + timedelta(hours=3))  # the leaf's cap, not the link's 10 days
    token = parse_token(ex.credential, trusted_keys(keyring()))
    assert str((NOW + timedelta(days=30)).year) in token.block_source(0)


def test_fractional_limits_are_compared_in_millionths() -> None:
    ex = mint(link("root", WEB, {"cost_usd": 2.5}, "code-web"))
    assert micros(2.5) == 2_500_000
    assert call(ex.credential, cost_usd=2.5)
    assert call(ex.credential, cost_usd=2)  # integers are numbers too
    assert not call(ex.credential, cost_usd=2.500001)
    assert not call(ex.credential, cost_usd="2")  # a string is not a number


def test_a_widening_block_appended_by_the_holder_has_no_effect() -> None:
    """Biscuit does not reject it; an authorizer just never trusts facts outside the authority block."""
    ex = mint(link("root", ["task.work@project:web"], {}, "code-web"))
    token = parse_token(ex.credential, trusted_keys(keyring()))
    widened = token.append(BlockBuilder('right("web", "task.admin"); right("api", "task.work");')).to_base64()
    assert not call(widened, "task.admin")
    assert not authorize(widened, "task.work", {"project": "api", "task_id": "T"}, trusted=trusted_keys(keyring()))
    assert call(widened)  # still what the board granted, no more


def test_a_childs_revocation_ids_contain_its_parents() -> None:
    ex = mint(link("root", WEB, {}, "chat-boss"), link("child", WEB, {}, "code-web"))
    ids = BiscuitFormat().revocation_ids(ex.credential)
    assert ids == [x for _, x in ex.links]
    for revoked in ids:
        assert not authorize(ex.credential, "task.work", {"project": "web"}, trusted=trusted_keys(keyring()), revoked=[revoked])


def test_the_authorizer_needs_a_project_but_not_a_task_id() -> None:
    ex = mint(link("root", WEB, {}, "code-web"))
    token = parse_token(ex.credential, trusted_keys(keyring()))
    assert authorizer_for("task.work", {"project": "web"}).build(token).authorize() == 0
    assert not authorize(ex.credential, "task.work", {"task_id": "T"}, trusted=trusted_keys(keyring()))


def test_rotation_picks_the_signing_key_by_root_key_id(monkeypatch: pytest.MonkeyPatch) -> None:
    old, new = new_seed(), new_seed()
    monkeypatch.setenv("PACT_BOARD_KEYS", f"k1={old}")
    ex = mint(link("root", WEB, {}, "code-web"))
    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new},k1={old}")
    assert parse_token(ex.credential, trusted_keys(keyring())).block_count() == 1
    monkeypatch.setenv("PACT_BOARD_KEYS", f"k2={new}")
    with pytest.raises(ValueError, match="trusted board key"):
        parse_token(ex.credential, trusted_keys(keyring()))


def test_minting_refuses_with_the_codes_agents_know() -> None:
    chain = Chain([link("root", ["task.*@project:web"], {}, "code-web")])
    with pytest.raises(PactError) as info:
        BiscuitFormat().mint(chain, keyring=keyring(), holder_keys={})
    assert info.value.code == "invalid_request" and "no registered public key" in info.value.message
    with pytest.raises(PactError) as info:
        BiscuitFormat().mint(chain, keyring=keyring(), holder_keys={"code-web": AGENT_KEY})
    assert info.value.code == "invalid_request" and "cannot be exported as Biscuit" in info.value.message
    with pytest.raises(PactError) as info:
        BiscuitFormat().ingest(b"", trusted_roots=[])
    assert info.value.code == "invalid_request" and "not supported yet" in info.value.message


def test_the_revocation_document_is_canonical_signed_json() -> None:
    doc = BiscuitFormat().revocation_list(["bb", "aa"], keyring=keyring(), version=7)
    outer = json.loads(doc)
    assert set(outer) == {"payload", "signature"} and outer["signature"].startswith(f"ed25519:{keyring().active}:")
    body = verify_revocation_list(doc, keyring().jwks())
    assert body["format"] == "biscuit" and body["version"] == 7 and body["revoked"] == ["bb", "aa"]
    assert outer["payload"] == json.dumps(body, sort_keys=True, separators=(",", ":"))
    assert datetime.fromisoformat(body["issued_at"]) <= datetime.now(UTC)

    tampered = json.dumps({**outer, "payload": outer["payload"].replace('"aa"', '"cc"')}).encode()
    with pytest.raises(ValueError, match="does not verify"):
        verify_revocation_list(tampered, keyring().jwks())
    with pytest.raises(ValueError, match="unknown key"):
        verify_revocation_list(doc, {"keys": []})
