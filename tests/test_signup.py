"""Signing up: a stranger with a verified sign-in starts their own organization."""

import asyncio
from typing import Any

import pytest

from pact.db import fetchall, fetchone, transaction
from pact.oauth import ResourceSettings

from .conftest import World
from .oauth_fixtures import Issuer
from .test_admin_api import api

pytestmark = pytest.mark.anyio

FORM = {"org_name": "Acme Robotics", "display_name": "Ann", "accept_terms": True, "terms_version": "draft-1"}


def token(issuer: Issuer, settings: ResourceSettings, who: str, email: str | None = None) -> str:
    return issuer.token(f"sub-{who}", settings.admin_audience, email=email or f"{who}@example.com", amr=["pwd", "otp", "mfa"])


@pytest.fixture
def open_signup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACT_SIGNUP_ENABLED", "true")


async def test_a_stranger_is_told_to_sign_up_and_cannot_until_it_opens(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, settings = board
    ann = token(issuer, settings, "ann")
    r = await api(url, "GET", "/me", ann)
    assert r.status_code == 403 and r.json()["error"] == "not_registered"
    monkeypatch.delenv("PACT_SIGNUP_ENABLED", raising=False)
    r = await api(url, "POST", "/signup", ann, FORM)
    assert r.status_code == 403 and r.json()["error"] == "signup_closed"
    async with transaction(world.pool) as conn:
        assert (await fetchone(conn, "SELECT count(*) AS n FROM orgs"))["n"] == 1  # type: ignore[index]


@pytest.mark.usefixtures("open_signup")
async def test_signing_up_makes_an_organization_with_its_own_owner_roles_rules_and_log(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    ann = token(issuer, settings, "ann")
    r = await api(url, "POST", "/signup", ann, FORM)
    assert r.status_code == 201, r.text
    out = r.json()
    org = out["org"]["id"]
    assert org.startswith("acme-robotics-") and out["org"]["name"] == "Acme Robotics" and out["invited"] is False

    me = (await api(url, "GET", "/me", ann)).json()
    assert me["role"] == "owner" and me["name"] == "Ann" and me["org"]["id"] == org
    roles = {x["id"] for x in (await api(url, "GET", "/roles", ann)).json()}
    assert {"chat", "code", "runner"} <= roles
    assert (await api(url, "GET", "/projects", ann)).json() == []
    assert (await api(url, "GET", "/humans", ann)).json()[0]["id"] == out["human"]
    chains = (await api(url, "GET", "/log/verify", ann)).json()
    assert [(c["chain_key"], c["ok"]) for c in chains] == [(f"_system:{org}", True)]

    async with transaction(world.pool) as conn:
        row = await fetchone(conn, "SELECT terms_version, terms_accepted_at, created_by FROM orgs WHERE id = %s", (org,))
        rules = await fetchall(conn, "SELECT action FROM approval_actions WHERE org_id = %s ORDER BY action", (org,))
        entry = await fetchone(conn, "SELECT action, org_id FROM entries WHERE chain_key = %s", (f"_system:{org}",))
    assert row and row["terms_version"] == "draft-1" and row["terms_accepted_at"] and row["created_by"] == out["human"]
    assert [x["action"] for x in rules] == ["customer.message", "deploy.*", "finance.*"]
    assert entry and entry["action"] == "org.created" and entry["org_id"] == org

    # The new owner can start working, and sees nothing of the first organization.
    assert (await api(url, "POST", "/projects", ann, {"id": "acme-web", "name": "Web"})).status_code == 200
    assert "boss" not in (await api(url, "GET", "/humans", ann)).text
    again = await api(url, "POST", "/signup", ann, FORM)
    assert again.status_code == 409 and again.json()["error"] == "already_registered"


@pytest.mark.usefixtures("open_signup")
async def test_two_clicks_at_once_make_one_organization(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    ann = token(issuer, settings, "ann")
    results = await asyncio.gather(*(api(url, "POST", "/signup", ann, FORM) for _ in range(4)))
    assert sorted(r.status_code for r in results) == [201, 409, 409, 409]
    async with transaction(world.pool) as conn:
        assert (await fetchone(conn, "SELECT count(*) AS n FROM orgs WHERE id <> 'default'"))["n"] == 1  # type: ignore[index]


@pytest.mark.usefixtures("open_signup")
async def test_someone_invited_joins_the_organization_that_invited_them(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await world.admin.add_human("vic", "Vic", "viewer", by="boss", email="vic@example.com")
    vic = token(issuer, settings, "vic")
    r = await api(url, "POST", "/signup", vic, FORM)
    assert r.status_code == 409 and r.json()["error"] == "already_registered"
    assert (await api(url, "GET", "/me", vic)).json()["org"]["id"] == "default"
    async with transaction(world.pool) as conn:
        assert (await fetchone(conn, "SELECT count(*) AS n FROM orgs"))["n"] == 1  # type: ignore[index]


@pytest.mark.usefixtures("open_signup")
async def test_a_disabled_person_is_told_so_and_cannot_sign_up_again(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await world.admin.add_human("vic", "Vic", "viewer", by="boss", email="vic@example.com")
    vic = token(issuer, settings, "vic")
    assert (await api(url, "GET", "/me", vic)).status_code == 200
    await world.admin.update_human("vic", by="boss", disabled=True)
    for method, path in (("GET", "/me"), ("POST", "/signup")):
        r = await api(url, method, path, vic, FORM)
        assert r.status_code == 403 and r.json()["error"] == "account_disabled", path

    # Disabled before ever signing in: the invitation's email is still refused.
    await world.admin.add_human("dee", "Dee", "viewer", by="boss", email="dee@example.com")
    await world.admin.update_human("dee", by="boss", disabled=True)
    r = await api(url, "POST", "/signup", token(issuer, settings, "dee"), FORM)
    assert r.status_code == 403 and r.json()["error"] == "account_disabled"


@pytest.mark.usefixtures("open_signup")
@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"accept_terms": False}, "accept the terms"),
        ({"org_name": "   "}, "organization name"),
        ({"display_name": "x" * 81}, "your name"),
        ({"terms_version": None}, "required"),
    ],
)
async def test_a_bad_form_is_refused(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer, change: dict[str, Any], expected: str
) -> None:
    url, settings = board
    r = await api(url, "POST", "/signup", token(issuer, settings, "ann"), {**FORM, **change})
    assert r.status_code == 400 and expected in r.json()["message"]


@pytest.mark.usefixtures("open_signup")
async def test_names_with_no_latin_letters_and_taken_person_ids_still_work(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await world.admin.add_human("ann", "Ann (first org)", "viewer", by="boss")
    r = await api(
        url, "POST", "/signup", token(issuer, settings, "ann2", email="ann@corp.example"), {**FORM, "org_name": "บริษัท ทดสอบ"}
    )
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["org"]["id"].startswith("org-") and out["org"]["name"] == "บริษัท ทดสอบ"
    assert out["human"].startswith("ann-")


@pytest.mark.usefixtures("open_signup")
async def test_a_flood_of_sign_ups_trips_the_breaker(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, settings = board
    monkeypatch.setenv("PACT_SIGNUP_MAX_PER_HOUR", "1")
    assert (await api(url, "POST", "/signup", token(issuer, settings, "ann"), FORM)).status_code == 201
    r = await api(url, "POST", "/signup", token(issuer, settings, "bob"), FORM)
    assert r.status_code == 429 and r.json()["error"] == "signup_busy"


@pytest.mark.usefixtures("open_signup")
async def test_a_sign_in_without_a_verified_email_cannot_sign_up(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    bare = issuer.token("sub-x", settings.admin_audience, amr=["pwd", "otp", "mfa"])
    r = await api(url, "POST", "/signup", bare, FORM)
    assert r.status_code == 400 and "verified email" in r.json()["message"]
    assert (await api(url, "POST", "/signup", None, FORM)).status_code == 401
