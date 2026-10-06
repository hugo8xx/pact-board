"""An organization's own settings: its name and where its Slack notifications go."""

from typing import Any

import httpx
import pytest

from pact.db import fetchall, fetchone, transaction
from pact.notify import SlackSender, enqueue
from pact.oauth import ResourceSettings

from .conftest import World
from .oauth_fixtures import Issuer
from .test_admin_api import admin_token, api, people
from .test_tenancy import two_organizations

pytestmark = pytest.mark.anyio

HOOK = "https://hooks.slack.com/services/T000/B000/" + "x" * 8


async def test_owners_rename_and_set_the_webhook_which_is_never_shown_again(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, settings = board
    await people(world)
    boss, vic = admin_token(issuer, settings), admin_token(issuer, settings, who="vic")
    org = (await api(url, "GET", "/org", vic)).json()
    assert org["id"] == "default" and org["slack"] == {"configured": False, "hint": None}

    r = await api(url, "PUT", "/org", boss, {"name": " Acme ", "slack_webhook_url": HOOK})
    assert r.status_code == 200 and r.json()["name"] == "Acme"
    assert r.json()["slack"] == {"configured": True, "hint": "…xxxx"}
    for path in ("/org", "/entries", "/me"):
        assert "hooks.slack.com" not in (await api(url, "GET", path, boss)).text, path

    refused = await api(url, "PUT", "/org", vic, {"name": "Mine"})
    assert refused.status_code == 403
    for bad in ("http://hooks.slack.com/services/x", "https://evil.example/services/x", "https://hooks.slack.com.evil/x",
                "https://hooks.slack.com/services/x?y=1", "https://hooks.slack.com/services/"):  # fmt: skip
        r = await api(url, "PUT", "/org", boss, {"slack_webhook_url": bad})
        assert r.status_code == 400, bad
    assert (await api(url, "PUT", "/org", boss, {"name": ""})).status_code == 400

    r = await api(url, "PUT", "/org", boss, {"slack_webhook_url": None})
    assert r.json()["slack"]["configured"] is False and r.json()["name"] == "Acme"
    async with transaction(world.pool) as conn:
        logged = await fetchall(conn, "SELECT action FROM entries WHERE action = 'admin.org.update'")
    assert len(logged) == 2


def recorder() -> tuple[httpx.AsyncClient, list[str]]:
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(200, text="ok")

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), sent


async def notify(world: World, project: str) -> None:
    async with transaction(world.pool) as conn:
        await enqueue(conn, "deferred", project_id=project, task_id=None, agent_id=None, title="t")


async def test_each_organization_hears_on_its_own_webhook_and_one_without_hears_nothing(world: World) -> None:
    await two_organizations(world)
    client, sent = recorder()
    sender = SlackSender(world.pool, "https://hooks.slack.test/env", client=client)
    await notify(world, "web")
    await notify(world, "acme")
    assert await sender.send_pending() == 1
    assert sent == ["https://hooks.slack.test/env"]  # the env webhook serves only the default organization
    async with transaction(world.pool) as conn:
        rows: list[Any] = await fetchall(conn, "SELECT org_id, sent_at, attempts, last_error FROM notifications ORDER BY id")
    assert [r["org_id"] for r in rows] == ["default", "rival"]
    assert rows[1]["sent_at"] is None and "no Slack webhook" in rows[1]["last_error"]

    await world.admin.update_org(by="rex", slack_webhook_url=HOOK)
    await notify(world, "acme")
    assert await sender.send_pending() == 1 and sent[-1] == HOOK  # the old one stays set aside
    await world.admin.update_org(by="boss", slack_webhook_url=HOOK.replace("x" * 8, "y" * 8))
    await notify(world, "web")
    assert await sender.send_pending() == 1 and sent[-1].endswith("y" * 8)  # its own beats the env one
    async with transaction(world.pool) as conn:
        assert await fetchone(conn, "SELECT count(*) AS n FROM notifications WHERE sent_at IS NULL AND attempts < 5") == {"n": 0}
    await client.aclose()
