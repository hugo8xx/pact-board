"""The Admin API as its own service, beside the board on the same database."""

from collections.abc import Iterator

import httpx2
import pytest

from pact.admin_server import create_admin_server
from pact.db import create_pool, transaction
from pact.errors import PactError
from pact.oauth import ResourceSettings

from .conftest import World
from .oauth_fixtures import Issuer, _serve

pytestmark = pytest.mark.anyio


@pytest.fixture
def admin_service(issuer: Issuer) -> Iterator[tuple[str, ResourceSettings]]:
    # Its own public URL, but the board's audience: the same tokens work wherever the API runs.
    settings = ResourceSettings(
        public_url="http://admin.test", issuer=issuer.url, admin_audience_override="http://mcp.test/admin"
    )
    url, server, thread = _serve(create_admin_server(create_pool(max_size=5), settings))
    yield url, settings
    server.should_exit = True
    thread.join(timeout=5)


async def boss_with_email(world: World) -> None:
    async with transaction(world.pool) as conn:
        await conn.execute("UPDATE humans SET email = 'boss@example.com' WHERE id = 'boss'")


async def test_admin_service_serves_only_the_admin_api(
    world: World, admin_service: tuple[str, ResourceSettings], issuer: Issuer
) -> None:
    url, _ = admin_service
    await boss_with_email(world)
    await world.project("web")
    await world.agent("code-web", "code", ["web"])
    token = issuer.token("sub-boss", "http://mcp.test/admin", email="boss@example.com", amr=["pwd", "otp", "mfa"])
    async with httpx2.AsyncClient(timeout=10) as http:
        auth = {"Authorization": f"Bearer {token}"}
        assert (await http.get(f"{url}/healthz")).status_code == 200
        assert (await http.get(f"{url}/admin/api/me", headers=auth)).json()["role"] == "owner"
        assert (await http.post(f"{url}/mcp/a/code-web", json={})).status_code == 404
        agent_token = {"Authorization": f"Bearer {world.tokens['code-web']}"}
        assert (await http.get(f"{url}/admin/api/me", headers=agent_token)).status_code == 401

        # The kill switch pulled here stops the board: they share the database, not the process.
        assert (await http.post(f"{url}/admin/api/kill-switch", headers=auth, json={"halted": True})).status_code == 200
    with pytest.raises(PactError) as info:
        await world.board.whoami(world.agents["code-web"])
    assert info.value.code == "system_halted"


async def test_board_stops_serving_the_admin_api_when_told(
    world: World, board: tuple[str, ResourceSettings], issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, settings = board
    await boss_with_email(world)
    token = issuer.token("sub-boss", settings.admin_audience, email="boss@example.com", amr=["mfa"])
    async with httpx2.AsyncClient(timeout=10) as http:
        auth = {"Authorization": f"Bearer {token}"}
        assert (await http.get(f"{url}/admin/api/me", headers=auth)).status_code == 200
        monkeypatch.setenv("PACT_ADMIN_API", "off")
        r = await http.get(f"{url}/admin/api/me", headers=auth)
    assert r.status_code == 404 and "own service" in r.json()["message"]
