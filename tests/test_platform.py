"""The platform operator's commands, and the end of the 'default' organization defaults."""

import argparse

import psycopg
import pytest

from pact.cli import _parser, _run
from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError

from .conftest import World
from .test_tenancy import two_organizations

pytestmark = pytest.mark.anyio


def cli(*argv: str) -> argparse.Namespace:
    return _parser().parse_args(list(argv))


async def test_a_row_that_forgets_its_organization_is_refused(world: World) -> None:
    with pytest.raises(psycopg.errors.NotNullViolation):
        async with transaction(world.pool) as conn:
            await conn.execute("INSERT INTO projects (id, name, created_by) VALUES ('orphan', 'Orphan', 'boss')")


async def test_the_operator_lists_renames_and_halts_one_organization(world: World) -> None:
    await two_organizations(world)
    listed = {o["id"]: o for o in await _run(cli("org-list"))}
    assert set(listed) == {"default", "rival"}
    assert listed["default"]["projects"] == 1 and listed["rival"]["projects"] == 1 and listed["rival"]["people"] == 1
    assert "boss@example.com" not in str(listed)

    assert (await _run(cli("org-rename", "rival", "Rival Ltd")))["name"] == "Rival Ltd"
    assert (await _run(cli("org-halt", "rival")))["halted"] is True
    halted = await world.board.list_tasks(world.agents["code-web"], mandate_id=world.roots["code-web"])
    assert halted is not None  # the default organization keeps working
    async with transaction(world.pool) as conn:
        log = await fetchall(
            conn, "SELECT org_id, chain_key, actor, action FROM entries WHERE action LIKE 'platform.%' ORDER BY id"
        )
    assert [(e["org_id"], e["chain_key"], e["actor"]) for e in log] == [("rival", "_system:rival", "system")] * 2
    await _run(cli("org-unhalt", "rival"))

    with pytest.raises(PactError) as err:
        await _run(cli("org-halt", "nobody"))
    assert err.value.code == "not_found"


async def test_the_platform_switch_stops_everyone_and_every_log_says_so(world: World) -> None:
    await two_organizations(world)
    await _run(cli("platform-halt"))
    with pytest.raises(PactError) as err:
        await world.board.list_tasks(world.agents["code-web"], mandate_id=world.roots["code-web"])
    assert err.value.code == "system_halted"
    await _run(cli("platform-unhalt"))
    async with transaction(world.pool) as conn:
        assert await fetchone(conn, "SELECT halted FROM system_state") == {"halted": False}
        log = await fetchall(conn, "SELECT org_id FROM entries WHERE action = 'platform.halt' ORDER BY id")
    assert sorted(e["org_id"] for e in log) == ["default", "default", "rival", "rival"]


async def test_log_verify_covers_every_organization_or_the_one_named(world: World) -> None:
    await two_organizations(world)
    every = await _run(cli("log-verify"))
    assert set(every) == {"default", "rival"} and all(c["ok"] for chains in every.values() for c in chains)
    assert set(await _run(cli("log-verify", "--org", "rival"))) == {"rival"}
