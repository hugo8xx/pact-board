"""Claude Code hooks: PostToolUse entries on the task in hand, and the Stop hook's new-task notice."""

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest

from pact.db import fetchall, fetchone, transaction
from pact.errors import PactError
from pact.hooks import TEXT_LIMIT, summarize_tool_use

from .conftest import World
from .test_http import server_url  # noqa: F401 — fixture

pytestmark = pytest.mark.anyio

HOOK_SCRIPT = Path(__file__).resolve().parents[1] / "hooks" / "pact-hook.sh"
SECRET = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def bash(command: str, session: str = "s1") -> dict[str, Any]:
    return {
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "run it"},
        "tool_response": {"stdout": "lots of output", "stderr": ""},
    }


async def setup(w: World) -> dict[str, Any]:
    await w.project("web")
    await w.agent("chat-boss", "chat", ["web"])
    await w.agent("code-web", "code", ["web"])
    await w.agent("code-web-2", "gemini", ["web"])
    t = await w.board.post(w.agents["chat-boss"], project_id="web", title="fix login", mandate_id=w.roots["chat-boss"])
    return t


async def hook_entries(w: World) -> list[dict[str, Any]]:
    async with transaction(w.pool) as conn:
        return await fetchall(
            conn,
            """SELECT e.task_id::text, e.agent_id, e.mandate_chain, e.outcome, p.content FROM entries e
               JOIN payloads p ON p.id = e.payload_ref WHERE e.action = 'hook.post_tool_use' ORDER BY e.id""",
        )


# ── A. PostToolUse → Entry ────────────────────────────────────────────────────


async def test_tool_use_is_logged_on_the_task_in_hand_with_secrets_redacted(world: World) -> None:
    t = await setup(world)
    code = world.agents["code-web"]
    await world.board.claim(code, task_id=t["task_id"], mandate_id=world.roots["code-web"])
    out = await world.board.record_tool_use(
        code, summarize_tool_use(bash(f"curl -H 'Authorization: Bearer {SECRET}' https://x && psql postgres://u:hunter2@db/p"))
    )
    assert out == {"logged": True, "task_id": t["task_id"]}

    [entry] = await hook_entries(world)
    assert entry["task_id"] == t["task_id"] and entry["agent_id"] == "code-web" and entry["outcome"] == "ok"
    assert [str(m) for m in entry["mandate_chain"]] == [world.roots["code-web"]]  # traceable to the human
    stored = json.dumps(entry["content"])
    assert SECRET not in stored and "hunter2" not in stored and "[REDACTED]" in stored
    assert "lots of output" not in stored  # tool output is not kept


async def test_file_edits_keep_the_path_and_a_redacted_clipped_change(world: World) -> None:
    t = await setup(world)
    code = world.agents["code-web"]
    await world.board.claim(code, task_id=t["task_id"], mandate_id=world.roots["code-web"])
    edit = {
        "session_id": "s1",
        "tool_name": "Edit",
        "tool_input": {"file_path": "/repo/.env", "old_string": "API_KEY=old", "new_string": f"API_KEY={SECRET}"},
    }
    write = {"session_id": "s1", "tool_name": "Write", "tool_input": {"file_path": "/repo/big.txt", "content": "x" * 5000}}
    other = {"session_id": "s1", "tool_name": "WebFetch", "tool_input": {"url": "https://example.com", "prompt": "p"}}
    for hook in (edit, write, other):
        await world.board.record_tool_use(code, summarize_tool_use(hook))

    e, w, o = (x["content"] for x in await hook_entries(world))
    assert e["file_path"] == "/repo/.env" and SECRET not in json.dumps(e)
    assert len(w["content"]) < TEXT_LIMIT + 50 and w["content"].endswith("[3000 more characters]")
    assert o == {"tool": "WebFetch", "session_id": "s1", "cwd": None, "input_keys": ["prompt", "url"]}


async def test_nothing_is_logged_without_exactly_one_task_in_hand(world: World) -> None:
    t = await setup(world)
    code = world.agents["code-web"]
    assert await world.board.record_tool_use(code, summarize_tool_use(bash("ls"))) == {
        "logged": False,
        "reason": "no task held",
    }
    t2 = await world.board.post(world.agents["chat-boss"], project_id="web", title="second", mandate_id=world.roots["chat-boss"])
    for task in (t, t2):
        await world.board.claim(code, task_id=task["task_id"], mandate_id=world.roots["code-web"])
    assert (await world.board.record_tool_use(code, summarize_tool_use(bash("ls"))))["reason"] == "several tasks held"
    assert await hook_entries(world) == []


async def test_hook_entries_are_heartbeats_so_long_work_is_not_released(world: World) -> None:
    t = await setup(world)
    code, other = world.agents["code-web"], world.agents["code-web-2"]
    await world.board.claim(code, task_id=t["task_id"], mandate_id=world.roots["code-web"])
    async with transaction(world.pool) as conn:  # claimed 45 minutes ago, last hook 10 minutes ago
        await conn.execute("UPDATE tasks SET claimed_at = now() - interval '45 minutes' WHERE id = %s", (t["task_id"],))
        await conn.execute("UPDATE task_activity SET at = now() - interval '10 minutes' WHERE task_id = %s", (t["task_id"],))
    await world.board.record_tool_use(code, summarize_tool_use(bash("pytest")))
    with pytest.raises(PactError) as info:
        await world.board.claim(other, task_id=t["task_id"], mandate_id=world.roots["code-web-2"])
    assert info.value.code == "already_claimed"
    async with transaction(world.pool) as conn:
        row = await fetchone(
            conn, "SELECT at > now() - interval '1 minute' AS fresh FROM task_activity WHERE task_id = %s", (t["task_id"],)
        )
    assert row == {"fresh": True}


async def test_hooks_respect_the_kill_switch(world: World) -> None:
    t = await setup(world)
    code = world.agents["code-web"]
    await world.board.claim(code, task_id=t["task_id"], mandate_id=world.roots["code-web"])
    await world.admin.set_halted(True, by="boss")
    with pytest.raises(PactError) as info:
        await world.board.record_tool_use(code, summarize_tool_use(bash("ls")))
    assert info.value.code == "system_halted"


# ── C. Stop → new tasks, never a claim ────────────────────────────────────────


async def test_stop_reports_each_task_once_per_session_and_claims_nothing(world: World) -> None:
    t = await setup(world)
    code = world.agents["code-web"]
    first = await world.board.new_tasks_for_session(code, "s1")
    assert [x["id"] for x in first["tasks"]] == [t["task_id"]]
    assert (await world.board.new_tasks_for_session(code, "s1"))["tasks"] == []
    t2 = await world.board.post(
        world.agents["chat-boss"], project_id="web", title="new one", mandate_id=world.roots["chat-boss"], delegate_to="code-web"
    )
    assert [x["id"] for x in (await world.board.new_tasks_for_session(code, "s1"))["tasks"]] == [t2["task_id"]]
    assert len((await world.board.new_tasks_for_session(code, "s2"))["tasks"]) == 2  # another session starts fresh
    async with transaction(world.pool) as conn:
        assert await fetchall(conn, "SELECT id FROM tasks WHERE assignee IS NOT NULL") == []


# ── over HTTP, through the real script ────────────────────────────────────────


async def post(url: str, path: str, token: str | None, body: Any) -> httpx2.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(timeout=10) as http:
        return await http.post(f"{url}{path}", headers=headers, json=body)


async def test_hook_endpoints_take_only_this_agents_token(world: World, server_url: str) -> None:  # noqa: F811
    await setup(world)
    path = "/hooks/a/code-web/post-tool-use"
    assert (await post(server_url, path, None, bash("ls"))).status_code == 401
    assert (await post(server_url, path, world.tokens["chat-boss"], bash("ls"))).status_code == 401
    assert (await post(server_url, path, world.tokens["code-web"], bash("ls"))).json() == {
        "logged": False,
        "reason": "no task held",
    }
    assert (await post(server_url, "/hooks/a/code-web/session-start", world.tokens["code-web"], {})).status_code == 404
    assert (await post(server_url, "/hooks/a/code-web/stop", world.tokens["code-web"], {})).status_code == 400


@pytest.fixture
def hook_dir(tmp_path: Path) -> Iterator[Path]:
    if not shutil.which("curl"):
        pytest.skip("curl is needed to run the hook script")
    yield tmp_path


def run_hook(hook_dir: Path, event: str, stdin: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(HOOK_SCRIPT), "code-web", event],
        input=json.dumps(stdin),
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "PACT_HOOK_DIR": str(hook_dir)},
    )


async def test_the_hook_script_end_to_end(world: World, server_url: str, hook_dir: Path) -> None:  # noqa: F811
    t = await setup(world)
    # Without a config file the hook is silent and never fails Claude Code.
    quiet = run_hook(hook_dir, "stop", {"session_id": "s1"})
    assert (quiet.returncode, quiet.stdout) == (0, "")

    (hook_dir / "code-web.env").write_text(f"PACT_URL={server_url}\nPACT_TOKEN={world.tokens['code-web']}\n")
    stop = run_hook(hook_dir, "stop", {"session_id": "s1", "hook_event_name": "Stop"})
    assert stop.returncode == 0
    message = json.loads(stop.stdout)["systemMessage"]
    assert "fix login" in message and "Nothing was claimed" in message
    assert json.loads(run_hook(hook_dir, "stop", {"session_id": "s1"}).stdout) == {}

    await world.board.claim(world.agents["code-web"], task_id=t["task_id"], mandate_id=world.roots["code-web"])
    logged = run_hook(hook_dir, "post-tool-use", bash(f"export ANTHROPIC_API_KEY={SECRET}"))
    assert (logged.returncode, logged.stdout) == (0, "")
    [entry] = await hook_entries(world)
    assert entry["task_id"] == t["task_id"] and SECRET not in json.dumps(entry["content"])

    (hook_dir / "code-web.env").write_text("PACT_URL=http://127.0.0.1:9\nPACT_TOKEN=pact_x\n")  # board unreachable
    down = run_hook(hook_dir, "stop", {"session_id": "s1"})
    assert (down.returncode, down.stdout) == (0, "")
