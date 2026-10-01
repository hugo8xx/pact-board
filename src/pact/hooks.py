"""Claude Code hooks: plain HTTP endpoints at /hooks/a/<agent-id>/<event>.

Hooks are shell commands, not MCP clients, so they get two small endpoints instead of tools.
Each takes the JSON Claude Code writes to the hook's stdin, verbatim, and an agent token:

- ``post-tool-use`` logs what Claude Code just did (a shell command, a file edit) as an Entry on
  the task the agent is working on. Secrets are redacted before anything is stored.
- ``stop`` answers in the hook output format: a ``systemMessage`` for the person when open tasks
  arrived since this session last looked, else ``{}``. It never claims anything.

``hooks/pact-hook.sh`` is the client side.
"""

import json
from typing import Any

from starlette.requests import Request
from starlette.types import Receive, Scope, Send

from .board import Agent, Board
from .errors import PactError

EVENTS = ("post-tool-use", "stop")
MAX_BODY = 1_000_000
TEXT_LIMIT = 2_000
"""Longest command or file excerpt kept per entry; the log is an audit trail, not a backup."""

_EDIT_TOOLS = ("Edit", "MultiEdit", "Write", "NotebookEdit")


def _clip(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return value if len(value) <= TEXT_LIMIT else f"{value[:TEXT_LIMIT]}… [{len(value) - TEXT_LIMIT} more characters]"


def summarize_tool_use(hook: dict[str, Any]) -> dict[str, Any]:
    """What a PostToolUse event is worth keeping: the command, or the file and the change."""
    tool = str(hook.get("tool_name") or "unknown")
    given = hook.get("tool_input")
    inp: dict[str, Any] = given if isinstance(given, dict) else {}
    out: dict[str, Any] = {"tool": tool, "session_id": hook.get("session_id"), "cwd": hook.get("cwd")}
    if tool == "Bash":
        out["command"] = _clip(inp.get("command"))
        if inp.get("description"):
            out["description"] = _clip(inp.get("description"))
    elif tool in _EDIT_TOOLS:
        out["file_path"] = inp.get("file_path") or inp.get("notebook_path")
        if tool == "Write":
            out["content"] = _clip(inp.get("content"))
        elif tool == "Edit":
            out["old_string"] = _clip(inp.get("old_string"))
            out["new_string"] = _clip(inp.get("new_string"))
        elif tool == "MultiEdit":
            given_edits = inp.get("edits")
            edits: list[Any] = given_edits if isinstance(given_edits, list) else []
            out["edits"] = [
                {"old_string": _clip(e.get("old_string")), "new_string": _clip(e.get("new_string"))}
                for e in edits[:20]
                if isinstance(e, dict)
            ]
        else:
            out["new_source"] = _clip(inp.get("new_source"))
    else:
        out["input_keys"] = sorted(str(k) for k in inp)  # names only: other tools' inputs are not ours to keep
    return out


def stop_message(agent_id: str, listed: dict[str, Any]) -> dict[str, Any]:
    """Hook output for Stop. Shown to the person only; it does not enter the model's context."""
    tasks = listed["tasks"]
    if not tasks:
        return {}
    lines = [f"PACT: {len(tasks)}{'+' if listed['has_more'] else ''} new task(s) for {agent_id}:"]
    for t in tasks[:5]:
        mark = " (delegated to you)" if t["delegate_to"] == agent_id else ""
        lines.append(f"  • {t['title'][:100]}{mark}")
    if len(tasks) > 5:
        lines.append(f"  … and {len(tasks) - 5} more")
    lines.append("Nothing was claimed. Ask Claude to pull work from PACT to start one.")
    return {"systemMessage": "\n".join(lines)}


async def handle(scope: Scope, receive: Receive, send: Send, board: Board, agent: Agent, event: str) -> None:
    request = Request(scope, receive)
    if request.method != "POST":
        await _respond(send, 405, {"error": "method_not_allowed"})
        return
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            await _respond(send, 413, {"error": "too_large", "message": f"hook input is over {MAX_BODY} bytes"})
            return
    try:
        hook = json.loads(body or b"{}")
    except json.JSONDecodeError:
        hook = None
    if not isinstance(hook, dict):
        await _respond(send, 400, {"error": "invalid_request", "message": "send the hook's stdin JSON object"})
        return

    try:
        if event == "post-tool-use":
            await _respond(send, 200, await board.record_tool_use(agent, summarize_tool_use(hook)))
            return
        session_id = str(hook.get("session_id") or "")[:200]
        if not session_id:
            await _respond(send, 400, {"error": "invalid_request", "message": "session_id is required"})
            return
        await _respond(send, 200, stop_message(agent.id, await board.new_tasks_for_session(agent, session_id)))
    except PactError as err:
        if event == "stop":
            # Still a valid hook answer: tell the person why the board said no.
            await _respond(send, 200, {"systemMessage": f"PACT: the board refused ({err.code}): {err.message}"})
        else:
            await _respond(send, 200, {"logged": False, **err.to_dict()})


async def _respond(send: Send, status: int, body: dict[str, Any]) -> None:
    data = json.dumps(body, ensure_ascii=False).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})
