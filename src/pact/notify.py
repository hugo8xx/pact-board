"""Tell people when the board needs them: a task waiting for approval, a task handed back to
humans, a top-level task closed, a task delegated to an agent that only works while a person has it
open (chat, cowork, design).

`enqueue` writes a row inside the caller's transaction, so a notification exists exactly when its
event does. `SlackSender` delivers pending rows to a Slack incoming webhook from whichever process
has ``PACT_SLACK_WEBHOOK_URL`` set (the Admin API service in production). Delivery failures retry
with backoff and never touch board work. Messages carry a redacted, shortened title and detail and a
link to the task in the Admin UI, never the task body.
"""

import asyncio
import json
import logging
import os
from typing import Any, Literal

import httpx
from psycopg_pool import AsyncConnectionPool

from .db import Conn, fetchall, transaction
from .redact import redact_text

Kind = Literal["approval_needed", "deferred", "question", "task_closed", "awaiting_session", "brief"]

TITLE_MAX = 200
DETAIL_MAX = 300
BRIEF_MAX = 2800
"""A brief is sent whole, up to this many characters (Slack shows about 3000 in one section)."""
MAX_ATTEMPTS = 8
BATCH = 20

log = logging.getLogger("pact.notify")

_HEADLINES: dict[str, str] = {
    "approval_needed": "รออนุมัติ",
    "deferred": "ส่งกลับให้คนตัดสิน",
    "question": "agent ถามคำถาม",
    "task_closed": "งานปิดแล้ว",
    "awaiting_session": "รอคนเปิด session",
    "brief": "รายงานประจำวัน",
}


def _clip(text: str, limit: int) -> str:
    text = " ".join(redact_text(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _clip_text(value: Any, limit: int) -> str:
    """Like _clip, but keeps the lines: a brief is read as a list, not one sentence."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    lines = [" ".join(line.split()) for line in redact_text(text).splitlines()]
    text = "\n".join(lines).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _first_line(value: Any) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


async def enqueue(
    conn: Conn,
    kind: Kind,
    *,
    project_id: str,
    task_id: str | None,
    agent_id: str | None,
    title: str,
    detail: Any = None,
) -> None:
    """Detail is cut to its first line, except for a brief, which goes whole (up to BRIEF_MAX)."""
    text = _clip_text(detail, BRIEF_MAX) if kind == "brief" and detail else _clip(_first_line(detail), DETAIL_MAX)
    await conn.execute(
        """INSERT INTO notifications (kind, project_id, task_id, agent_id, title, detail)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (kind, project_id, task_id, agent_id, _clip(title, TITLE_MAX), text or None),
    )


def _escape(text: str) -> str:
    # Slack mrkdwn treats these three as control characters.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_message(row: dict[str, Any], admin_ui_url: str | None) -> dict[str, Any]:
    headline = _HEADLINES.get(row["kind"], row["kind"])
    title = _escape(row["title"])
    if admin_ui_url and row.get("task_id"):
        title = f"<{admin_ui_url.rstrip('/')}/tasks/{row['task_id']}|{title}>"
    lines = [f"*{headline}* · {_escape(row['project_id'])} · {title}"]
    if row.get("agent_id"):
        lines.append(f"โดย {_escape(row['agent_id'])}")
    if row.get("detail") and row["kind"] == "brief":
        lines += ["", _escape(row["detail"])]
    elif row.get("detail"):
        lines.append(f"> {_escape(row['detail'])}")
    text = "\n".join(lines)
    return {"text": text, "mrkdwn": True}


class SlackSender:
    def __init__(
        self,
        pool: AsyncConnectionPool[Conn],
        webhook_url: str,
        *,
        admin_ui_url: str | None = None,
        interval: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.pool = pool
        self.webhook_url = webhook_url
        self.admin_ui_url = admin_ui_url
        self.interval = interval
        self.client = client or httpx.AsyncClient(timeout=10)
        self._task: asyncio.Task[None] | None = None

    @classmethod
    def from_env(cls, pool: AsyncConnectionPool[Conn]) -> "SlackSender | None":
        url = os.environ.get("PACT_SLACK_WEBHOOK_URL")
        if not url:
            return None
        return cls(pool, url, admin_ui_url=os.environ.get("PACT_ADMIN_UI_URL"))

    async def send_pending(self) -> int:
        """Deliver one batch. Rows are locked with SKIP LOCKED, so two senders never double-post."""
        sent = 0
        async with transaction(self.pool) as conn:
            rows = await fetchall(
                conn,
                """SELECT id, kind, project_id, task_id::text AS task_id, agent_id, title, detail, attempts
                   FROM notifications
                   WHERE sent_at IS NULL AND attempts < %s AND next_attempt_at <= now()
                   ORDER BY id LIMIT %s FOR UPDATE SKIP LOCKED""",
                (MAX_ATTEMPTS, BATCH),
            )
            for row in rows:
                error: str | None = None
                try:
                    response = await self.client.post(self.webhook_url, json=slack_message(row, self.admin_ui_url))
                    if response.status_code >= 300:
                        error = f"slack answered {response.status_code}: {response.text[:200]}"
                except httpx.HTTPError as exc:
                    error = f"{type(exc).__name__}: {exc}"[:300]
                if error is None:
                    await conn.execute("UPDATE notifications SET sent_at = now(), last_error = NULL WHERE id = %s", (row["id"],))
                    sent += 1
                else:
                    log.warning("notification %s not delivered: %s", row["id"], error)
                    await conn.execute(
                        """UPDATE notifications
                           SET attempts = attempts + 1, last_error = %s,
                               next_attempt_at = now() + make_interval(secs => 30 * power(2, attempts))
                           WHERE id = %s""",
                        (error, row["id"]),
                    )
        return sent

    async def _loop(self) -> None:
        while True:
            try:
                await self.send_pending()
            except Exception:  # noqa: BLE001 — the loop must outlive a bad batch or a database blip
                log.exception("notification sender failed a batch")
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="pact-slack-sender")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.client.aclose()
