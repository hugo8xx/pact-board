"""Tell people when the board needs them: a task waiting for approval, a task handed back to
humans, a top-level task closed, a task delegated to an agent that only works while a person has it
open (chat, cowork, design).

`enqueue` writes a row inside the caller's transaction, so a notification exists exactly when its
event does. `SlackSender` delivers pending rows to a Slack incoming webhook from whichever process
has ``PACT_SLACK_WEBHOOK_URL`` set (the Admin API service in production). Delivery failures retry
with backoff and never touch board work. Messages are Block Kit cards (`slack_cards`) carrying a
redacted, shortened title and detail and a button to the task in the Admin UI, never the task body.
"""

import asyncio
import json
import logging
import os
import time
from typing import Any, Literal

import httpx
from psycopg_pool import AsyncConnectionPool

from .db import Conn, fetchall, transaction
from .redact import redact_text
from .slack_cards import card, clean_report

Kind = Literal["approval_needed", "deferred", "question", "task_closed", "awaiting_session", "brief", "expiring", "expired"]

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
    "expiring": "ใกล้หมดอายุ",
    "expired": "หมดอายุแล้ว agent หยุดทำงาน",
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
    """Detail is cut to its first line, except for a brief, which goes whole: structured sections
    (a ``report``) as JSON for a card, or text up to BRIEF_MAX."""
    if kind == "brief" and isinstance(detail, dict) and isinstance(detail.get("report"), dict):
        report = clean_report(detail["report"])
        text = json.dumps(report, ensure_ascii=False) if report else _clip_text(detail.get("text") or "", BRIEF_MAX)
    elif kind == "brief" and detail:
        text = _clip_text(detail, BRIEF_MAX)
    else:
        text = _clip(_first_line(detail), DETAIL_MAX)
    await conn.execute(
        """INSERT INTO notifications (kind, project_id, task_id, agent_id, title, detail)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (kind, project_id, task_id, agent_id, _clip(title, TITLE_MAX), text or None),
    )


def slack_message(row: dict[str, Any], admin_ui_url: str | None) -> dict[str, Any]:
    return card(row, _HEADLINES.get(row["kind"], row["kind"]), admin_ui_url)


def warn_hours() -> float:
    return float(os.environ.get("PACT_EXPIRY_WARN_HOURS", "48"))


async def sweep_expiring(conn: Conn, within_hours: float | None = None) -> int:
    """Queue a notice for every active agent whose root mandate (one a person issued) or newest token
    expires within ``within_hours``, and again once it has expired, each only once. Something that
    expired more than a day ago is old news and never announced."""
    within = within_hours if within_hours is not None else warn_hours()
    rows = await fetchall(
        conn,
        """WITH subjects AS (
             SELECT 'mandate:' || m.id AS subject, m.holder AS agent, m.expires_at, 'mandate' AS what
             FROM mandates m JOIN agents a ON a.id = m.holder
             WHERE m.issuer_kind = 'human' AND m.revoked_at IS NULL AND a.status = 'active'
               -- a newer root for the same agent that outlives this one means it was renewed
               AND NOT EXISTS (SELECT 1 FROM mandates n WHERE n.holder = m.holder AND n.issuer_kind = 'human'
                                 AND n.revoked_at IS NULL AND n.expires_at > m.expires_at + interval '1 hour')
             UNION ALL
             SELECT 'token:' || t.agent_id || ':' || max(t.expires_at), t.agent_id, max(t.expires_at), 'token'
             FROM agent_tokens t JOIN agents a ON a.id = t.agent_id
             WHERE t.revoked_at IS NULL AND a.status = 'active'
             GROUP BY t.agent_id
           )
           SELECT s.*, CASE WHEN s.expires_at <= now() THEN 'expired' ELSE 'expiring' END AS stage,
                  (SELECT min(project_id) FROM agent_projects WHERE agent_id = s.agent) AS project_id
           FROM subjects s
           WHERE s.expires_at <= now() + make_interval(secs => %s) AND s.expires_at > now() - interval '1 day'""",
        (within * 3600,),
    )
    queued = 0
    for r in rows:
        if r["project_id"] is None:
            continue
        fresh = await fetchall(
            conn,
            "INSERT INTO expiry_notices (subject, stage) VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING subject",
            (r["subject"], r["stage"]),
        )
        if not fresh:
            continue
        what = "ใบมอบอำนาจราก" if r["what"] == "mandate" else "token"
        when = r["expires_at"].astimezone().strftime("%Y-%m-%d %H:%M %Z")
        verb = "หมดอายุแล้วเมื่อ" if r["stage"] == "expired" else "จะหมดอายุ"
        await enqueue(
            conn,
            r["stage"],
            project_id=r["project_id"],
            task_id=None,
            agent_id=r["agent"],
            title=f"{r['agent']}: {what} {verb} {when}",
            detail=f"ต่ออายุด้วย pact-admin {'mandate-issue' if r['what'] == 'mandate' else 'token-issue'} แล้วอัปเดต env ของ agent",
        )
        queued += 1
    return queued


class SlackSender:
    def __init__(
        self,
        pool: AsyncConnectionPool[Conn],
        webhook_url: str,
        *,
        admin_ui_url: str | None = None,
        interval: float = 5.0,
        sweep_every: float = 600.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.sweep_every = sweep_every
        self._next_sweep = 0.0
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
                if time.monotonic() >= self._next_sweep:
                    self._next_sweep = time.monotonic() + self.sweep_every
                    async with transaction(self.pool) as conn:
                        await sweep_expiring(conn)
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
