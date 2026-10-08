"""Slack Block Kit cards for notifications. Incoming webhooks render blocks and link buttons; buttons
that act (approve, send back) would need a Slack app with an interactivity endpoint, so every button
here only opens the Admin UI.

A brief arrives either as structured sections (``{"greeting", "sections": [{"title", "items":
[{"text", "task_id"}]}]}``), which become one card with a button per item, or as plain text, which
becomes a card with the text in it.
"""

import json
import re
from typing import Any

from .redact import redact_text

ICONS: dict[str, str] = {
    "approval_needed": "🟡",
    "deferred": "↩️",
    "question": "❓",
    "task_closed": "✅",
    "awaiting_session": "💤",
    "brief": "📋",
    "expiring": "⏳",
    "expired": "⛔",
    "message": "💬",
}

MAX_BLOCKS = 50
SECTION_MAX = 2900
"""Slack refuses a section's text over 3000 characters."""
HEADER_MAX = 150
BRIEF_SECTIONS = 6
BRIEF_ITEMS = 10
ITEM_MAX = 600
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def escape(text: str) -> str:
    # Slack mrkdwn treats these three as control characters.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _clean(value: Any, limit: int) -> str:
    """Redacted, lines kept, each line's spacing squeezed, cut to ``limit``."""
    lines = [" ".join(line.split()) for line in redact_text(str(value or "")).splitlines()]
    return _cut("\n".join(lines).strip(), limit)


def clean_report(report: dict[str, Any]) -> dict[str, Any] | None:
    """A structured brief as the board stores it: redacted, bounded, with only well-formed task ids.
    None if it has no sections."""
    sections = []
    for s in (report.get("sections") or [])[:BRIEF_SECTIONS]:
        if not isinstance(s, dict) or not s.get("title"):
            continue
        items = []
        for it in (s.get("items") or [])[:BRIEF_ITEMS]:
            item = it if isinstance(it, dict) else {"text": it}
            text = _clean(item.get("text"), ITEM_MAX)
            if not text:
                continue
            task_id = str(item.get("task_id") or "")
            items.append({"text": text, **({"task_id": task_id} if _UUID.match(task_id) else {})})
        sections.append({"title": _clean(s["title"], 80), "items": items})
    if not sections:
        return None
    return {"greeting": _clean(report.get("greeting"), 300), "sections": sections}


def _button(label: str, url: str) -> dict[str, Any]:
    return {"type": "button", "text": {"type": "plain_text", "text": label, "emoji": True}, "url": url}


def _section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": _cut(text, SECTION_MAX)}}


def _header(text: str) -> dict[str, Any]:
    return {"type": "header", "text": {"type": "plain_text", "text": _cut(text, HEADER_MAX), "emoji": True}}


def _context(row: dict[str, Any]) -> dict[str, Any]:
    parts = [escape(row["project_id"])]
    if row.get("agent_id"):
        parts.append(f"โดย {escape(row['agent_id'])}")
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(parts)}]}


def _report(row: dict[str, Any]) -> dict[str, Any] | None:
    if row["kind"] != "brief" or not row.get("detail"):
        return None
    try:
        parsed = json.loads(row["detail"])
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) and parsed.get("sections") else None


def card(row: dict[str, Any], headline: str, admin_ui_url: str | None) -> dict[str, Any]:
    """The webhook payload for one notification row: blocks plus a plain ``text`` for phone
    notifications and clients that show no blocks."""
    base = admin_ui_url.rstrip("/") if admin_ui_url else None
    task_url = f"{base}/tasks/{row['task_id']}" if base and row.get("task_id") else None
    icon = ICONS.get(row["kind"], "🔔")
    report = _report(row)
    if report is not None:
        return _brief_card(row, report, icon, base)

    blocks: list[dict[str, Any]] = [_header(f"{icon} {headline}")]
    title = f"*<{task_url}|{escape(row['title'])}>*" if task_url else f"*{escape(row['title'])}*"
    detail = row.get("detail") or ""
    if row["kind"] == "brief":
        blocks += [_section(title), _section(escape(detail))] if detail else [_section(title)]
    else:
        blocks.append(_section(f"{title}\n{escape(detail)}" if detail else title))
    blocks.append(_context(row))
    if task_url:
        blocks.append({"type": "actions", "elements": [_button("เปิดงาน", task_url)]})
    return {"text": f"{icon} {headline} · {row['title']}", "blocks": blocks}


def _brief_card(row: dict[str, Any], report: dict[str, Any], icon: str, base: str | None) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [_header(f"{icon} {row['title']}")]
    if report.get("greeting"):
        blocks.append(_section(escape(report["greeting"])))
    for s in report["sections"]:
        if len(blocks) >= MAX_BLOCKS - 4:
            break
        blocks += [{"type": "divider"}, _section(f"*{escape(s['title'])}*")]
        loose: list[str] = []
        for i, item in enumerate(s["items"], 1):
            if len(blocks) >= MAX_BLOCKS - 4:
                break
            text = escape(item["text"])
            if base and item.get("task_id"):
                if loose:
                    blocks.append(_section("\n".join(loose)))
                    loose = []
                block = _section(f"{i}. {text}")
                block["accessory"] = _button("เปิดงาน", f"{base}/tasks/{item['task_id']}")
                blocks.append(block)
            else:
                loose.append(f"• {text}")
        if loose:
            blocks.append(_section("\n".join(loose)))
    blocks += [{"type": "divider"}, _context(row)]
    if base:
        blocks.append({"type": "actions", "elements": [_button("เปิดกระดาน", f"{base}/tasks")]})
    preview = report.get("greeting") or row["title"]
    return {"text": f"{icon} {preview}", "blocks": blocks[:MAX_BLOCKS]}
