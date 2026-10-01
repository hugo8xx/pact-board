"""Scope strings.

Board scopes look like ``<action>@project:<slug>``, e.g. ``task.claim@project:web``.
Anything else (e.g. ``doc.read:customer_a``) is matched as an opaque string.
Action patterns: ``*`` matches every action, ``a.*`` matches ``a`` and anything under ``a.``.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

_BOARD = re.compile(r"^([^@\s]+)@project:([a-z0-9][a-z0-9-]*)$")


@dataclass(frozen=True)
class BoardScope:
    action: str
    project: str


def board_scope(action: str, project: str) -> str:
    return f"{action}@project:{project}"


def parse_board_scope(scope: str) -> BoardScope | None:
    m = _BOARD.match(scope)
    return BoardScope(m.group(1), m.group(2)) if m else None


def action_covers(granted: str, needed: str) -> bool:
    if granted == "*" or granted == needed:
        return True
    if granted.endswith(".*"):
        prefix = granted[:-2]
        return needed == prefix or needed.startswith(prefix + ".")
    return False


def scope_covers(granted: str, needed: str) -> bool:
    g, n = parse_board_scope(granted), parse_board_scope(needed)
    if g and n:
        return g.project == n.project and action_covers(g.action, n.action)
    if g or n:
        return False
    return action_covers(granted, needed)


def any_covers(granted: Iterable[str], needed: str) -> bool:
    return any(scope_covers(g, needed) for g in granted)


def uncovered(child: Iterable[str], parent: list[str]) -> list[str]:
    """Items of ``child`` not covered by ``parent``; empty means child ⊆ parent."""
    return [c for c in child if not any_covers(parent, c)]


def is_valid_scope(scope: str) -> bool:
    return 0 < len(scope) <= 200 and not re.search(r"\s", scope)
