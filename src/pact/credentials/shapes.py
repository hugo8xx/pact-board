"""What every credential format shares when it turns ledger links into a credential.

Kept apart from the formats so that loading one format never loads another.
"""

import os
from collections.abc import Sequence

from ..mandates import Limits, Mandate
from ..scope import parse_board_scope


def unexportable(scope: Sequence[str]) -> list[str]:
    """Scopes no format can carry: wildcard actions, and anything without a project."""
    out = []
    for s in scope:
        parsed = parse_board_scope(s)
        if parsed is None or "*" in parsed.action:
            out.append(s)
    return out


def effective_limits(links: Sequence[Mandate]) -> list[Limits]:
    """Each link's per-call ceilings: its own, tightened by every ancestor's."""
    out: list[Limits] = []
    current: Limits = {}
    for m in links:
        current = {**current, **{k: min(v, current.get(k, v)) for k, v in m.limits.items()}}
        out.append(dict(current))
    return out


def leaf_ttl_cap() -> int:
    """``PACT_EXPORT_TTL_HOURS`` (default 24): the longest an exported leaf lives. A root mandate
    can run for weeks and is not revoked when a task closes, so an agent's outside credential is
    kept short and simply re-issued on its next claim."""
    return max(60, int(float(os.environ.get("PACT_EXPORT_TTL_HOURS", "24")) * 3600))
