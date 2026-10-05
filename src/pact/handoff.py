"""A task closes with a handoff, so whoever picks up the work next sees what was done and where it lives."""

import re
from typing import Any

from .errors import PactError

TEMPLATE = """\
## Handoff
- Done: what was done
- Repo / branch / PR / commit: e.g. org/repo · feat/x · PR #12 · abc1234 (or "no code" and where it changed)
- Checks: lint / type / test / build results, or why they were not run
- Left / next: what remains
- Needs a human: decisions or steps only a person can take
- Links: docs, PRs, artifacts"""

_HEADING = re.compile(r"^\s{0,3}#{1,6}\s*handoff\b", re.IGNORECASE | re.MULTILINE)


def without_handoff(result: Any) -> Any:
    """The result minus its Handoff section (from the heading to the next heading of the same or a
    higher level, or the end): what a person reads, not what the next agent needs."""
    if not isinstance(result, str):
        return result
    match = _HEADING.search(result)
    if not match:
        return result
    level = len(match.group(0).strip()) - len(match.group(0).strip().lstrip("#"))
    rest = result[match.end() :]
    after = re.search(rf"^\s{{0,3}}#{{1,{level}}}\s", rest, re.MULTILINE)
    return (result[: match.start()] + (rest[after.start() :] if after else "")).strip()


def has_handoff(result: Any) -> bool:
    if isinstance(result, str):
        return bool(_HEADING.search(result))
    if isinstance(result, dict):
        for key, value in result.items():
            if isinstance(key, str) and key.lower() == "handoff":
                return bool(value.strip()) if isinstance(value, str) else bool(value)
    return False


def require_handoff(status: str, result: Any) -> None:
    if not has_handoff(result):
        raise PactError(
            "handoff_required",
            f"closing a task ({status}) needs a handoff in result: a markdown section headed 'Handoff', "
            f"or an object with a 'handoff' key. Template:\n{TEMPLATE}",
        )
