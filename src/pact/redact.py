"""Strip secrets before anything reaches the log.

Entries are permanent, so a key written there could never be removed from the hash chain.
"""

import re
from typing import Any

MARK = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), MARK),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}"), MARK),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"), MARK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), MARK),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MARK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MARK),
    (re.compile(r"\bpact_[A-Za-z0-9_-]{20,}"), MARK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), MARK),
    (re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/-]{16,}=*", re.IGNORECASE), rf"\1{MARK}"),
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@", re.IGNORECASE), rf"\1{MARK}@"),
    (
        re.compile(
            r"(\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b\s*[=:]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)",
            re.IGNORECASE,
        ),
        rf"\1{MARK}",
    ),
]

_SECRET_KEY = re.compile(
    r"^(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token|authorization|private[_-]?key)$",
    re.IGNORECASE,
)


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, dict):
        return {k: (MARK if _SECRET_KEY.match(str(k)) and v is not None else redact(v)) for k, v in value.items()}
    return value
