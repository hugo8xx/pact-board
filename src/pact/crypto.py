import hashlib
import hmac as _hmac
import json
import os
import secrets
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID


def iso(dt: datetime) -> str:
    """One spelling per instant, whatever time zone the value came back in."""
    return dt.astimezone(UTC).isoformat()


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def canonical_json(value: Any) -> str:
    """JSON with keys sorted at every level, so equal values always hash the same."""
    return json.dumps(_normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def hmac_hex(key: str, text: str) -> str:
    return _hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()


def hmac_equals(a: str, b: str) -> bool:
    return _hmac.compare_digest(a, b)


def new_token() -> str:
    return "pact_" + secrets.token_urlsafe(32)


def signing_key() -> str:
    key = os.environ.get("PACT_SIGNING_KEY", "")
    if len(key) < 32:
        raise RuntimeError("PACT_SIGNING_KEY must be set to at least 32 characters")
    return key
