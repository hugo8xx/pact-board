from typing import Literal

ErrorCode = Literal[
    "chain_broken",
    "scope_exceeded",
    "limit_exceeded",
    "mandate_expired",
    "mandate_revoked",
    "already_claimed",
    "delegation_exhausted",
    "project_mismatch",
    "project_required",
    "agent_paused",
    "project_frozen",
    "system_halted",
    "approval_pending",
    "claim_lost",
    "wrong_agent",
    "agent_unknown",
    "not_issuer",
    # Not in the requirement's list: plain input problems, not authority failures.
    "not_found",
    "invalid_request",
    "forbidden",
]


class PactError(Exception):
    """A refusal the board returns to the caller. `mandate_id` names the link in the chain at fault."""

    def __init__(self, code: ErrorCode, message: str, mandate_id: str | None = None) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message = message
        self.mandate_id = mandate_id

    def to_dict(self) -> dict[str, str]:
        out = {"error": self.code, "message": self.message}
        if self.mandate_id:
            out["mandate_id"] = self.mandate_id
        return out
