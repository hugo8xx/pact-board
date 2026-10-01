"""Who is calling. Phase 1 knows bearer tokens; phase 2 adds OAuth for Claude and Gemini clients."""

from .board import Agent
from .crypto import sha256
from .db import Conn, fetchone


async def agent_for_token(conn: Conn, agent_id: str, token: str) -> Agent | None:
    """The agent named in the URL, if the token is a live token for that same agent."""
    row = await fetchone(
        conn,
        """SELECT a.id, a.owner, a.client, a.status FROM agent_tokens t JOIN agents a ON a.id = t.agent_id
           WHERE t.token_hash = %s AND t.agent_id = %s AND t.revoked_at IS NULL AND t.expires_at > now()""",
        (sha256(token), agent_id),
    )
    return Agent(**row) if row else None
