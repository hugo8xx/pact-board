"""The board as an OAuth protected resource.

Any OAuth 2.1 authorization server that issues JWT access tokens and publishes a JWKS works
(the PACT auth server, Keycloak, WorkOS, Auth0, …). The board never stores passwords.
"""

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

from .board import Agent
from .db import Conn, fetchone

ALGORITHMS = ["ES256", "RS256", "EdDSA"]


@dataclass(frozen=True)
class ResourceSettings:
    public_url: str
    """This server's public URL, e.g. https://mcp.example.com (no trailing slash)."""
    issuer: str | None
    """The authorization server's issuer URL. Unset: OAuth is off and only agent tokens work."""
    admin_requires_mfa: bool = True
    """Admin API tokens must show a second factor in `amr`. Turn off only for an issuer that never sets it."""
    admin_audience_override: str | None = None
    """The audience Admin API tokens carry. Defaults to ``<public_url>/admin``; the Admin API service
    sets it to the board's value so tokens stay the same wherever the API runs."""

    @classmethod
    def from_env(cls) -> "ResourceSettings":
        return cls(
            public_url=os.environ.get("PACT_PUBLIC_URL", "http://127.0.0.1:8787").rstrip("/"),
            issuer=(os.environ.get("PACT_AUTH_ISSUER") or "").rstrip("/") or None,
            admin_requires_mfa=os.environ.get("PACT_ADMIN_REQUIRE_MFA", "1") not in ("0", "false", "no"),
            admin_audience_override=(os.environ.get("PACT_ADMIN_AUDIENCE") or "").rstrip("/") or None,
        )

    @property
    def admin_audience(self) -> str:
        return self.admin_audience_override or f"{self.public_url}/admin"

    def resource(self, agent_id: str) -> str:
        return f"{self.public_url}/mcp/a/{agent_id}"

    def metadata_url(self, agent_id: str) -> str:
        return f"{self.public_url}/.well-known/oauth-protected-resource/mcp/a/{agent_id}"

    def resource_metadata(self, agent_id: str) -> dict[str, Any]:
        """RFC 9728 document. `resource` must equal the URL the user typed into Claude."""
        return {
            "resource": self.resource(agent_id),
            "authorization_servers": [self.issuer] if self.issuer else [],
            "scopes_supported": ["pact"],
            "bearer_methods_supported": ["header"],
            "resource_name": "PACT Board",
        }


class TokenRejected(Exception):
    pass


@dataclass
class Verifier:
    """Verifies access tokens against the issuer's published keys; keys and metadata are cached."""

    settings: ResourceSettings
    _meta: dict[str, Any] | None = None
    _meta_at: float = 0.0
    _jwks: jwt.PyJWKClient | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def issuer_metadata(self) -> dict[str, Any]:
        async with self._lock:
            if self._meta is None or time.monotonic() - self._meta_at > 3600:
                assert self.settings.issuer
                async with httpx.AsyncClient(timeout=10) as http:
                    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
                        r = await http.get(self.settings.issuer + path)
                        if r.status_code == 200:
                            self._meta, self._meta_at = r.json(), time.monotonic()
                            break
                    else:
                        raise TokenRejected("the authorization server publishes no metadata")
                self._jwks = jwt.PyJWKClient(self._meta["jwks_uri"], cache_keys=True, lifespan=3600)
            return self._meta

    async def verify(self, token: str, agent_id: str) -> dict[str, Any]:
        """Signature, issuer, expiry, and an audience of this agent's URL (or the server itself)."""
        return await self._decode(token, [self.settings.resource(agent_id), self.settings.public_url])

    async def verify_admin(self, token: str) -> dict[str, Any]:
        """A token minted for the Admin API only. Tokens for agent URLs carry another audience."""
        claims = await self._decode(token, [self.settings.admin_audience])
        if self.settings.admin_requires_mfa and "mfa" not in (claims.get("amr") or []):
            raise TokenRejected("the Admin API needs a sign-in with a second factor")
        return claims

    async def _decode(self, token: str, audiences: list[str]) -> dict[str, Any]:
        if not self.settings.issuer:
            raise TokenRejected("OAuth is not configured")
        await self.issuer_metadata()
        assert self._jwks is not None
        try:
            key = await asyncio.to_thread(self._jwks.get_signing_key_from_jwt, token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=ALGORITHMS,
                issuer=self.settings.issuer,
                audience=audiences,
                options={"require": ["exp", "sub", "iss", "aud"]},
                leeway=30,
            )
        except jwt.PyJWTError as err:
            raise TokenRejected(str(err)) from err
        scope = claims.get("scope")
        if isinstance(scope, str) and "pact" not in scope.split():
            raise TokenRejected("the token does not carry the pact scope")
        return claims

    async def email_of(self, token: str, claims: dict[str, Any]) -> str | None:
        """A verified email: from the token if it says so, else from the issuer's userinfo."""
        if claims.get("email") and claims.get("email_verified") is True:
            return str(claims["email"])
        meta = await self.issuer_metadata()
        if not meta.get("userinfo_endpoint"):
            return None
        async with httpx.AsyncClient(timeout=10) as http:
            r = await http.get(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            return None
        info = r.json()
        if info.get("sub") != claims["sub"] or info.get("email_verified") is not True:
            return None
        return str(info.get("email") or "") or None


async def human_for(conn: Conn, verifier: Verifier, token: str, claims: dict[str, Any]) -> str | None:
    """The board human this sign-in belongs to. Matched by email once, then pinned by `sub`."""
    issuer = verifier.settings.issuer
    row = await fetchone(conn, "SELECT id FROM humans WHERE auth_issuer = %s AND auth_sub = %s", (issuer, claims["sub"]))
    if row:
        return str(row["id"])
    email = await verifier.email_of(token, claims)
    if not email:
        return None
    row = await fetchone(
        conn,
        """UPDATE humans SET auth_issuer = %s, auth_sub = %s
           WHERE lower(email) = lower(%s) AND auth_sub IS NULL RETURNING id""",
        (issuer, claims["sub"], email),
    )
    return str(row["id"]) if row else None


async def agent_for_oauth(conn: Conn, verifier: Verifier, agent_id: str, token: str) -> Agent | None:
    """The agent in the URL, if the signed-in person is its owner."""
    claims = await verifier.verify(token, agent_id)
    human = await human_for(conn, verifier, token, claims)
    if human is None:
        raise TokenRejected("this account is not a registered person on the board")
    row = await fetchone(conn, "SELECT id, owner, client, status FROM agents WHERE id = %s", (agent_id,))
    if row is None or row["owner"] != human:
        return None
    return Agent(**row)
