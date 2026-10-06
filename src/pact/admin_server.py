"""The Admin API as its own service: ``pact-admin-api``.

Same database and code as the board, a separate process. The kill switch, pausing and the audit
log keep working when the MCP side is overloaded or down, and nothing an agent can reach shares
a process with what only humans may do. It serves /healthz and /admin/api/* and nothing else.
It also delivers notifications to each organization's Slack webhook.
"""

import json
import os
from typing import Any

import uvicorn
from psycopg_pool import AsyncConnectionPool
from starlette.types import Receive, Scope, Send

from .admin_api import build_admin_app
from .db import Conn, create_pool
from .notify import SlackSender
from .oauth import ResourceSettings, Verifier


class AdminServer:
    def __init__(self, pool: AsyncConnectionPool[Conn], settings: ResourceSettings) -> None:
        self.pool = pool
        self.admin_app = build_admin_app(pool, Verifier(settings))
        self.sender = SlackSender.from_env(pool)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        path: str = scope["path"]
        if path == "/healthz":
            await _respond(send, 200, {"ok": True})
        elif path.startswith("/admin/api/"):
            await self.admin_app(scope, receive, send)
        else:
            await _respond(send, 404, {"error": "not_found", "message": "this service serves /admin/api only"})

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message: Any = await receive()
            if message["type"] == "lifespan.startup":
                await self.pool.open()
                if self.sender:
                    self.sender.start()
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                if self.sender:
                    await self.sender.stop()
                await self.pool.close()
                await send({"type": "lifespan.shutdown.complete"})
                return


async def _respond(send: Send, status: int, body: dict[str, Any]) -> None:
    data = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})


def create_admin_server(pool: AsyncConnectionPool[Conn] | None = None, settings: ResourceSettings | None = None) -> AdminServer:
    return AdminServer(pool or create_pool(max_size=5), settings or ResourceSettings.from_env())


def main() -> None:
    uvicorn.run(create_admin_server(), host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8788")))


if __name__ == "__main__":
    main()
