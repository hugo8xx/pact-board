import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from psycopg import AsyncConnection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import AsyncConnectionPool

Conn = AsyncConnection[DictRow]

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


async def _configure(conn: AsyncConnection[Any]) -> None:
    # Timestamps come back in UTC so signatures and hashes see one spelling of each instant.
    await conn.execute("SET TIME ZONE 'UTC'")
    await conn.commit()


def create_pool(url: str | None = None, max_size: int = 20) -> AsyncConnectionPool[Conn]:
    url = url or os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    return AsyncConnectionPool(
        url,
        min_size=1,
        max_size=max_size,
        open=False,
        configure=_configure,
        kwargs={"row_factory": dict_row},
        connection_class=AsyncConnection[DictRow],
    )


@asynccontextmanager
async def transaction(pool: AsyncConnectionPool[Conn]) -> AsyncIterator[Conn]:
    """One transaction: commits when the block ends, rolls back if it raises."""
    async with pool.connection() as conn:
        async with conn.transaction():
            yield conn


async def fetchone(conn: Conn, sql: str, params: Any = None) -> DictRow | None:
    cur = await conn.execute(sql, params)
    return await cur.fetchone()


async def fetchall(conn: Conn, sql: str, params: Any = None) -> list[DictRow]:
    cur = await conn.execute(sql, params)
    return await cur.fetchall()


async def migrate(pool: AsyncConnectionPool[Conn], upto: str | None = None) -> list[str]:
    """Apply the migrations not applied yet, in order. ``upto`` (a file name) stops after that one,
    so a test can load data the way an older release left it before the next migration runs."""
    applied: list[str] = []
    async with transaction(pool) as conn:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {r["name"] for r in await fetchall(conn, "SELECT name FROM schema_migrations")}
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if upto is not None and path.name > upto:
            break
        if path.name in done:
            continue
        async with transaction(pool) as conn:
            await conn.execute(path.read_text())
            await conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (path.name,))
        applied.append(path.name)
    return applied
