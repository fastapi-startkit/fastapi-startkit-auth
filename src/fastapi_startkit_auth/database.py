from __future__ import annotations

import asyncio
import re
from typing import Any, Callable, Protocol, Sequence, runtime_checkable

from .concurrency import resolve

Params = Sequence[Any]


@runtime_checkable
class AsyncDatabase(Protocol):
    async def execute(self, sql: str, params: Params = ()) -> int: ...

    async def fetch_one(self, sql: str, params: Params = ()) -> Sequence[Any] | None: ...

    async def fetch_all(self, sql: str, params: Params = ()) -> list[Sequence[Any]]: ...


class AsyncpgDatabase:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def execute(self, sql: str, params: Params = ()) -> int:
        status = await self._pool.execute(_numbered(sql), *params)
        count = status.rsplit(" ", 1)[-1]
        return int(count) if count.isdigit() else 0

    async def fetch_one(self, sql: str, params: Params = ()) -> Sequence[Any] | None:
        return await self._pool.fetchrow(_numbered(sql), *params)

    async def fetch_all(self, sql: str, params: Params = ()) -> list[Sequence[Any]]:
        return list(await self._pool.fetch(_numbered(sql), *params))


class AiosqliteDatabase:
    def __init__(self, connection: Any) -> None:
        self._conn = connection
        self._lock = asyncio.Lock()

    async def execute(self, sql: str, params: Params = ()) -> int:
        async with self._lock:
            cursor = await self._conn.execute(sql, tuple(params))
            await self._conn.commit()
            return cursor.rowcount

    async def fetch_one(self, sql: str, params: Params = ()) -> Sequence[Any] | None:
        async with self._lock:
            cursor = await self._conn.execute(sql, tuple(params))
            row = await cursor.fetchone()
            await cursor.close()
            await self._conn.commit()
            return row

    async def fetch_all(self, sql: str, params: Params = ()) -> list[Sequence[Any]]:
        async with self._lock:
            cursor = await self._conn.execute(sql, tuple(params))
            rows = await cursor.fetchall()
            await cursor.close()
            await self._conn.commit()
            return list(rows)


class LazyAsyncDatabase:
    def __init__(self, factory: Callable[[], Any]) -> None:
        self._factory = factory
        self._database: AsyncDatabase | None = None
        self._lock = asyncio.Lock()

    async def _resolved(self) -> AsyncDatabase:
        if self._database is None:
            async with self._lock:
                if self._database is None:
                    self._database = wrap_connection(await resolve(self._factory()))
        return self._database

    async def execute(self, sql: str, params: Params = ()) -> int:
        return await (await self._resolved()).execute(sql, params)

    async def fetch_one(self, sql: str, params: Params = ()) -> Sequence[Any] | None:
        return await (await self._resolved()).fetch_one(sql, params)

    async def fetch_all(self, sql: str, params: Params = ()) -> list[Sequence[Any]]:
        return await (await self._resolved()).fetch_all(sql, params)


def wrap_connection(connection: Any) -> AsyncDatabase:
    if hasattr(connection, "fetch_one"):
        return connection
    if hasattr(connection, "fetchrow"):
        return AsyncpgDatabase(connection)
    if hasattr(connection, "commit") and hasattr(connection, "execute"):
        return AiosqliteDatabase(connection)
    raise TypeError(f"Unsupported async database connection: {type(connection).__name__}")


def async_database(connection: Any) -> AsyncDatabase:
    try:
        return wrap_connection(connection)
    except TypeError:
        if callable(connection):
            return LazyAsyncDatabase(connection)
        raise


def _numbered(sql: str) -> str:
    counter = iter(range(1, sql.count("?") + 1))
    return re.sub(r"\?", lambda _: f"${next(counter)}", sql)
