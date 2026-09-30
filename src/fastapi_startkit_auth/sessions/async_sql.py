from __future__ import annotations

import json
import time
from typing import Any, Sequence

from ..database import async_database
from .models import SessionRecord
from .store import generate_csrf_token, generate_session_id

_COLUMNS = "id, user_id, guard, csrf_token, created_at, last_activity, expires_at"


def session_table_ddl(table: str) -> list[str]:
    return [
        f"CREATE TABLE IF NOT EXISTS {table} ("
        "id VARCHAR(255) PRIMARY KEY, "
        "user_id TEXT, "
        "guard VARCHAR(255) NOT NULL, "
        "csrf_token VARCHAR(255) NOT NULL, "
        "created_at DOUBLE PRECISION NOT NULL, "
        "last_activity DOUBLE PRECISION NOT NULL, "
        "expires_at DOUBLE PRECISION)",
        f"CREATE INDEX IF NOT EXISTS {table}_expires_at_index ON {table} (expires_at)",
    ]


class AsyncSqlSessionStore:
    def __init__(
        self,
        connection: Any,
        table: str = "sessions",
        idle_ttl: float | None = None,
        purge_interval: float = 300,
    ) -> None:
        self._db = async_database(connection)
        self._table = table
        self._idle_ttl = idle_ttl
        self._purge_interval = purge_interval
        self._last_purge = time.time()

    async def create_table(self) -> None:
        for statement in session_table_ddl(self._table):
            await self._db.execute(statement)

    async def _maybe_purge(self) -> None:
        now = time.time()
        if now - self._last_purge < self._purge_interval:
            return
        self._last_purge = now
        await self.purge_expired()

    async def create(self, *, user_id: Any, guard: str, ttl: float | None) -> SessionRecord:
        await self._maybe_purge()
        now = time.time()
        record = SessionRecord(
            id=generate_session_id(),
            user_id=user_id,
            guard=guard,
            csrf_token=generate_csrf_token(),
            created_at=now,
            last_activity=now,
            expires_at=(now + ttl) if ttl is not None else None,
        )
        await self._db.execute(
            f"INSERT INTO {self._table} ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.id,
                json.dumps(record.user_id),
                record.guard,
                record.csrf_token,
                record.created_at,
                record.last_activity,
                record.expires_at,
            ),
        )
        return record

    async def find(self, session_id: str) -> SessionRecord | None:
        row = await self._db.fetch_one(f"SELECT {_COLUMNS} FROM {self._table} WHERE id = ?", (session_id,))
        if row is None:
            return None
        record = _to_record(row)
        if record.expired(self._idle_ttl):
            await self.invalidate(session_id)
            return None
        return record

    async def touch(self, session_id: str) -> None:
        await self._db.execute(
            f"UPDATE {self._table} SET last_activity = ? WHERE id = ?",
            (time.time(), session_id),
        )

    async def regenerate_id(self, session_id: str) -> SessionRecord | None:
        record = await self.find(session_id)
        if record is None:
            return None
        new_id = generate_session_id()
        await self._db.execute(f"UPDATE {self._table} SET id = ? WHERE id = ?", (new_id, session_id))
        record.id = new_id
        return record

    async def invalidate(self, session_id: str) -> bool:
        return await self._db.execute(f"DELETE FROM {self._table} WHERE id = ?", (session_id,)) > 0

    async def purge_expired(self) -> None:
        now = time.time()
        await self._db.execute(
            f"DELETE FROM {self._table} WHERE expires_at IS NOT NULL AND expires_at < ?",
            (now,),
        )
        if self._idle_ttl is not None:
            await self._db.execute(
                f"DELETE FROM {self._table} WHERE last_activity < ?",
                (now - self._idle_ttl,),
            )


def _to_record(row: Sequence[Any]) -> SessionRecord:
    return SessionRecord(
        id=row[0],
        user_id=json.loads(row[1]),
        guard=row[2],
        csrf_token=row[3],
        created_at=row[4],
        last_activity=row[5],
        expires_at=row[6],
    )
