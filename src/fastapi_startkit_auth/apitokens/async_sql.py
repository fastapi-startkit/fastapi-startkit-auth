from __future__ import annotations

import json
import time
from typing import Any, Sequence

from ..database import async_database
from .models import ApiTokenRecord
from .repository import generate_token_id

_COLUMNS = "id, user_id, token_hash, name, abilities, last_used_at, expires_at, created_at"


def api_token_table_ddl(table: str) -> list[str]:
    return [
        f"CREATE TABLE IF NOT EXISTS {table} ("
        "id VARCHAR(255) PRIMARY KEY, "
        "user_id TEXT, "
        "token_hash VARCHAR(255) NOT NULL, "
        "name VARCHAR(255), "
        "abilities TEXT NOT NULL, "
        "last_used_at DOUBLE PRECISION, "
        "expires_at DOUBLE PRECISION, "
        "created_at DOUBLE PRECISION NOT NULL)",
        f"CREATE INDEX IF NOT EXISTS {table}_user_id_index ON {table} (user_id)",
    ]


class AsyncSqlApiTokenRepository:
    def __init__(self, connection: Any, table: str = "personal_api_tokens") -> None:
        self._db = async_database(connection)
        self._table = table

    async def create_table(self) -> None:
        for statement in api_token_table_ddl(self._table):
            await self._db.execute(statement)

    async def create(
        self,
        *,
        user_id: Any,
        token_hash: str,
        name: str | None,
        abilities: list[str],
        expires_at: float | None,
    ) -> ApiTokenRecord:
        record = ApiTokenRecord(
            id=generate_token_id(),
            user_id=user_id,
            token_hash=token_hash,
            name=name,
            abilities=list(abilities),
            expires_at=expires_at,
        )
        await self._db.execute(
            f"INSERT INTO {self._table} ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.id,
                json.dumps(record.user_id),
                record.token_hash,
                record.name,
                json.dumps(record.abilities),
                record.last_used_at,
                record.expires_at,
                record.created_at,
            ),
        )
        return record

    async def find(self, token_id: str) -> ApiTokenRecord | None:
        row = await self._db.fetch_one(f"SELECT {_COLUMNS} FROM {self._table} WHERE id = ?", (token_id,))
        if row is None:
            return None
        record = _to_record(row)
        if record.expired:
            await self.revoke(token_id)
            return None
        return record

    async def touch(self, token_id: str) -> None:
        await self._db.execute(
            f"UPDATE {self._table} SET last_used_at = ? WHERE id = ?",
            (time.time(), token_id),
        )

    async def revoke(self, token_id: str) -> bool:
        return await self._db.execute(f"DELETE FROM {self._table} WHERE id = ?", (token_id,)) > 0

    async def revoke_all_for_user(self, user_id: Any) -> int:
        return await self._db.execute(f"DELETE FROM {self._table} WHERE user_id = ?", (json.dumps(user_id),))

    async def list_for_user(self, user_id: Any) -> list[ApiTokenRecord]:
        rows = await self._db.fetch_all(
            f"SELECT {_COLUMNS} FROM {self._table} "
            "WHERE user_id = ? AND (expires_at IS NULL OR expires_at >= ?) ORDER BY created_at",
            (json.dumps(user_id), time.time()),
        )
        return [_to_record(row) for row in rows]

    async def purge_expired(self) -> None:
        await self._db.execute(
            f"DELETE FROM {self._table} WHERE expires_at IS NOT NULL AND expires_at < ?",
            (time.time(),),
        )


def _to_record(row: Sequence[Any]) -> ApiTokenRecord:
    return ApiTokenRecord(
        id=row[0],
        user_id=json.loads(row[1]),
        token_hash=row[2],
        name=row[3],
        abilities=json.loads(row[4]),
        last_used_at=row[5],
        expires_at=row[6],
        created_at=row[7],
    )
