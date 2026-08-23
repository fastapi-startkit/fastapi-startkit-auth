from __future__ import annotations

import json
import threading
import time
from typing import Any

from .models import ApiTokenRecord
from .repository import generate_token_id

_SCHEMA = """
CREATE TABLE IF NOT EXISTS {table} (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    token_hash TEXT NOT NULL,
    name TEXT,
    abilities TEXT NOT NULL,
    last_used_at REAL,
    expires_at REAL,
    created_at REAL NOT NULL
)
"""

_COLUMNS = "id, user_id, token_hash, name, abilities, last_used_at, expires_at, created_at"


class SqlApiTokenRepository:
    """Persistent :class:`~.repository.ApiTokenRepository` backed by a
    ``personal_api_tokens`` table.

    Works with any DB-API 2.0 connection using ``qmark`` placeholders (sqlite3
    out of the box). ``user_id`` and ``abilities`` are JSON-encoded so
    identifier types and ability lists round-trip exactly, matching the
    in-memory repository. A lock serialises access because FastAPI runs sync
    endpoints in a thread pool.
    """

    def __init__(
        self,
        connection: Any,
        table: str = "personal_api_tokens",
        create_table: bool = True,
    ) -> None:
        self._conn = connection
        self._table = table
        self._lock = threading.Lock()
        if create_table:
            with self._lock:
                self._conn.execute(_SCHEMA.format(table=table))
                self._conn.commit()

    def create(
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
        with self._lock:
            self._conn.execute(
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
            self._conn.commit()
        return record

    def find(self, token_id: str) -> ApiTokenRecord | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_COLUMNS} FROM {self._table} WHERE id = ?", (token_id,)
            ).fetchone()
        if row is None:
            return None
        record = self._to_record(row)
        if record.expired:
            self.revoke(token_id)
            return None
        return record

    def touch(self, token_id: str) -> None:
        with self._lock:
            self._conn.execute(
                f"UPDATE {self._table} SET last_used_at = ? WHERE id = ?",
                (time.time(), token_id),
            )
            self._conn.commit()

    def revoke(self, token_id: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                f"DELETE FROM {self._table} WHERE id = ?", (token_id,)
            )
            self._conn.commit()
        return cursor.rowcount > 0

    def revoke_all_for_user(self, user_id: Any) -> int:
        with self._lock:
            cursor = self._conn.execute(
                f"DELETE FROM {self._table} WHERE user_id = ?", (json.dumps(user_id),)
            )
            self._conn.commit()
        return cursor.rowcount

    def list_for_user(self, user_id: Any) -> list[ApiTokenRecord]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_COLUMNS} FROM {self._table} "
                "WHERE user_id = ? AND (expires_at IS NULL OR expires_at >= ?)",
                (json.dumps(user_id), now),
            ).fetchall()
        return [self._to_record(row) for row in rows]

    def purge_expired(self) -> None:
        with self._lock:
            self._conn.execute(
                f"DELETE FROM {self._table} WHERE expires_at IS NOT NULL AND expires_at < ?",
                (time.time(),),
            )
            self._conn.commit()

    @staticmethod
    def _to_record(row: Any) -> ApiTokenRecord:
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
