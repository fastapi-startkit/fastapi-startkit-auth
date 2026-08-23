from __future__ import annotations

import json
import threading
import time
from typing import Any

from .models import SessionRecord
from .store import generate_csrf_token, generate_session_id

_SCHEMA = """
CREATE TABLE IF NOT EXISTS {table} (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    guard TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_activity REAL NOT NULL,
    expires_at REAL
)
"""


class SqlSessionStore:
    """Persistent :class:`~.store.SessionStore` backed by a ``sessions`` table.

    Works with any DB-API 2.0 connection using ``qmark`` placeholders (sqlite3
    out of the box). ``user_id`` is JSON-encoded so int and str identifiers
    round-trip with their original type, matching the in-memory store. A lock
    serialises access because FastAPI runs sync endpoints in a thread pool.
    """

    def __init__(
        self,
        connection: Any,
        table: str = "sessions",
        idle_ttl: float | None = None,
        create_table: bool = True,
        purge_interval: float = 300,
    ) -> None:
        self._conn = connection
        self._table = table
        self._idle_ttl = idle_ttl
        self._lock = threading.Lock()
        self._purge_interval = purge_interval
        self._last_purge = time.time()
        if create_table:
            with self._lock:
                self._conn.execute(_SCHEMA.format(table=table))
                self._conn.commit()

    def _maybe_purge(self) -> None:
        """Drop expired rows periodically so the table stays bounded without a
        scheduler (mirrors ``TokenService``'s purge-on-issue)."""
        now = time.time()
        # Check-and-update under the lock so concurrent creates cannot both
        # claim the same purge window and sweep twice.
        with self._lock:
            if now - self._last_purge < self._purge_interval:
                return
            self._last_purge = now
        self.purge_expired()

    def create(self, *, user_id: Any, guard: str, ttl: float | None) -> SessionRecord:
        self._maybe_purge()
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
        with self._lock:
            self._conn.execute(
                f"INSERT INTO {self._table} (id, user_id, guard, csrf_token, created_at, last_activity, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
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
            self._conn.commit()
        return record

    def find(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT id, user_id, guard, csrf_token, created_at, last_activity, expires_at "
                f"FROM {self._table} WHERE id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        record = SessionRecord(
            id=row[0],
            user_id=json.loads(row[1]),
            guard=row[2],
            csrf_token=row[3],
            created_at=row[4],
            last_activity=row[5],
            expires_at=row[6],
        )
        if record.expired(self._idle_ttl):
            self.invalidate(session_id)
            return None
        return record

    def touch(self, session_id: str) -> None:
        with self._lock:
            self._conn.execute(
                f"UPDATE {self._table} SET last_activity = ? WHERE id = ?",
                (time.time(), session_id),
            )
            self._conn.commit()

    def regenerate_id(self, session_id: str) -> SessionRecord | None:
        record = self.find(session_id)
        if record is None:
            return None
        new_id = generate_session_id()
        with self._lock:
            self._conn.execute(
                f"UPDATE {self._table} SET id = ? WHERE id = ?",
                (new_id, session_id),
            )
            self._conn.commit()
        record.id = new_id
        return record

    def invalidate(self, session_id: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                f"DELETE FROM {self._table} WHERE id = ?", (session_id,)
            )
            self._conn.commit()
        return cursor.rowcount > 0

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                f"DELETE FROM {self._table} WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            if self._idle_ttl is not None:
                self._conn.execute(
                    f"DELETE FROM {self._table} WHERE last_activity + ? < ?",
                    (self._idle_ttl, now),
                )
            self._conn.commit()
