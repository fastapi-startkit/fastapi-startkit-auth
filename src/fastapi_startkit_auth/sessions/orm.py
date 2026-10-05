from __future__ import annotations

import json
import time
from typing import Any

from .. import orm
from .models import SessionRecord
from .store import generate_session_id, new_session_record


class OrmSessionStore:
    """Session store on the ``sessions`` table created by the published migrations."""

    def __init__(
        self,
        connection: str | None = None,
        idle_ttl: float | None = None,
        purge_interval: float = 300,
    ) -> None:
        self._connection = connection
        self._idle_ttl = idle_ttl
        self._purge_interval = purge_interval
        self._last_purge = time.time()

    def _query(self) -> Any:
        return orm.query(orm.AuthSession, self._connection)

    async def _maybe_purge(self) -> None:
        now = time.time()
        if now - self._last_purge < self._purge_interval:
            return
        self._last_purge = now
        await self.purge_expired()

    async def create(self, *, user_id: Any, guard: str, ttl: float | None) -> SessionRecord:
        record = new_session_record(user_id=user_id, guard=guard, ttl=ttl)
        await self.save(record)
        return record

    async def save(self, record: SessionRecord) -> None:
        await self._maybe_purge()
        await self._query().insert(
            {
                "id": record.id,
                "user_id": json.dumps(record.user_id),
                "guard": record.guard,
                "csrf_token": record.csrf_token,
                "created_at": record.created_at,
                "last_activity": record.last_activity,
                "expires_at": record.expires_at,
            }
        )

    async def find(self, session_id: str) -> SessionRecord | None:
        row = await self._query().where("id", session_id).first()
        if row is None:
            return None
        record = _to_record(orm.attributes(row))
        if record.expired(self._idle_ttl):
            await self.invalidate(session_id)
            return None
        return record

    async def touch(self, session_id: str) -> None:
        await self._query().where("id", session_id).update({"last_activity": time.time()})

    async def regenerate_id(self, session_id: str) -> SessionRecord | None:
        record = await self.find(session_id)
        if record is None:
            return None
        new_id = generate_session_id()
        await self._query().where("id", session_id).update({"id": new_id})
        record.id = new_id
        return record

    async def invalidate(self, session_id: str) -> bool:
        return await self._query().where("id", session_id).delete() > 0

    async def purge_expired(self) -> None:
        now = time.time()
        await self._query().where("expires_at", "<", now).delete()
        if self._idle_ttl is not None:
            await self._query().where("last_activity", "<", now - self._idle_ttl).delete()


def _to_record(row: dict[str, Any]) -> SessionRecord:
    return SessionRecord(
        id=row["id"],
        user_id=json.loads(row["user_id"]),
        guard=row["guard"],
        csrf_token=row["csrf_token"],
        created_at=row["created_at"],
        last_activity=row["last_activity"],
        expires_at=row["expires_at"],
    )
