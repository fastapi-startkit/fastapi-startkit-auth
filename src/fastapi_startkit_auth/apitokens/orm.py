from __future__ import annotations

import json
import time
from typing import Any

from .. import orm
from .models import ApiTokenRecord
from .repository import generate_token_id


class OrmApiTokenRepository:
    """Personal API tokens on the ``personal_api_tokens`` table created by the published migrations."""

    def __init__(self, connection: str | None = None) -> None:
        self._connection = connection

    def _query(self) -> Any:
        return orm.query(orm.AuthApiToken, self._connection)

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
        await self._query().insert(
            {
                "id": record.id,
                "user_id": json.dumps(record.user_id),
                "token_hash": record.token_hash,
                "name": record.name,
                "abilities": json.dumps(record.abilities),
                "last_used_at": record.last_used_at,
                "expires_at": record.expires_at,
                "created_at": record.created_at,
            }
        )
        return record

    async def find(self, token_id: str) -> ApiTokenRecord | None:
        row = await self._query().where("id", token_id).first()
        if row is None:
            return None
        record = _to_record(orm.attributes(row))
        if record.expired:
            await self.revoke(token_id)
            return None
        return record

    async def touch(self, token_id: str) -> None:
        await self._query().where("id", token_id).update({"last_used_at": time.time()})

    async def revoke(self, token_id: str) -> bool:
        return await self._query().where("id", token_id).delete() > 0

    async def revoke_all_for_user(self, user_id: Any) -> int:
        return await self._query().where("user_id", json.dumps(user_id)).delete()

    async def list_for_user(self, user_id: Any) -> list[ApiTokenRecord]:
        now = time.time()
        rows = await (
            self._query()
            .where("user_id", json.dumps(user_id))
            .where(lambda q: q.where_null("expires_at").or_where("expires_at", ">=", now))
            .order_by("created_at")
            .get()
        )
        return [_to_record(orm.attributes(row)) for row in rows]

    async def purge_expired(self) -> None:
        await self._query().where("expires_at", "<", time.time()).delete()


def _to_record(row: dict[str, Any]) -> ApiTokenRecord:
    return ApiTokenRecord(
        id=row["id"],
        user_id=json.loads(row["user_id"]),
        token_hash=row["token_hash"],
        name=row["name"],
        abilities=json.loads(row["abilities"]),
        last_used_at=row["last_used_at"],
        expires_at=row["expires_at"],
        created_at=row["created_at"],
    )
