from __future__ import annotations

import json
import time
from typing import Any

from starlette.concurrency import run_in_threadpool

from .. import orm
from ..security.hashing import BcryptHasher, Hasher
from .models import Client
from .repository import InMemoryClientRepository, verified_client


class OrmClientRepository:
    """OAuth clients on the ``oauth_clients`` table; secrets are stored as bcrypt hashes."""

    def __init__(self, connection: str | None = None, hasher: Hasher | None = None) -> None:
        self._connection = connection
        self._hasher = hasher or BcryptHasher()

    def _clients(self) -> Any:
        return orm.query(orm.AuthOAuthClient, self._connection)

    async def register(
        self,
        *,
        name: str,
        redirect_uris: list[str] | None = None,
        confidential: bool = True,
        grant_types: list[str] | None = None,
        provider: str | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[Client, str | None]:
        client, secret = await run_in_threadpool(
            lambda: InMemoryClientRepository(self._hasher).register(
                name=name,
                redirect_uris=redirect_uris,
                confidential=confidential,
                grant_types=grant_types,
                provider=provider,
                scopes=scopes,
            )
        )
        await self.add(client)
        return client, secret

    async def add(self, client: Client) -> Client:
        await self._clients().insert(
            {
                "id": client.id,
                "name": client.name,
                "secret": client.secret,
                "redirect_uris": json.dumps(client.redirect_uris),
                "confidential": client.confidential,
                "grant_types": json.dumps(client.grant_types),
                "scopes": json.dumps(client.scopes),
                "revoked": client.revoked,
                "provider": client.provider,
                "created_at": time.time(),
            }
        )
        return client

    async def find(self, client_id: str) -> Client | None:
        row = await self._clients().where("id", client_id).first()
        return None if row is None else _client(orm.attributes(row))

    async def all(self) -> list[Client]:
        rows = await self._clients().order_by("created_at").get()
        return [_client(orm.attributes(row)) for row in rows]

    async def authenticate(self, client_id: str, secret: str | None) -> Client | None:
        client = await self.find(client_id)
        # bcrypt is deliberately slow; keep it off the event loop.
        return await run_in_threadpool(verified_client, self._hasher, client, secret)

    async def revoke(self, client_id: str) -> bool:
        return await self._clients().where("id", client_id).update({"revoked": True}) > 0

    async def delete(self, client_id: str) -> bool:
        return await self._clients().where("id", client_id).delete() > 0


def _client(row: dict[str, Any]) -> Client:
    return Client(
        id=row["id"],
        name=row["name"],
        secret=row["secret"],
        redirect_uris=json.loads(row["redirect_uris"]),
        confidential=bool(row["confidential"]),
        grant_types=json.loads(row["grant_types"]),
        # Rows written before the add_scopes migration hold NULL: unrestricted.
        scopes=json.loads(row.get("scopes") or "[]"),
        revoked=bool(row["revoked"]),
        provider=row.get("provider"),
    )
