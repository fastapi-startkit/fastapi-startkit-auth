from __future__ import annotations

import json
import secrets
import time
import uuid
from typing import Any

from starlette.concurrency import run_in_threadpool

from .. import orm
from ..security.hashing import BcryptHasher, Hasher
from .models import Client
from .repository import verified_client


class OrmClientRepository:
    """OAuth clients on the ``oauth_clients`` table; secrets are stored as bcrypt hashes only."""

    def __init__(self, connection: str | None = None, hasher: Hasher | None = None) -> None:
        self._connection = connection
        self._hasher = hasher or BcryptHasher()

    def _query(self) -> Any:
        return orm.query(orm.AuthClient, self._connection)

    async def register(
        self,
        *,
        name: str,
        redirect_uris: list[str] | None = None,
        confidential: bool = True,
        grant_types: list[str] | None = None,
        provider: str | None = None,
        scopes: list[str] | None = None,
        owner_id: Any | None = None,
    ) -> tuple[Client, str | None]:
        plain_secret = secrets.token_urlsafe(40) if confidential else None
        client = Client(
            id=uuid.uuid4().hex,
            name=name,
            secret=None if plain_secret is None else await run_in_threadpool(self._hasher.make, plain_secret),
            redirect_uris=list(redirect_uris or []),
            confidential=confidential,
            grant_types=list(grant_types or []),
            provider=provider,
            scopes=list(scopes or []),
            owner_id=owner_id,
        )
        return await self.add(client), plain_secret

    async def add(self, client: Client) -> Client:
        await self._query().insert(
            {
                "id": client.id,
                "name": client.name,
                "secret": client.secret,
                "redirect_uris": json.dumps(client.redirect_uris),
                "confidential": client.confidential,
                "grant_types": json.dumps(client.grant_types),
                "scopes": json.dumps(client.scopes),
                "provider": client.provider,
                "owner_id": None if client.owner_id is None else json.dumps(client.owner_id),
                "revoked": client.revoked,
                "created_at": time.time(),
            }
        )
        return client

    async def find(self, client_id: str) -> Client | None:
        row = await self._query().where("id", client_id).first()
        return None if row is None else _client(orm.attributes(row))

    async def all(self) -> list[Client]:
        rows = await self._query().order_by("created_at").get()
        return [_client(orm.attributes(row)) for row in rows]

    async def authenticate(self, client_id: str, secret: str | None) -> Client | None:
        client = await self.find(client_id)
        return await run_in_threadpool(verified_client, self._hasher, client, secret)

    async def revoke(self, client_id: str) -> bool:
        return await self._query().where("id", client_id).update({"revoked": True}) > 0

    async def delete(self, client_id: str) -> bool:
        return await self._query().where("id", client_id).delete() > 0


def _client(row: dict[str, Any]) -> Client:
    return Client(
        id=row["id"],
        name=row["name"],
        secret=row["secret"],
        redirect_uris=json.loads(row["redirect_uris"]),
        confidential=bool(row["confidential"]),
        grant_types=json.loads(row["grant_types"]),
        scopes=json.loads(row["scopes"]),
        provider=row["provider"],
        owner_id=None if row["owner_id"] is None else json.loads(row["owner_id"]),
        revoked=bool(row["revoked"]),
    )
