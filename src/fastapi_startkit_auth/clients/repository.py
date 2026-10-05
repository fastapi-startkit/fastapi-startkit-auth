from __future__ import annotations

from ..security.hashing import BcryptHasher, Hasher
from .credentials import new_client, verified_client
from .models import Client


class InMemoryClientRepository:
    """Client registry with hashed-secret storage.

    ``register`` returns the plaintext secret exactly once (mirroring how real
    OAuth servers surface credentials); only its hash is retained.
    """

    def __init__(self, hasher: Hasher | None = None) -> None:
        self._hasher = hasher or BcryptHasher()
        self._clients: dict[str, Client] = {}

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
        client, secret = await new_client(
            self._hasher,
            name=name,
            redirect_uris=redirect_uris,
            confidential=confidential,
            grant_types=grant_types,
            provider=provider,
            scopes=scopes,
        )
        return await self.add(client), secret

    async def add(self, client: Client) -> Client:
        self._clients[client.id] = client
        return client

    async def find(self, client_id: str) -> Client | None:
        return self._clients.get(client_id)

    async def all(self) -> list[Client]:
        return list(self._clients.values())

    async def authenticate(self, client_id: str, secret: str | None) -> Client | None:
        return await verified_client(self._hasher, self._clients.get(client_id), secret)

    async def revoke(self, client_id: str) -> bool:
        client = self._clients.get(client_id)
        if client is None:
            return False
        client.revoked = True
        return True

    async def delete(self, client_id: str) -> bool:
        return self._clients.pop(client_id, None) is not None
