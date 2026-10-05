from __future__ import annotations

import secrets
import uuid

from ..security.hashing import BcryptHasher, Hasher
from .models import Client


class InMemoryClientRepository:
    """Client registry with hashed-secret storage.

    ``register`` returns the plaintext secret exactly once (mirroring how real
    OAuth servers surface credentials); only its hash is retained.
    """

    def __init__(self, hasher: Hasher | None = None) -> None:
        self._hasher = hasher or BcryptHasher()
        self._clients: dict[str, Client] = {}

    def register(
        self,
        *,
        name: str,
        redirect_uris: list[str] | None = None,
        confidential: bool = True,
        grant_types: list[str] | None = None,
        provider: str | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[Client, str | None]:
        client_id = uuid.uuid4().hex
        plain_secret: str | None = None
        stored_secret: str | None = None
        if confidential:
            plain_secret = secrets.token_urlsafe(40)
            stored_secret = self._hasher.make(plain_secret)
        client = Client(
            id=client_id,
            name=name,
            secret=stored_secret,
            redirect_uris=list(redirect_uris or []),
            confidential=confidential,
            grant_types=list(grant_types or []),
            provider=provider,
            scopes=[] if scopes is None else scopes,
        )
        self._clients[client_id] = client
        return client, plain_secret

    def add(self, client: Client) -> Client:
        self._clients[client.id] = client
        return client

    def find(self, client_id: str) -> Client | None:
        return self._clients.get(client_id)

    def all(self) -> list[Client]:
        return list(self._clients.values())

    def authenticate(self, client_id: str, secret: str | None) -> Client | None:
        return verified_client(self._hasher, self._clients.get(client_id), secret)

    def revoke(self, client_id: str) -> bool:
        client = self._clients.get(client_id)
        if client is None:
            return False
        client.revoked = True
        return True

    def delete(self, client_id: str) -> bool:
        return self._clients.pop(client_id, None) is not None


def verified_client(hasher: Hasher, client: Client | None, secret: str | None) -> Client | None:
    if client is None or client.revoked:
        return None
    if not client.confidential:
        return client
    if secret is None or client.secret is None:
        return None
    return client if hasher.verify(secret, client.secret) else None
