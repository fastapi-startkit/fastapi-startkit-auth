from __future__ import annotations

from typing import Any

from ..clients.models import Client
from ..concurrency import call
from ..tokens.service import IssuedToken, TokenService


class ClientCredentialsGrant:
    """Machine-to-machine grant (RFC 6749 §4.4). No user, no refresh token."""

    def __init__(self, token_service: TokenService) -> None:
        self._tokens = token_service

    def handle(self, *, client: Client, scopes: list[str]) -> IssuedToken:
        return self._tokens.issue(
            user_id=None,
            client_id=client.id,
            scopes=scopes,
            with_refresh=False,
        )


class AsyncClientCredentialsGrant:
    def __init__(self, token_service: Any) -> None:
        self._tokens = token_service

    async def handle(self, *, client: Client, scopes: list[str]) -> IssuedToken:
        return await call(self._tokens.issue, user_id=None, client_id=client.id, scopes=scopes, with_refresh=False)
