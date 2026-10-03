from __future__ import annotations

from typing import Any

from ..clients.models import Client
from ..concurrency import call
from ..policy import GrantPolicy
from ..tokens.service import IssuedToken, TokenService


class ClientCredentialsGrant:
    """Machine-to-machine grant (RFC 6749 §4.4). No user, no refresh token."""

    def __init__(self, token_service: TokenService, policy: GrantPolicy | None = None) -> None:
        self._tokens = token_service
        self._policy = policy or GrantPolicy()

    def handle(self, *, client: Client, scopes: list[str], resource: str | None = None) -> IssuedToken:
        self._policy.check_scopes(scopes)
        self._policy.check_client_scopes(client, scopes)
        self._policy.check_resource(resource)
        return self._tokens.issue(
            user_id=None,
            client_id=client.id,
            scopes=scopes,
            with_refresh=False,
            audience=resource,
        )


class AsyncClientCredentialsGrant:
    def __init__(self, token_service: Any, policy: GrantPolicy | None = None) -> None:
        self._tokens = token_service
        self._policy = policy or GrantPolicy()

    async def handle(self, *, client: Client, scopes: list[str], resource: str | None = None) -> IssuedToken:
        self._policy.check_scopes(scopes)
        self._policy.check_client_scopes(client, scopes)
        self._policy.check_resource(resource)
        return await call(
            self._tokens.issue,
            user_id=None,
            client_id=client.id,
            scopes=scopes,
            with_refresh=False,
            audience=resource,
        )
