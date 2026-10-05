from __future__ import annotations

from typing import Any

from ..clients.models import Client
from ..concurrency import call
from ..exceptions import UnauthorizedClient
from ..policy import GrantPolicy, ensure_client_may
from ..tokens.service import IssuedToken, TokenService


def _check(policy: GrantPolicy, client: Client, scopes: list[str], resource: str | None) -> None:
    # A public client has no secret, so anyone holding its id could mint tokens.
    if not client.confidential:
        raise UnauthorizedClient("Only confidential clients may use the client_credentials grant.")
    ensure_client_may(client, "client_credentials")
    policy.check_scopes(scopes)
    policy.check_resource(resource)


class ClientCredentialsGrant:
    """Machine-to-machine grant (RFC 6749 §4.4) for confidential clients. No user, no refresh token."""

    def __init__(self, token_service: TokenService, policy: GrantPolicy | None = None) -> None:
        self._tokens = token_service
        self._policy = policy or GrantPolicy()

    def handle(self, *, client: Client, scopes: list[str], resource: str | None = None) -> IssuedToken:
        _check(self._policy, client, scopes, resource)
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
        _check(self._policy, client, scopes, resource)
        return await call(
            self._tokens.issue,
            user_id=None,
            client_id=client.id,
            scopes=scopes,
            with_refresh=False,
            audience=resource,
        )
