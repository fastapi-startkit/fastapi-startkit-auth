from __future__ import annotations

from typing import Any, Callable

from ..concurrency import call, ensure_sync
from ..exceptions import InvalidGrant
from ..providers.base import active_user, active_user_async
from ..tokens.service import IssuedToken, TokenService

INACTIVE_OWNER = "The resource owner no longer exists or is not active."

OwnerProviderResolver = Callable[[Any], Any]


def owner_resolver(user_provider: Any, owner_provider: OwnerProviderResolver | None) -> OwnerProviderResolver:
    """Return a ``client_id -> provider`` lookup for owner re-checks.

    ``owner_provider`` resolves the provider that issued a token or code from
    its client; a bare ``user_provider`` serves every client (single-provider
    apps and direct construction).
    """
    if owner_provider is not None:
        return owner_provider
    return lambda client_id: user_provider


def ensure_owner_active(provider: Any, user_id: Any) -> None:
    if provider is not None and user_id is not None and active_user(provider, user_id) is None:
        raise InvalidGrant(INACTIVE_OWNER)


async def ensure_owner_active_async(provider: Any, user_id: Any) -> None:
    if provider is not None and user_id is not None and await active_user_async(provider, user_id) is None:
        raise InvalidGrant(INACTIVE_OWNER)


class RefreshTokenGrant:
    """Refresh-token grant (RFC 6749 §6) with rotation handled by TokenService."""

    def __init__(
        self,
        token_service: TokenService,
        user_provider: Any = None,
        owner_provider: OwnerProviderResolver | None = None,
    ) -> None:
        self._tokens = token_service
        self._owner_provider = owner_resolver(user_provider, owner_provider)

    def handle(
        self,
        *,
        refresh_token: str,
        scopes: list[str] | None,
        resource: str | None = None,
        client_id: str | None = None,
    ) -> IssuedToken:
        record = ensure_sync(self._tokens.repository.find_refresh_token(refresh_token), "find_refresh_token")
        if record is not None and record.active:
            ensure_owner_active(self._owner_provider(record.client_id), record.user_id)
        return self._tokens.refresh(refresh_token, scopes=scopes, resource=resource, client_id=client_id)


class AsyncRefreshTokenGrant:
    def __init__(
        self,
        token_service: Any,
        user_provider: Any = None,
        owner_provider: OwnerProviderResolver | None = None,
    ) -> None:
        self._tokens = token_service
        self._owner_provider = owner_resolver(user_provider, owner_provider)

    async def handle(
        self,
        *,
        refresh_token: str,
        scopes: list[str] | None,
        resource: str | None = None,
        client_id: str | None = None,
    ) -> IssuedToken:
        record = await call(self._tokens.repository.find_refresh_token, refresh_token)
        if record is not None and record.active:
            await ensure_owner_active_async(await call(self._owner_provider, record.client_id), record.user_id)
        return await call(self._tokens.refresh, refresh_token, scopes=scopes, resource=resource, client_id=client_id)
