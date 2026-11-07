from __future__ import annotations

from typing import Any, Callable

from ..concurrency import call
from ..exceptions import InvalidGrantException
from ..providers.base import active_user
from ..tokens.service import IssuedToken

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


def ensure_issued_to(record: Any, client_id: str | None) -> None:
    if record.client_id != client_id:
        raise InvalidGrantException("The refresh token was not issued to this client.")


async def ensure_owner_active(provider: Any, user_id: Any) -> None:
    if provider is not None and user_id is not None and await active_user(provider, user_id) is None:
        raise InvalidGrantException(INACTIVE_OWNER)


class RefreshTokenGrant:
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
            ensure_issued_to(record, client_id)
            await ensure_owner_active(await call(self._owner_provider, record.client_id), record.user_id)
        return await call(self._tokens.refresh, refresh_token, scopes=scopes, resource=resource, client_id=client_id)
