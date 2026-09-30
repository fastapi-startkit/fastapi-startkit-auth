from __future__ import annotations

from typing import Any

from ..concurrency import call, ensure_sync
from ..exceptions import InvalidGrant
from ..providers.base import UserProvider, user_is_active, user_is_active_async
from ..tokens.service import IssuedToken, TokenService

_INVALID_CREDENTIALS = "The provided credentials are incorrect."


def _credentials(username: str, password: str) -> dict[str, str]:
    return {"username": username, "email": username, "password": password}


class PasswordGrant:
    """Resource-owner password credentials grant (RFC 6749 §4.3)."""

    def __init__(self, token_service: TokenService, user_provider: UserProvider) -> None:
        self._tokens = token_service
        self._users = user_provider

    def handle(self, *, username: str, password: str, scopes: list[str], client_id: str | None) -> IssuedToken:
        credentials = _credentials(username, password)
        user = ensure_sync(self._users.retrieve_by_credentials(credentials), "retrieve_by_credentials")
        if user is None:
            # Perform equivalent hashing work so response timing doesn't reveal
            # whether the account exists, then fail with the same generic error.
            dummy = getattr(self._users, "dummy_verify", None)
            if callable(dummy):
                ensure_sync(dummy(), "dummy_verify")
            raise InvalidGrant(_INVALID_CREDENTIALS)
        valid = ensure_sync(self._users.validate_credentials(user, credentials), "validate_credentials")
        if not valid or not user_is_active(self._users, user):
            raise InvalidGrant(_INVALID_CREDENTIALS)
        return self._tokens.issue(
            user_id=self._users.get_identifier(user),
            client_id=client_id,
            scopes=scopes,
            with_refresh=True,
        )


class AsyncPasswordGrant:
    def __init__(self, token_service: Any, user_provider: Any) -> None:
        self._tokens = token_service
        self._users = user_provider

    async def handle(self, *, username: str, password: str, scopes: list[str], client_id: str | None) -> IssuedToken:
        credentials = _credentials(username, password)
        user = await call(self._users.retrieve_by_credentials, credentials)
        if user is None:
            dummy = getattr(self._users, "dummy_verify", None)
            if callable(dummy):
                await call(dummy)
            raise InvalidGrant(_INVALID_CREDENTIALS)
        valid = await call(self._users.validate_credentials, user, credentials)
        if not valid or not await user_is_active_async(self._users, user):
            raise InvalidGrant(_INVALID_CREDENTIALS)
        return await call(
            self._tokens.issue,
            user_id=self._users.get_identifier(user),
            client_id=client_id,
            scopes=scopes,
            with_refresh=True,
        )
