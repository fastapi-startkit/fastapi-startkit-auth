from __future__ import annotations

from typing import Any

from ..clients.models import Client
from ..concurrency import call
from ..exceptions import InvalidCredentialsException
from ..policy import GrantPolicy
from ..providers.base import user_is_active
from ..tokens.service import IssuedToken

_INVALID_CREDENTIALS = "The provided credentials are incorrect."


def _credentials(username: str, password: str) -> dict[str, str]:
    return {"username": username, "email": username, "password": password}


def _check(policy: GrantPolicy, client: Client | None, scopes: list[str]) -> None:
    policy.check_scopes(scopes)
    if client is not None:
        policy.check_client_scopes(client, scopes)


class PasswordGrant:
    def __init__(
        self,
        token_service: Any,
        user_provider: Any,
        policy: GrantPolicy | None = None,
        client: Client | None = None,
    ) -> None:
        self._tokens = token_service
        self._users = user_provider
        self._policy = policy or GrantPolicy()
        self._client = client

    async def handle(self, *, username: str, password: str, scopes: list[str], client_id: str | None) -> IssuedToken:
        _check(self._policy, self._client, scopes)
        credentials = _credentials(username, password)
        user = await call(self._users.retrieve_by_credentials, credentials)
        if user is None:
            dummy = getattr(self._users, "dummy_verify", None)
            if callable(dummy):
                await call(dummy)
            raise InvalidCredentialsException(_INVALID_CREDENTIALS)
        valid = await call(self._users.validate_credentials, user, credentials)
        if not valid or not await user_is_active(self._users, user):
            raise InvalidCredentialsException(_INVALID_CREDENTIALS)
        return await call(
            self._tokens.issue,
            user_id=self._users.get_identifier(user),
            client_id=client_id,
            scopes=scopes,
            with_refresh=True,
        )
