from __future__ import annotations

from ..exceptions import InvalidGrant
from ..providers.base import UserProvider
from ..tokens.service import IssuedToken, TokenService


class PasswordGrant:
    """Resource-owner password credentials grant (RFC 6749 §4.3)."""

    def __init__(self, token_service: TokenService, user_provider: UserProvider) -> None:
        self._tokens = token_service
        self._users = user_provider

    def handle(self, *, username: str, password: str, scopes: list[str], client_id: str | None) -> IssuedToken:
        credentials = {"username": username, "email": username, "password": password}
        user = self._users.retrieve_by_credentials(credentials)
        if user is None:
            # Perform equivalent hashing work so response timing doesn't reveal
            # whether the account exists, then fail with the same generic error.
            dummy = getattr(self._users, "dummy_verify", None)
            if callable(dummy):
                dummy()
            raise InvalidGrant("The provided credentials are incorrect.")
        if not self._users.validate_credentials(user, credentials):
            raise InvalidGrant("The provided credentials are incorrect.")
        return self._tokens.issue(
            user_id=self._users.get_identifier(user),
            client_id=client_id,
            scopes=scopes,
            with_refresh=True,
        )
