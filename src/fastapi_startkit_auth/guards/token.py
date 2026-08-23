from __future__ import annotations

from fastapi import Request

from ..apitokens.manager import ApiTokenManager
from ..exceptions import InvalidToken
from ..providers.base import UserProvider
from .guard import AuthContext


class TokenGuard:
    """Opaque API-token guard (Sanctum-style).

    Corresponds to a ``{"driver": "token"}`` guard entry. Resolves
    ``Authorization: Bearer {id}|{secret}`` — or the raw token in a configured
    custom header — through :class:`ApiTokenManager` and turns the record's
    abilities into the ``AuthContext`` scopes, so ``require_scopes`` works
    unchanged.
    """

    def __init__(
        self,
        name: str,
        tokens: ApiTokenManager,
        provider: UserProvider,
        header: str = "Authorization",
    ) -> None:
        self.name = name
        self._tokens = tokens
        self.provider = provider
        self.header = header

    def authenticate(self, request: Request) -> AuthContext:
        """Resolve the request's configured token header to an ``AuthContext``."""
        token = self._extract(request)
        if not token:
            raise InvalidToken("Not authenticated.")
        return self.user_from_token(token)

    def user_from_token(self, access_token: str) -> AuthContext:
        record = self._tokens.verify(access_token)
        user = self.provider.retrieve_by_id(record.user_id)
        if user is None:
            # Orphaned token (user deleted): revoke it, fail generically.
            self._tokens.revoke(record.id)
            raise InvalidToken("The API token is invalid.")
        return AuthContext(user=user, scopes=list(record.abilities))

    def _extract(self, request: Request) -> str | None:
        raw = request.headers.get(self.header)
        if raw is None:
            return None
        if self.header.lower() == "authorization":
            scheme, _, value = raw.partition(" ")
            if scheme.lower() != "bearer":
                return None
            return value.strip()
        return raw.strip()
