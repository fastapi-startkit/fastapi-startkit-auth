from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Request

from ..exceptions import AuthenticationException, InvalidTokenException
from ..concurrency import call
from ..providers.base import user_is_active
from .guard import AuthContext


def _extract_token(request: Request, header: str) -> str | None:
    raw = request.headers.get(header)
    if raw is None:
        return None
    if header.lower() == "authorization":
        scheme, _, value = raw.partition(" ")
        if scheme.lower() != "bearer":
            return None
        return value.strip()
    return raw.strip()


class TokenGuard:
    def __init__(
        self,
        name: str,
        tokens: Any,
        provider: Any,
        header: str = "Authorization",
        session_guard: Callable[[], Any] | None = None,
    ) -> None:
        self.name = name
        self._tokens = tokens
        self.provider = provider
        self.header = header
        self._session_guard = session_guard

    async def authenticate(self, request: Request) -> AuthContext:
        if self._session_guard is not None:
            try:
                return await call(self._session_guard().authenticate, request)
            except AuthenticationException:
                pass
        token = _extract_token(request, self.header)
        if not token:
            raise AuthenticationException("Not authenticated.")
        return await self.user_from_token(token)

    def presented_token(self, request: Request) -> str | None:
        return _extract_token(request, self.header) or None

    async def user_from_token(self, access_token: str) -> AuthContext:
        record = await call(self._tokens.verify, access_token)
        user = await call(self.provider.retrieve_by_id, record.user_id)
        if user is None:
            await call(self._tokens.revoke, record.id)
            raise InvalidTokenException("The API token is invalid.")
        if not await user_is_active(self.provider, user):
            raise InvalidTokenException("The API token is invalid.")
        return AuthContext(user=user, scopes=list(record.abilities), jti=record.id)
