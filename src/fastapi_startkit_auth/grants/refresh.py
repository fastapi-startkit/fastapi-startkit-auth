from __future__ import annotations

from typing import Any

from ..concurrency import resolve
from ..tokens.service import IssuedToken, TokenService


class RefreshTokenGrant:
    """Refresh-token grant (RFC 6749 §6) with rotation handled by TokenService."""

    def __init__(self, token_service: TokenService) -> None:
        self._tokens = token_service

    def handle(self, *, refresh_token: str, scopes: list[str] | None) -> IssuedToken:
        return self._tokens.refresh(refresh_token, scopes=scopes)


class AsyncRefreshTokenGrant:
    def __init__(self, token_service: Any) -> None:
        self._tokens = token_service

    async def handle(self, *, refresh_token: str, scopes: list[str] | None) -> IssuedToken:
        return await resolve(self._tokens.refresh(refresh_token, scopes=scopes))
