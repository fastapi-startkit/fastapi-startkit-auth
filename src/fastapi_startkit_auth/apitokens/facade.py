from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Depends, Request

from ..concurrency import call
from ..dependencies import get_auth_manager
from ..scoped_method import ScopedMethod
from .manager import NewApiToken
from .models import ApiTokenRecord

if TYPE_CHECKING:
    from ..manager import AuthManager


class ApiToken:
    """Issue and revoke opaque API tokens; awaitable for sync and async token stores alike."""

    def __init__(self, manager: AuthManager, request: Request | None = None) -> None:
        self._manager = manager
        self._request = request

    @classmethod
    def scoped(cls, request: Request, manager: AuthManager = Depends(get_auth_manager)) -> ApiToken:
        return cls(manager, request)

    @ScopedMethod
    async def create(
        self,
        user_or_id: Any,
        name: str | None = None,
        abilities: list[str] | None = None,
        expires_at: float | None = None,
        guard: str | None = None,
    ) -> NewApiToken:
        return await call(
            self._manager.api_tokens.create,
            self._user_id(user_or_id, guard),
            name=name,
            abilities=abilities,
            expires_at=expires_at,
        )

    @ScopedMethod
    async def tokens(self, user_or_id: Any, guard: str | None = None) -> list[ApiTokenRecord]:
        return await call(self._manager.api_tokens.tokens_for, self._user_id(user_or_id, guard))

    @ScopedMethod
    async def revoke(self, token_id: str) -> bool:
        return await call(self._manager.api_tokens.revoke, token_id)

    @ScopedMethod
    async def revoke_all(self, user_or_id: Any, guard: str | None = None) -> int:
        return await call(self._manager.api_tokens.revoke_all, self._user_id(user_or_id, guard))

    def _user_id(self, user_or_id: Any, guard: str | None) -> Any:
        if isinstance(user_or_id, (int, str)):
            return user_or_id
        resolved = self._manager.guard(guard) if guard else self._manager.guard_for_driver("token")
        if resolved is None:
            raise RuntimeError('ApiToken needs a {"driver": "token"} guard to identify users; pass a user id instead.')
        return resolved.provider.get_identifier(user_or_id)
