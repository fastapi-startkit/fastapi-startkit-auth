from __future__ import annotations

from typing import Any

from fastapi import Depends, Request

from .dependencies import GuardDependency, get_auth_manager, resolve_context
from .concurrency import call
from .exceptions import AuthException
from .guards.session import SessionGuard
from .manager import AuthManager
from .providers.base import user_is_active
from .scoped_method import ScopedMethod
from .sessions.models import SessionRecord


class GuardAccessor:
    """``Auth.guard(name)`` is a FastAPI dependency; ``auth.guard(name)`` on an instance is the guard itself."""

    def __get__(self, instance: Any, owner: type) -> Any:
        if instance is None:
            return GuardDependency
        return instance._manager.guard


class Auth:
    def __init__(self, manager: AuthManager, request: Request) -> None:
        self._manager = manager
        self._request = request

    @classmethod
    def scoped(cls, request: Request, manager: AuthManager = Depends(get_auth_manager)) -> "Auth":
        return cls(manager, request)

    guard = GuardAccessor()

    @ScopedMethod
    async def login(self, user_or_id: Any, guard: str | None = None) -> SessionRecord:
        session_guard = self._session_guard(guard)
        user = await self._resolve_user(user_or_id, session_guard)
        return await call(session_guard.login, self._request, user)

    @ScopedMethod
    async def attempt(self, credentials: dict[str, Any], guard: str | None = None) -> bool:
        session_guard = self._session_guard(guard)
        user = await self.validate(credentials, session_guard.name)
        if user is None:
            return False
        await call(session_guard.login, self._request, user)
        return True

    @ScopedMethod
    async def validate(self, credentials: dict[str, Any], guard: str | None = None) -> Any | None:
        provider = self.guard(guard).provider
        user = await call(provider.retrieve_by_credentials, credentials)
        if user is None:
            dummy = getattr(provider, "dummy_verify", None)
            if dummy is not None:
                await call(dummy)
            return None
        valid = await call(provider.validate_credentials, user, credentials)
        return user if valid and await user_is_active(provider, user) else None

    @ScopedMethod
    async def logout(self, guard: str | None = None) -> None:
        await call(self._session_guard(guard).logout, self._request)

    @ScopedMethod
    async def user(self, guard: str | None = None) -> Any | None:
        try:
            return (await resolve_context(self._request, self._manager, guard)).user
        except AuthException:
            return None

    @ScopedMethod
    async def id(self, guard: str | None = None) -> Any | None:
        user = await self.user(guard)
        if user is None:
            return None
        return self.guard(guard).provider.get_identifier(user)

    @ScopedMethod
    async def check(self, guard: str | None = None) -> bool:
        return await self.user(guard) is not None

    def _session_guard(self, name: str | None) -> SessionGuard:
        return self._manager.session_guard(name)

    async def _resolve_user(self, user_or_id: Any, session_guard: Any) -> Any:
        if not isinstance(user_or_id, (int, str)):
            return user_or_id
        user = await call(session_guard.provider.retrieve_by_id, user_or_id)
        if user is None:
            raise ValueError(f"No user with id {user_or_id!r} in guard {session_guard.name!r}'s provider.")
        return user
