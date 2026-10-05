from __future__ import annotations

from typing import Any

from fastapi import Depends, Request

from .dependencies import _bearer_token, get_auth_manager, resolve_context
from .concurrency import call, ensure_sync
from .exceptions import AuthError
from .guards.session import AsyncSessionGuard, SessionGuard
from .manager import AuthManager
from .providers.base import user_is_active, user_is_active_async
from .scoped_method import ScopedMethod
from .sessions.models import SessionRecord


class Auth:
    """Request-scoped facade over the manager and the request's session.

    Inside a request handled by ``AuthProvider`` the methods also work on the
    class itself (``Auth.user()``), bound to the current request. Wire it into
    your own login/logout routes (the package ships none)::

        from fastapi_startkit_auth import Auth

        @api.post("/login")
        def login(payload: Credentials, auth: Auth = Depends(Auth.scoped)):
            if not auth.attempt(payload.model_dump()):
                raise InvalidSession("Invalid credentials.")
            return {"ok": True}

        @api.post("/logout")
        def logout(auth: Auth = Depends(Auth.scoped)):
            auth.logout()
    """

    def __init__(self, manager: AuthManager, request: Request) -> None:
        self._manager = manager
        self._request = request

    @classmethod
    def scoped(cls, request: Request, manager: AuthManager = Depends(get_auth_manager)) -> "Auth":
        """FastAPI dependency: ``auth: Auth = Depends(Auth.scoped)``."""
        return cls(manager, request)

    @ScopedMethod
    def guard(self, name: str | None = None) -> Any:
        return self._manager.guard(name)

    @ScopedMethod
    def login(self, user_or_id: Any, guard: str | None = None) -> SessionRecord:
        """Start a session for a user instance or a user id.

        Always regenerates the session id (fixation protection) and rides the
        middleware to deliver the cookie.
        """
        session_guard = self._session_guard(guard)
        user = self._resolve_user(user_or_id, session_guard)
        return session_guard.login(self._request, user)

    @ScopedMethod
    def attempt(self, credentials: dict[str, Any], guard: str | None = None) -> bool:
        """Log in by credentials; ``False`` on any failure (no enumeration)."""
        session_guard = self._session_guard(guard)
        user = self.validate(credentials, session_guard.name)
        if user is None:
            return False
        session_guard.login(self._request, user)
        return True

    @ScopedMethod
    def validate(self, credentials: dict[str, Any], guard: str | None = None) -> Any | None:
        """Check credentials without logging in; the user, or ``None``."""
        provider = self.guard(guard).provider
        user = ensure_sync(provider.retrieve_by_credentials(credentials), "retrieve_by_credentials")
        if user is None:
            dummy = getattr(provider, "dummy_verify", None)
            if dummy is not None:
                ensure_sync(dummy(), "dummy_verify")
            return None
        valid = ensure_sync(provider.validate_credentials(user, credentials), "validate_credentials")
        return user if valid and user_is_active(provider, user) else None

    @ScopedMethod
    def logout(self, guard: str | None = None) -> None:
        self._session_guard(guard).logout(self._request)

    @ScopedMethod
    def user(self, guard: str | None = None) -> Any | None:
        """The authenticated user, or ``None`` — never raises."""
        resolved = self.guard(guard)
        authenticate = getattr(resolved, "authenticate", None)
        try:
            if authenticate is not None:
                return ensure_sync(authenticate(self._request), "The guard's authenticate").user
            token = _bearer_token(self._request)
            if token is None:
                return None
            return ensure_sync(resolved.user_from_token(token), "The guard's user_from_token").user
        except AuthError:
            return None

    @ScopedMethod
    def id(self, guard: str | None = None) -> Any | None:
        user = self.user(guard)
        if user is None:
            return None
        return self.guard(guard).provider.get_identifier(user)

    @ScopedMethod
    def check(self, guard: str | None = None) -> bool:
        return self.user(guard) is not None

    def _session_guard(self, name: str | None) -> SessionGuard:
        resolved = self._manager.session_guard(name)
        if isinstance(resolved, AsyncSessionGuard):
            raise RuntimeError(f"Auth guard {resolved.name!r} is async; use AsyncAuth instead of Auth.")
        return resolved

    def _resolve_user(self, user_or_id: Any, session_guard: SessionGuard) -> Any:
        if not isinstance(user_or_id, (int, str)):
            return user_or_id
        user = ensure_sync(session_guard.provider.retrieve_by_id(user_or_id), "retrieve_by_id")
        if user is None:
            raise ValueError(f"No user with id {user_or_id!r} in guard {session_guard.name!r}'s provider.")
        return user


class AsyncAuth:
    def __init__(self, manager: AuthManager, request: Request) -> None:
        self._manager = manager
        self._request = request

    @classmethod
    def scoped(cls, request: Request, manager: AuthManager = Depends(get_auth_manager)) -> "AsyncAuth":
        return cls(manager, request)

    @ScopedMethod
    def guard(self, name: str | None = None) -> Any:
        return self._manager.guard(name)

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
        return user if valid and await user_is_active_async(provider, user) else None

    @ScopedMethod
    async def logout(self, guard: str | None = None) -> None:
        await call(self._session_guard(guard).logout, self._request)

    @ScopedMethod
    async def user(self, guard: str | None = None) -> Any | None:
        try:
            return (await resolve_context(self._request, self._manager, guard)).user
        except AuthError:
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

    def _session_guard(self, name: str | None) -> SessionGuard | AsyncSessionGuard:
        return self._manager.session_guard(name)

    async def _resolve_user(self, user_or_id: Any, session_guard: Any) -> Any:
        if not isinstance(user_or_id, (int, str)):
            return user_or_id
        user = await call(session_guard.provider.retrieve_by_id, user_or_id)
        if user is None:
            raise ValueError(f"No user with id {user_or_id!r} in guard {session_guard.name!r}'s provider.")
        return user
