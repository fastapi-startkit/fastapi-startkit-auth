from __future__ import annotations

from typing import Any

from fastapi import Depends, Request

from .dependencies import get_auth_manager
from .concurrency import resolve
from .exceptions import AuthError
from .guards.session import AsyncSessionGuard, SessionGuard
from .manager import AuthManager
from .providers.base import user_is_active
from .sessions.models import SessionRecord


class Auth:
    """Request-scoped facade over the manager and the request's session.

    Wire it into your own login/logout routes (the package ships none)::

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

    def guard(self, name: str | None = None) -> Any:
        return self._manager.guard(name)

    def login(self, user_or_id: Any, guard: str | None = None) -> SessionRecord:
        """Start a session for a user instance or a user id.

        Always regenerates the session id (fixation protection) and rides the
        middleware to deliver the cookie.
        """
        session_guard = self._session_guard(guard)
        user = self._resolve_user(user_or_id, session_guard)
        return session_guard.login(self._request, user)

    def attempt(self, credentials: dict[str, Any], guard: str | None = None) -> bool:
        """Log in by credentials; ``False`` on any failure (no enumeration)."""
        session_guard = self._session_guard(guard)
        provider = session_guard.provider
        user = provider.retrieve_by_credentials(credentials)
        if user is None:
            dummy = getattr(provider, "dummy_verify", None)
            if dummy is not None:
                dummy()
            return False
        if not provider.validate_credentials(user, credentials) or not user_is_active(provider, user):
            return False
        session_guard.login(self._request, user)
        return True

    def logout(self, guard: str | None = None) -> None:
        self._session_guard(guard).logout(self._request)

    def user(self, guard: str | None = None) -> Any | None:
        """The authenticated user, or ``None`` — never raises."""
        resolved = self.guard(guard)
        authenticate = getattr(resolved, "authenticate", None)
        if authenticate is None:
            return None
        try:
            return authenticate(self._request).user
        except AuthError:
            return None

    def id(self, guard: str | None = None) -> Any | None:
        user = self.user(guard)
        if user is None:
            return None
        return self.guard(guard).provider.get_identifier(user)

    def check(self, guard: str | None = None) -> bool:
        return self.user(guard) is not None

    def _session_guard(self, name: str | None) -> SessionGuard:
        resolved = self.guard(name)
        if isinstance(resolved, AsyncSessionGuard):
            raise RuntimeError(f"Auth guard {resolved.name!r} is async; use AsyncAuth instead of Auth.")
        if not isinstance(resolved, SessionGuard):
            raise RuntimeError(
                f"Auth guard {resolved.name!r} is not a session guard; "
                'login/logout require a {"driver": "session"} guard.'
            )
        return resolved

    def _resolve_user(self, user_or_id: Any, session_guard: SessionGuard) -> Any:
        if not isinstance(user_or_id, (int, str)):
            return user_or_id
        user = session_guard.provider.retrieve_by_id(user_or_id)
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

    def guard(self, name: str | None = None) -> Any:
        return self._manager.guard(name)

    async def login(self, user_or_id: Any, guard: str | None = None) -> SessionRecord:
        session_guard = self._session_guard(guard)
        user = await self._resolve_user(user_or_id, session_guard)
        return await resolve(session_guard.login(self._request, user))

    async def attempt(self, credentials: dict[str, Any], guard: str | None = None) -> bool:
        session_guard = self._session_guard(guard)
        provider = session_guard.provider
        user = await resolve(provider.retrieve_by_credentials(credentials))
        if user is None:
            dummy = getattr(provider, "dummy_verify", None)
            if dummy is not None:
                await resolve(dummy())
            return False
        valid = await resolve(provider.validate_credentials(user, credentials))
        if not valid or not user_is_active(provider, user):
            return False
        await resolve(session_guard.login(self._request, user))
        return True

    async def logout(self, guard: str | None = None) -> None:
        await resolve(self._session_guard(guard).logout(self._request))

    async def user(self, guard: str | None = None) -> Any | None:
        authenticate = getattr(self.guard(guard), "authenticate", None)
        if authenticate is None:
            return None
        try:
            return (await resolve(authenticate(self._request))).user
        except AuthError:
            return None

    async def id(self, guard: str | None = None) -> Any | None:
        user = await self.user(guard)
        if user is None:
            return None
        return self.guard(guard).provider.get_identifier(user)

    async def check(self, guard: str | None = None) -> bool:
        return await self.user(guard) is not None

    def _session_guard(self, name: str | None) -> SessionGuard | AsyncSessionGuard:
        resolved = self.guard(name)
        if not isinstance(resolved, (SessionGuard, AsyncSessionGuard)):
            raise RuntimeError(
                f"Auth guard {resolved.name!r} is not a session guard; "
                'login/logout require a {"driver": "session"} guard.'
            )
        return resolved

    async def _resolve_user(self, user_or_id: Any, session_guard: Any) -> Any:
        if not isinstance(user_or_id, (int, str)):
            return user_or_id
        user = await resolve(session_guard.provider.retrieve_by_id(user_or_id))
        if user is None:
            raise ValueError(f"No user with id {user_or_id!r} in guard {session_guard.name!r}'s provider.")
        return user
