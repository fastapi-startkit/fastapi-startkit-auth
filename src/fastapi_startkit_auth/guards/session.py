from __future__ import annotations

from typing import Any

from fastapi import Request

from ..exceptions import InvalidSession
from ..concurrency import call, ensure_sync
from ..providers.base import UserProvider, user_is_active, user_is_active_async
from ..sessions.models import SessionRecord
from ..sessions.state import FORGET_KEY, SESSION_KEY
from ..sessions.store import SessionStore
from .guard import AuthContext


class SessionGuard:
    """Cookie/session guard: resolves the server-side session to a user.

    Corresponds to a ``{"driver": "session"}`` guard entry. The middleware puts
    the loaded :class:`SessionRecord` on ``request.state``; this guard turns it
    into an :class:`AuthContext` and owns the login/logout primitives used by
    the ``Auth`` facade. Session-authenticated requests get the wildcard scope,
    like a first-party browser login.
    """

    def __init__(self, name: str, store: SessionStore, provider: UserProvider, ttl: float | None) -> None:
        self.name = name
        self.store = store
        self.provider = provider
        self.ttl = ttl

    def user_from_token(self, access_token: str) -> AuthContext:
        """Resolve a raw session id (the cookie value) to an ``AuthContext``."""
        record = ensure_sync(self.store.find(access_token), "The session store's find")
        if record is None:
            raise InvalidSession("Not authenticated.")
        return self._context(record)

    def authenticate(self, request: Request) -> AuthContext:
        """Resolve the session attached to the request by the middleware."""
        record = getattr(request.state, SESSION_KEY, None)
        if record is None:
            raise InvalidSession("Not authenticated.")
        return self._context(record)

    def login(self, request: Request, user: Any) -> SessionRecord:
        """Start a fresh session for ``user``.

        Always issues a new session id (fixation protection): any session that
        arrived with the request is invalidated server-side and the middleware
        sends the new id in the cookie.
        """
        previous = getattr(request.state, SESSION_KEY, None)
        record = ensure_sync(
            self.store.create(
                user_id=self.provider.get_identifier(user),
                guard=self.name,
                ttl=self.ttl,
            ),
            "The session store's create",
        )
        if previous is not None:
            ensure_sync(self.store.invalidate(previous.id), "The session store's invalidate")
        setattr(request.state, SESSION_KEY, record)
        setattr(request.state, FORGET_KEY, False)
        return record

    def logout(self, request: Request) -> None:
        """Invalidate the server-side session and mark the cookie for deletion."""
        record = getattr(request.state, SESSION_KEY, None)
        if record is not None:
            ensure_sync(self.store.invalidate(record.id), "The session store's invalidate")
        setattr(request.state, SESSION_KEY, None)
        setattr(request.state, FORGET_KEY, True)

    def _context(self, record: SessionRecord) -> AuthContext:
        if record.user_id is None:
            # Guest session (issued by /__auth__/csrf-cookie): it carries a CSRF
            # token but no user, and must survive 401s so the SPA can log in.
            raise InvalidSession("Not authenticated.")
        user = ensure_sync(self.provider.retrieve_by_id(record.user_id), "The user provider's retrieve_by_id")
        if user is None or not user_is_active(self.provider, user):
            ensure_sync(self.store.invalidate(record.id), "The session store's invalidate")
            raise InvalidSession("The session user no longer exists.")
        return AuthContext(user=user, scopes=["*"])


class AsyncSessionGuard:
    def __init__(self, name: str, store: Any, provider: Any, ttl: float | None) -> None:
        self.name = name
        self.store = store
        self.provider = provider
        self.ttl = ttl

    async def user_from_token(self, access_token: str) -> AuthContext:
        record = await call(self.store.find, access_token)
        if record is None:
            raise InvalidSession("Not authenticated.")
        return await self._context(record)

    async def authenticate(self, request: Request) -> AuthContext:
        record = getattr(request.state, SESSION_KEY, None)
        if record is None:
            raise InvalidSession("Not authenticated.")
        return await self._context(record)

    async def login(self, request: Request, user: Any) -> SessionRecord:
        previous = getattr(request.state, SESSION_KEY, None)
        record = await call(
            self.store.create, user_id=self.provider.get_identifier(user), guard=self.name, ttl=self.ttl
        )
        if previous is not None:
            await call(self.store.invalidate, previous.id)
        setattr(request.state, SESSION_KEY, record)
        setattr(request.state, FORGET_KEY, False)
        return record

    async def logout(self, request: Request) -> None:
        record = getattr(request.state, SESSION_KEY, None)
        if record is not None:
            await call(self.store.invalidate, record.id)
        setattr(request.state, SESSION_KEY, None)
        setattr(request.state, FORGET_KEY, True)

    async def _context(self, record: SessionRecord) -> AuthContext:
        if record.user_id is None:
            raise InvalidSession("Not authenticated.")
        user = await call(self.provider.retrieve_by_id, record.user_id)
        if user is None or not await user_is_active_async(self.provider, user):
            await call(self.store.invalidate, record.id)
            raise InvalidSession("The session user no longer exists.")
        return AuthContext(user=user, scopes=["*"])
