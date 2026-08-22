from __future__ import annotations

from typing import Any

from fastapi import Request

from ..exceptions import InvalidSession
from ..providers.base import UserProvider
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
        record = self.store.find(access_token)
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
        record = self.store.create(
            user_id=self.provider.get_identifier(user),
            guard=self.name,
            ttl=self.ttl,
        )
        if previous is not None:
            self.store.invalidate(previous.id)
        setattr(request.state, SESSION_KEY, record)
        setattr(request.state, FORGET_KEY, False)
        return record

    def logout(self, request: Request) -> None:
        """Invalidate the server-side session and mark the cookie for deletion."""
        record = getattr(request.state, SESSION_KEY, None)
        if record is not None:
            self.store.invalidate(record.id)
        setattr(request.state, SESSION_KEY, None)
        setattr(request.state, FORGET_KEY, True)

    def _context(self, record: SessionRecord) -> AuthContext:
        user = self.provider.retrieve_by_id(record.user_id)
        if user is None:
            self.store.invalidate(record.id)
            raise InvalidSession("The session user no longer exists.")
        return AuthContext(user=user, scopes=["*"])
