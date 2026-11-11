from __future__ import annotations

from typing import Any

from fastapi import Request

from ..exceptions import AuthenticationException
from ..concurrency import call
from ..providers.base import user_is_active
from ..sessions.models import SessionRecord
from ..sessions.state import FORGET_KEY, PENDING_KEY, SESSION_KEY, TOKEN_CLIENT_KEY
from ..sessions.store import new_session_record
from .guard import AuthContext


class SessionGuard:
    def __init__(self, name: str, store: Any, provider: Any, ttl: float | None) -> None:
        self.name = name
        self.store = store
        self.provider = provider
        self.ttl = ttl

    async def user_from_token(self, access_token: str) -> AuthContext:
        record = await call(self.store.find, access_token)
        if record is None:
            raise AuthenticationException("Not authenticated.")
        return await self._context(record)

    async def authenticate(self, request: Request) -> AuthContext:
        record = getattr(request.state, SESSION_KEY, None)
        if record is None or getattr(request.state, TOKEN_CLIENT_KEY, False):
            raise AuthenticationException("Not authenticated.")
        return await self._context(record)

    async def login(self, request: Request, user: Any) -> SessionRecord:
        previous = getattr(request.state, SESSION_KEY, None)
        record = new_session_record(user_id=self.provider.get_identifier(user), guard=self.name, ttl=self.ttl)
        await call(self.store.save, record)
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
        setattr(request.state, PENDING_KEY, None)
        setattr(request.state, FORGET_KEY, True)

    def start_guest_session(self, request: Request) -> SessionRecord:
        return start_guest_session(request, self.name, self.ttl)

    async def _context(self, record: SessionRecord) -> AuthContext:
        if record.user_id is None:
            raise AuthenticationException("Not authenticated.")
        user = await call(self.provider.retrieve_by_id, record.user_id)
        if user is None or not await user_is_active(self.provider, user):
            await call(self.store.invalidate, record.id)
            raise AuthenticationException("The session user no longer exists.")
        return AuthContext(user=user, scopes=["*"])


def start_guest_session(request: Request, guard: str, ttl: float | None) -> SessionRecord:
    """Return the request's session, starting a user-less one if it has none.

    The new record is only persisted when the response starts (see
    ``SessionMiddleware``), so it can still be re-keyed or dropped for free.
    """
    record = getattr(request.state, SESSION_KEY, None)
    if record is not None:
        return record
    record = new_session_record(user_id=None, guard=guard, ttl=ttl)
    setattr(request.state, SESSION_KEY, record)
    setattr(request.state, PENDING_KEY, record)
    setattr(request.state, FORGET_KEY, False)
    return record
