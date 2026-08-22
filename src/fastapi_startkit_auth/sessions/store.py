from __future__ import annotations

import secrets
import time
from typing import Any, Protocol, runtime_checkable

from .models import SessionRecord


def generate_session_id() -> str:
    return secrets.token_urlsafe(32)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


@runtime_checkable
class SessionStore(Protocol):
    """Contract every session backend satisfies.

    Mirrors the repository pattern of ``InMemoryTokenRepository``: the package
    ships an in-memory default and a SQL implementation, and apps may implement
    the same surface against any other store.
    """

    def create(self, *, user_id: Any, guard: str, ttl: float | None) -> SessionRecord:
        """Persist and return a new session with a fresh id and CSRF token."""

    def find(self, session_id: str) -> SessionRecord | None:
        """Return the live session for this id, or ``None`` if unknown/expired."""

    def touch(self, session_id: str) -> None:
        """Record activity on the session (slides the idle-expiry window)."""

    def regenerate_id(self, session_id: str) -> SessionRecord | None:
        """Re-key the session under a fresh id, invalidating the old id."""

    def invalidate(self, session_id: str) -> bool:
        """Delete the session server-side; returns whether it existed."""

    def purge_expired(self) -> None:
        """Drop expired sessions (maintenance)."""


class InMemorySessionStore:
    """Default dict-backed session store for tests, demos, and prototypes.

    ``idle_ttl`` expires sessions that have been inactive longer than the
    window, independently of the absolute ``expires_at`` set at creation.
    """

    def __init__(self, idle_ttl: float | None = None) -> None:
        self._sessions: dict[str, SessionRecord] = {}
        self._idle_ttl = idle_ttl

    def create(self, *, user_id: Any, guard: str, ttl: float | None) -> SessionRecord:
        now = time.time()
        record = SessionRecord(
            id=generate_session_id(),
            user_id=user_id,
            guard=guard,
            csrf_token=generate_csrf_token(),
            created_at=now,
            last_activity=now,
            expires_at=(now + ttl) if ttl is not None else None,
        )
        self._sessions[record.id] = record
        return record

    def find(self, session_id: str) -> SessionRecord | None:
        record = self._sessions.get(session_id)
        if record is None:
            return None
        if record.expired(self._idle_ttl):
            del self._sessions[session_id]
            return None
        return record

    def touch(self, session_id: str) -> None:
        record = self._sessions.get(session_id)
        if record is not None:
            record.last_activity = time.time()

    def regenerate_id(self, session_id: str) -> SessionRecord | None:
        record = self.find(session_id)
        if record is None:
            return None
        del self._sessions[session_id]
        record.id = generate_session_id()
        self._sessions[record.id] = record
        return record

    def invalidate(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    def purge_expired(self) -> None:
        self._sessions = {
            sid: rec for sid, rec in self._sessions.items() if not rec.expired(self._idle_ttl)
        }
