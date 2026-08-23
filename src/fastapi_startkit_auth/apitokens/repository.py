from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, Protocol, runtime_checkable

from .models import ApiTokenRecord


def generate_token_id() -> str:
    return secrets.token_urlsafe(16)


def generate_token_secret() -> str:
    return secrets.token_urlsafe(40)


def hash_token_secret(secret: str) -> str:
    """SHA-256 at rest: correct for high-entropy random secrets (bcrypt would
    add per-request latency without adding security for non-guessable input)."""
    return hashlib.sha256(secret.encode()).hexdigest()


@runtime_checkable
class ApiTokenRepository(Protocol):
    """Contract every API-token backend satisfies.

    Mirrors the ``SessionStore`` pattern: the package ships an in-memory
    default and a SQL implementation, and apps may implement the same surface
    against any other store. Implementations must never see or persist the
    plaintext secret — only its hash arrives here.
    """

    def create(
        self,
        *,
        user_id: Any,
        token_hash: str,
        name: str | None,
        abilities: list[str],
        expires_at: float | None,
    ) -> ApiTokenRecord:
        """Persist and return a new token record with a fresh id."""

    def find(self, token_id: str) -> ApiTokenRecord | None:
        """Return the live record for this id, or ``None`` if unknown/expired."""

    def touch(self, token_id: str) -> None:
        """Record usage (updates ``last_used_at``)."""

    def revoke(self, token_id: str) -> bool:
        """Delete the record (revocation is row deletion); returns whether it existed."""

    def revoke_all_for_user(self, user_id: Any) -> int:
        """Delete every token belonging to ``user_id``; returns how many."""

    def list_for_user(self, user_id: Any) -> list[ApiTokenRecord]:
        """Return the user's live (non-expired) token records."""

    def purge_expired(self) -> None:
        """Drop expired records (maintenance)."""


class InMemoryApiTokenRepository:
    """Default dict-backed token repository for tests, demos, and prototypes."""

    def __init__(self) -> None:
        self._tokens: dict[str, ApiTokenRecord] = {}

    def create(
        self,
        *,
        user_id: Any,
        token_hash: str,
        name: str | None,
        abilities: list[str],
        expires_at: float | None,
    ) -> ApiTokenRecord:
        record = ApiTokenRecord(
            id=generate_token_id(),
            user_id=user_id,
            token_hash=token_hash,
            name=name,
            abilities=list(abilities),
            expires_at=expires_at,
        )
        self._tokens[record.id] = record
        return record

    def find(self, token_id: str) -> ApiTokenRecord | None:
        record = self._tokens.get(token_id)
        if record is None:
            return None
        if record.expired:
            del self._tokens[token_id]
            return None
        return record

    def touch(self, token_id: str) -> None:
        record = self._tokens.get(token_id)
        if record is not None:
            record.last_used_at = time.time()

    def revoke(self, token_id: str) -> bool:
        return self._tokens.pop(token_id, None) is not None

    def revoke_all_for_user(self, user_id: Any) -> int:
        doomed = [tid for tid, rec in self._tokens.items() if rec.user_id == user_id]
        for tid in doomed:
            del self._tokens[tid]
        return len(doomed)

    def list_for_user(self, user_id: Any) -> list[ApiTokenRecord]:
        return [
            rec for rec in self._tokens.values() if rec.user_id == user_id and not rec.expired
        ]

    def purge_expired(self) -> None:
        self._tokens = {tid: rec for tid, rec in self._tokens.items() if not rec.expired}
