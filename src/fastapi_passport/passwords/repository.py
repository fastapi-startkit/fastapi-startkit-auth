from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class PasswordResetToken:
    """A row in the ``password_reset_tokens`` table."""

    email: str
    hashed_token: str
    created_at: float

    def age(self) -> float:
        return time.time() - self.created_at


class InMemoryPasswordResetRepository:
    """Stores at most one active reset token per identifier (email).

    Mirrors Laravel's ``password_reset_tokens`` table where issuing a new token
    replaces any previous one for the same user.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, PasswordResetToken] = {}

    def create(self, email: str, hashed_token: str) -> PasswordResetToken:
        rec = PasswordResetToken(email=email, hashed_token=hashed_token, created_at=time.time())
        self._tokens[email] = rec
        return rec

    def find(self, email: str) -> PasswordResetToken | None:
        return self._tokens.get(email)

    def delete(self, email: str) -> None:
        self._tokens.pop(email, None)

    def recently_created(self, email: str, throttle_seconds: int) -> bool:
        rec = self._tokens.get(email)
        if rec is None:
            return False
        return rec.age() < throttle_seconds
