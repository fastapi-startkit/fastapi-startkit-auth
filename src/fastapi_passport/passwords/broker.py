from __future__ import annotations

import secrets

from ..exceptions import InvalidGrant, ThrottleException
from ..providers.base import UserProvider
from ..security.hashing import BcryptHasher, Hasher
from .repository import InMemoryPasswordResetRepository


class PasswordBroker:
    """Password reset flow backed by the ``password_reset_tokens`` table.

    Tokens are stored hashed, expire after ``expire_minutes``, and are
    rate-limited per user by ``throttle_seconds`` — matching Laravel's broker.
    The plaintext token is returned from ``send_reset_link`` so the caller can
    deliver it (e.g. by email); only its hash is persisted.
    """

    def __init__(
        self,
        user_provider: UserProvider,
        repository: InMemoryPasswordResetRepository | None = None,
        hasher: Hasher | None = None,
        expire_minutes: int = 60,
        throttle_seconds: int = 60,
    ) -> None:
        self._users = user_provider
        self._repo = repository or InMemoryPasswordResetRepository()
        self._hasher = hasher or BcryptHasher()
        self._expire_minutes = expire_minutes
        self._throttle_seconds = throttle_seconds

    def _find_user(self, email: str):
        return self._users.retrieve_by_credentials({"email": email, "username": email})

    def send_reset_link(self, email: str) -> str:
        user = self._find_user(email)
        if user is None:
            raise InvalidGrant("We can't find a user with that email address.")
        if self._repo.recently_created(email, self._throttle_seconds):
            raise ThrottleException("Please wait before requesting another reset link.")
        token = secrets.token_urlsafe(40)
        self._repo.create(email, self._hasher.make(token))
        return token

    def reset(self, email: str, token: str, new_password: str) -> bool:
        record = self._repo.find(email)
        if record is None:
            raise InvalidGrant("This password reset token is invalid.")
        if record.age() > self._expire_minutes * 60:
            self._repo.delete(email)
            raise InvalidGrant("This password reset token has expired.")
        if not self._hasher.verify(token, record.hashed_token):
            raise InvalidGrant("This password reset token is invalid.")
        user = self._find_user(email)
        if user is None:
            raise InvalidGrant("We can't find a user with that email address.")
        self._users.update_password(user, new_password)
        self._repo.delete(email)
        return True
