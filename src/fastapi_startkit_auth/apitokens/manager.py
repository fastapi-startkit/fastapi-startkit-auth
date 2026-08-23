from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from ..exceptions import InvalidToken
from .models import ApiTokenRecord
from .repository import ApiTokenRepository, generate_token_secret, hash_token_secret

# Every verification failure raises this exact message so responses (and their
# timing, via the dummy compare below) never reveal whether the id exists.
_GENERIC_FAILURE = "The API token is invalid."

_DUMMY_HASH = hash_token_secret("!" + generate_token_secret())


@dataclass(repr=False)
class NewApiToken:
    """The one and only carrier of a token's plaintext.

    ``plain_text`` (``"{id}|{secret}"``) exists here and nowhere else — the
    repository stores only the secret's hash, so it cannot be shown again.
    """

    record: ApiTokenRecord
    plain_text: str

    def __repr__(self) -> str:
        # The dataclass auto-repr would leak the live secret into logs,
        # error-tracker locals, and test output; show only the id half.
        return (
            f"NewApiToken(record={self.record!r}, plain_text='{self.record.id}|***redacted***')"
        )


class ApiTokenManager:
    """Issues, verifies, revokes, and lists opaque API tokens.

    Exposed as ``AuthManager.api_tokens``; apps wire their own management
    routes around it (the package ships none, per the app-owns-routes
    decision).
    """

    def __init__(
        self,
        repository: ApiTokenRepository,
        default_ttl: float | None = None,
        purge_interval: float = 300,
    ) -> None:
        self.repository = repository
        self._default_ttl = default_ttl
        self._purge_interval = purge_interval
        self._purge_lock = threading.Lock()
        self._last_purge = time.time()

    def _maybe_purge(self) -> None:
        """Drop expired records periodically so stores stay bounded without a
        scheduler (mirrors the purge-on-issue pattern of ``TokenService``)."""
        now = time.time()
        with self._purge_lock:
            if now - self._last_purge < self._purge_interval:
                return
            self._last_purge = now
        self.repository.purge_expired()

    def create(
        self,
        user_id: Any,
        name: str | None = None,
        abilities: list[str] | None = None,
        expires_at: float | None = None,
    ) -> NewApiToken:
        """Issue a token for ``user_id``; the plaintext is returned exactly once.

        ``expires_at`` overrides the configured default ttl; ``None`` with no
        configured ttl means the token never expires. ``abilities`` default to
        the unrestricted ``["*"]``.
        """
        self._maybe_purge()
        if expires_at is None and self._default_ttl is not None:
            expires_at = time.time() + self._default_ttl
        secret = generate_token_secret()
        record = self.repository.create(
            user_id=user_id,
            token_hash=hash_token_secret(secret),
            name=name,
            abilities=list(abilities) if abilities else ["*"],
            expires_at=expires_at,
        )
        return NewApiToken(record=record, plain_text=f"{record.id}|{secret}")

    def verify(self, token: str) -> ApiTokenRecord:
        """Resolve ``"{id}|{secret}"`` to its live record or raise 401.

        Lookup is by id (O(1), no scan); the secret comparison is constant-time
        against the stored hash — or against a dummy hash when the id is
        unknown, so the miss path costs the same as a mismatch.
        """
        token_id, sep, secret = token.partition("|")
        expected = _DUMMY_HASH
        record = None
        if sep and token_id and secret:
            record = self.repository.find(token_id)
            if record is not None:
                expected = record.token_hash
        matched = secrets.compare_digest(hash_token_secret(secret), expected)
        if record is None or not matched or record.expired:
            raise InvalidToken(_GENERIC_FAILURE)
        self.repository.touch(record.id)
        return record

    def revoke(self, token_id: str) -> bool:
        return self.repository.revoke(token_id)

    def revoke_all(self, user_id: Any) -> int:
        return self.repository.revoke_all_for_user(user_id)

    def tokens_for(self, user_id: Any) -> list[ApiTokenRecord]:
        return self.repository.list_for_user(user_id)
