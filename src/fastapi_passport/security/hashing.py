from __future__ import annotations

import base64
import hashlib
from typing import Protocol, runtime_checkable

import bcrypt


@runtime_checkable
class Hasher(Protocol):
    """Password hashing contract. Swap implementations via the auth config."""

    def make(self, plain: str) -> str: ...

    def verify(self, plain: str, hashed: str) -> bool: ...


class BcryptHasher:
    """bcrypt hasher used in place of passlib.

    passlib is avoided because it imports the stdlib ``crypt`` module, removed in
    Python 3.13. Inputs are SHA-256 pre-hashed and base64-encoded so passwords
    longer than bcrypt's 72-byte limit remain fully significant rather than being
    silently truncated.
    """

    def __init__(self, rounds: int = 12) -> None:
        self._rounds = rounds

    def _prepare(self, plain: str) -> bytes:
        digest = hashlib.sha256(plain.encode("utf-8")).digest()
        return base64.b64encode(digest)

    def make(self, plain: str) -> str:
        salt = bcrypt.gensalt(self._rounds)
        return bcrypt.hashpw(self._prepare(plain), salt).decode("utf-8")

    def verify(self, plain: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(self._prepare(plain), hashed.encode("utf-8"))
        except (ValueError, TypeError):
            return False
