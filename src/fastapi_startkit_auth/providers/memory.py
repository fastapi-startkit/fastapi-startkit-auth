from __future__ import annotations

import asyncio
import secrets
from typing import Any

from ..concurrency import resolve
from ..security.hashing import BcryptHasher, Hasher
from .fields import ActiveCheck, active_check


class InMemoryUserProvider:
    """Dict-backed user provider for tests, demos, and prototypes.

    Users are plain dicts keyed by an ``id`` field. Real deployments swap this
    for an ORM-backed provider via the ``providers`` config, but the contract is
    identical.
    """

    def __init__(
        self,
        hasher: Hasher | None = None,
        id_field: str = "id",
        username_field: str = "email",
        password_field: str = "password",
        password_key: str | None = None,
        is_active: ActiveCheck = None,
    ) -> None:
        self._hasher = hasher or BcryptHasher()
        self._id_field = id_field
        self._username_field = username_field
        self._password_field = password_field
        self._password_key = password_key or password_field
        self._is_active = active_check(is_active)
        self._users: dict[Any, dict[str, Any]] = {}
        # Precomputed hash for constant-time verification of absent users.
        self._dummy_hash = self._hasher.make(secrets.token_urlsafe(16))

    def add(self, user: dict[str, Any]) -> dict[str, Any]:
        self._users[user[self._id_field]] = user
        return user

    def create(self, *, password: str, **fields: Any) -> dict[str, Any]:
        fields[self._password_field] = self._hasher.make(password)
        return self.add(fields)

    async def retrieve_by_id(self, identifier: Any) -> dict[str, Any] | None:
        return self._users.get(identifier)

    async def retrieve_by_credentials(self, credentials: dict[str, Any]) -> dict[str, Any] | None:
        username = credentials.get(self._username_field)
        if username is None:
            return None
        for user in self._users.values():
            if user.get(self._username_field) == username:
                return user
        return None

    async def validate_credentials(self, user: dict[str, Any], credentials: dict[str, Any]) -> bool:
        if user is None:
            return False
        supplied = credentials.get(self._password_key)
        if supplied is None:
            return False
        return await asyncio.to_thread(self._hasher.verify, supplied, user.get(self._password_field, ""))

    async def dummy_verify(self) -> None:
        """Run a throwaway hash verification to equalise timing for absent users."""
        await asyncio.to_thread(self._hasher.verify, "invalid", self._dummy_hash)

    def get_identifier(self, user: dict[str, Any]) -> Any:
        return user[self._id_field]

    async def is_active(self, user: dict[str, Any]) -> bool:
        return bool(await resolve(self._is_active(user)))

    async def update_password(self, user: dict[str, Any], plain: str) -> None:
        stored = self._users[user[self._id_field]]
        stored[self._password_field] = await asyncio.to_thread(self._hasher.make, plain)
