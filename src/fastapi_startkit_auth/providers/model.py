from __future__ import annotations

import asyncio
import secrets
from typing import Any

from ..concurrency import resolve
from ..security.hashing import BcryptHasher, Hasher
from .fields import ActiveCheck, active_check, read_attribute, write_attribute


class ModelUserProvider:
    """User provider backed by an active-record-style model class.

    Works with masoniteorm (``config providers['users']['driver'] = 'masoniteorm'``)
    and any ORM whose model exposes ``find(id)`` and ``where(field, value).first()``.
    The model isn't imported here, keeping the ORM an optional dependency.
    """

    def __init__(
        self,
        model: Any,
        hasher: Hasher | None = None,
        id_field: str = "id",
        username_field: str = "email",
        password_field: str = "password",
        password_key: str | None = None,
        is_active: ActiveCheck = None,
    ) -> None:
        self._model = model
        self._hasher = hasher or BcryptHasher()
        self._id_field = id_field
        self._username_field = username_field
        self._password_field = password_field
        self._password_key = password_key or password_field
        self._is_active = active_check(is_active)
        self._dummy_hash = self._hasher.make(secrets.token_urlsafe(16))

    def dummy_verify(self) -> None:
        """Run a throwaway hash verification to equalise timing for absent users."""
        self._hasher.verify("invalid", self._dummy_hash)

    def retrieve_by_id(self, identifier: Any) -> Any | None:
        return self._model.find(identifier)

    def retrieve_by_credentials(self, credentials: dict[str, Any]) -> Any | None:
        username = credentials.get(self._username_field)
        if username is None:
            return None
        return self._model.where(self._username_field, username).first()

    def validate_credentials(self, user: Any, credentials: dict[str, Any]) -> bool:
        if user is None:
            return False
        supplied = credentials.get(self._password_key)
        if supplied is None:
            return False
        return self._hasher.verify(supplied, read_attribute(user, self._password_field) or "")

    def get_identifier(self, user: Any) -> Any:
        return read_attribute(user, self._id_field)

    def is_active(self, user: Any) -> bool:
        return self._is_active(user)

    def update_password(self, user: Any, plain: str) -> None:
        write_attribute(user, self._password_field, self._hasher.make(plain))
        save = getattr(user, "save", None)
        if callable(save):
            save()


class AsyncModelUserProvider:
    def __init__(
        self,
        model: Any,
        hasher: Hasher | None = None,
        id_field: str = "id",
        username_field: str = "email",
        password_field: str = "password",
        password_key: str | None = None,
        is_active: ActiveCheck = None,
    ) -> None:
        self._model = model
        self._hasher = hasher or BcryptHasher()
        self._id_field = id_field
        self._username_field = username_field
        self._password_field = password_field
        self._password_key = password_key or password_field
        self._is_active = active_check(is_active)
        self._dummy_hash = self._hasher.make(secrets.token_urlsafe(16))

    async def dummy_verify(self) -> None:
        await asyncio.to_thread(self._hasher.verify, "invalid", self._dummy_hash)

    async def retrieve_by_id(self, identifier: Any) -> Any | None:
        return await resolve(self._model.find(identifier))

    async def retrieve_by_credentials(self, credentials: dict[str, Any]) -> Any | None:
        username = credentials.get(self._username_field)
        if username is None:
            return None
        return await resolve(self._model.where(self._username_field, username).first())

    async def validate_credentials(self, user: Any, credentials: dict[str, Any]) -> bool:
        if user is None:
            return False
        supplied = credentials.get(self._password_key)
        if supplied is None:
            return False
        stored = read_attribute(user, self._password_field) or ""
        return await asyncio.to_thread(self._hasher.verify, supplied, stored)

    def get_identifier(self, user: Any) -> Any:
        return read_attribute(user, self._id_field)

    def is_active(self, user: Any) -> bool:
        return self._is_active(user)

    async def update_password(self, user: Any, plain: str) -> None:
        hashed = await asyncio.to_thread(self._hasher.make, plain)
        write_attribute(user, self._password_field, hashed)
        save = getattr(user, "save", None)
        if callable(save):
            await resolve(save())
