from __future__ import annotations

from typing import Any

from ..security.hashing import BcryptHasher, Hasher


def _attr(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


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
    ) -> None:
        self._model = model
        self._hasher = hasher or BcryptHasher()
        self._id_field = id_field
        self._username_field = username_field
        self._password_field = password_field

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
        supplied = credentials.get(self._password_field)
        if supplied is None:
            return False
        return self._hasher.verify(supplied, _attr(user, self._password_field) or "")

    def get_identifier(self, user: Any) -> Any:
        return _attr(user, self._id_field)

    def update_password(self, user: Any, plain: str) -> None:
        hashed = self._hasher.make(plain)
        if isinstance(user, dict):
            user[self._password_field] = hashed
        else:
            setattr(user, self._password_field, hashed)
        save = getattr(user, "save", None)
        if callable(save):
            save()
