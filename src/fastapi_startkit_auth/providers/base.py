from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..concurrency import call

User = Any


@runtime_checkable
class UserProvider(Protocol):
    async def retrieve_by_id(self, identifier: Any) -> User | None: ...

    async def retrieve_by_credentials(self, credentials: dict[str, Any]) -> User | None: ...

    async def validate_credentials(self, user: User, credentials: dict[str, Any]) -> bool: ...

    async def dummy_verify(self) -> None: ...

    def get_identifier(self, user: User) -> Any: ...

    async def is_active(self, user: User) -> bool: ...

    async def update_password(self, user: User, plain: str) -> None: ...


async def user_is_active(provider: Any, user: User) -> bool:
    check = getattr(provider, "is_active", None)
    if check is None:
        return True
    return bool(await call(check, user))


def _identifiers(identifier: Any) -> list[Any]:
    # JWT `sub` and SQL-stored ids are strings; retry with an int for numeric keys.
    if isinstance(identifier, str) and identifier.isdigit():
        return [identifier, int(identifier)]
    return [identifier]


async def find_user(provider: Any, identifier: Any) -> User | None:
    for candidate in _identifiers(identifier):
        user = await call(provider.retrieve_by_id, candidate)
        if user is not None:
            return user
    return None


async def active_user(provider: Any, identifier: Any) -> User | None:
    user = await find_user(provider, identifier)
    return user if user is not None and await user_is_active(provider, user) else None
