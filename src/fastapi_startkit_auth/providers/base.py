from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..concurrency import call, ensure_sync, has_async_methods

User = Any


@runtime_checkable
class UserProvider(Protocol):
    """Retrieves and verifies users from a backing store.

    Kept deliberately small so any store (ORM, in-memory, external service) can
    implement it. Credential *lookup* is separate from credential *verification*
    so timing and hashing stay under the provider's control.
    """

    def retrieve_by_id(self, identifier: Any) -> User | None:
        """Return the user with this primary identifier, or ``None``."""

    def retrieve_by_credentials(self, credentials: dict[str, Any]) -> User | None:
        """Find a user by identifying fields (e.g. email); does NOT check the password."""

    def validate_credentials(self, user: User, credentials: dict[str, Any]) -> bool:
        """Return whether ``credentials`` authenticate ``user``."""

    def dummy_verify(self) -> None:
        """Burn a credential verification against a throwaway hash.

        Called when ``retrieve_by_credentials`` finds no user, so the
        absent-user path takes as long as a real password check and login
        timing does not enumerate accounts.
        """

    def get_identifier(self, user: User) -> Any:
        """Return the primary identifier stored in a token's ``sub`` claim."""

    def update_password(self, user: User, plain: str) -> None:
        """Persist a new hashed password for ``user`` (used by password resets)."""


@runtime_checkable
class AsyncUserProvider(Protocol):
    async def retrieve_by_id(self, identifier: Any) -> User | None: ...

    async def retrieve_by_credentials(self, credentials: dict[str, Any]) -> User | None: ...

    async def validate_credentials(self, user: User, credentials: dict[str, Any]) -> bool: ...

    async def dummy_verify(self) -> None: ...

    def get_identifier(self, user: User) -> Any: ...

    async def is_active(self, user: User) -> bool: ...

    async def update_password(self, user: User, plain: str) -> None: ...


PROVIDER_METHODS = (
    "retrieve_by_id",
    "retrieve_by_credentials",
    "validate_credentials",
    "dummy_verify",
    "update_password",
    "is_active",
)


def is_async_provider(provider: Any) -> bool:
    return has_async_methods(provider, PROVIDER_METHODS)


def user_is_active(provider: Any, user: User) -> bool:
    check = getattr(provider, "is_active", None)
    if check is None:
        return True
    return bool(ensure_sync(check(user), "The user provider's is_active"))


async def user_is_active_async(provider: Any, user: User) -> bool:
    check = getattr(provider, "is_active", None)
    if check is None:
        return True
    return bool(await call(check, user))


def _identifiers(identifier: Any) -> list[Any]:
    # JWT `sub` and SQL-stored ids are strings; retry with an int for numeric keys.
    if isinstance(identifier, str) and identifier.isdigit():
        return [identifier, int(identifier)]
    return [identifier]


def find_user(provider: Any, identifier: Any) -> User | None:
    for candidate in _identifiers(identifier):
        user = ensure_sync(provider.retrieve_by_id(candidate), "The user provider's retrieve_by_id")
        if user is not None:
            return user
    return None


async def find_user_async(provider: Any, identifier: Any) -> User | None:
    for candidate in _identifiers(identifier):
        user = await call(provider.retrieve_by_id, candidate)
        if user is not None:
            return user
    return None


def active_user(provider: Any, identifier: Any) -> User | None:
    user = find_user(provider, identifier)
    return user if user is not None and user_is_active(provider, user) else None


async def active_user_async(provider: Any, identifier: Any) -> User | None:
    user = await find_user_async(provider, identifier)
    return user if user is not None and await user_is_active_async(provider, user) else None
