from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

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
