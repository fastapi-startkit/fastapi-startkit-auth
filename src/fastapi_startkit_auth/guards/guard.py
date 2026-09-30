from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..exceptions import InvalidToken
from ..concurrency import call, ensure_sync
from ..providers.base import UserProvider, find_user, find_user_async, user_is_active, user_is_active_async
from ..tokens.service import TokenService


_INACTIVE_SUBJECT = "The token subject is not active."


@dataclass
class AuthContext:
    """The authenticated principal resolved from a bearer token.

    ``user`` is ``None`` for client-credentials tokens (machine-to-machine).
    ``can``/``can_any`` implement Passport-style ability checks against the
    token's scopes.
    """

    user: Any | None
    scopes: list[str] = field(default_factory=list)
    client_id: str | None = None
    jti: str | None = None

    def can(self, scope: str) -> bool:
        return "*" in self.scopes or scope in self.scopes

    def can_any(self, scopes: list[str]) -> bool:
        return any(self.can(s) for s in scopes)

    def can_all(self, scopes: list[str]) -> bool:
        return all(self.can(s) for s in scopes)


@runtime_checkable
class Guard(Protocol):
    """Structural contract every auth guard driver satisfies.

    A guard pairs a named user provider with a mechanism for turning a request
    credential into an :class:`AuthContext`. ``PassportGuard`` (JWT bearer),
    ``SessionGuard`` (cookie), and ``TokenGuard`` (opaque API token) are the
    built-in drivers; app-defined drivers register their own factories with
    :class:`~fastapi_startkit_auth.manager.AuthManager` and implement this same
    surface.
    """

    name: str
    provider: UserProvider

    def user_from_token(self, access_token: str) -> AuthContext: ...


class PassportGuard:
    """Resolves a request's bearer token to an :class:`AuthContext`.

    Corresponds to a ``{"driver": "passport"}`` guard entry: it pairs the shared
    :class:`TokenService` (which validates signature, expiry, and revocation)
    with the guard's configured user provider.
    """

    def __init__(self, name: str, token_service: TokenService, provider: UserProvider) -> None:
        self.name = name
        self._tokens = token_service
        self.provider = provider

    def user_from_token(self, access_token: str) -> AuthContext:
        claims = ensure_sync(self._tokens.authenticate(access_token), "The token service's authenticate")
        return _context_from_claims(claims, self._resolve_user(claims.get("sub")))

    def _resolve_user(self, sub: Any) -> Any | None:
        if sub is None:
            return None
        user = find_user(self.provider, sub)
        if user is None:
            raise InvalidToken("The token subject no longer exists.")
        if not user_is_active(self.provider, user):
            raise InvalidToken(_INACTIVE_SUBJECT)
        return user


def _context_from_claims(claims: dict[str, Any], user: Any | None) -> AuthContext:
    return AuthContext(
        user=user,
        scopes=list(claims.get("scopes", [])),
        client_id=claims.get("client_id"),
        jti=claims.get("jti"),
    )


class AsyncPassportGuard:
    def __init__(self, name: str, token_service: Any, provider: Any) -> None:
        self.name = name
        self._tokens = token_service
        self.provider = provider

    async def user_from_token(self, access_token: str) -> AuthContext:
        claims = await call(self._tokens.authenticate, access_token)
        return _context_from_claims(claims, await self._resolve_user(claims.get("sub")))

    async def _resolve_user(self, sub: Any) -> Any | None:
        if sub is None:
            return None
        user = await find_user_async(self.provider, sub)
        if user is None:
            raise InvalidToken("The token subject no longer exists.")
        if not await user_is_active_async(self.provider, user):
            raise InvalidToken(_INACTIVE_SUBJECT)
        return user
