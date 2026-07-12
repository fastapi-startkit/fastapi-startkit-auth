from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..exceptions import InvalidToken
from ..providers.base import UserProvider
from ..tokens.service import TokenService


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
        claims = self._tokens.authenticate(access_token)
        user = self._resolve_user(claims.get("sub"))
        return AuthContext(
            user=user,
            scopes=list(claims.get("scopes", [])),
            client_id=claims.get("client_id"),
            jti=claims.get("jti"),
        )

    def _resolve_user(self, sub: Any) -> Any | None:
        if sub is None:
            return None
        user = self.provider.retrieve_by_id(sub)
        # JWT `sub` is always a string; retry with an int id for numeric keys.
        if user is None and isinstance(sub, str) and sub.isdigit():
            user = self.provider.retrieve_by_id(int(sub))
        if user is None:
            raise InvalidToken("The token subject no longer exists.")
        return user
