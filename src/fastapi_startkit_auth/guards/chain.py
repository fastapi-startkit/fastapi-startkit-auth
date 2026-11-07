from __future__ import annotations

from typing import Any

from fastapi import Request

from ..concurrency import call
from ..exceptions import AuthException, InvalidTokenException
from .guard import AuthContext, Guard
from .session import SessionGuard


def _bearer_token(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


class ChainGuard:
    def __init__(self, name: str, guards: list[Guard]) -> None:
        if not guards:
            raise ValueError(f"Chain guard {name!r} needs at least one member guard.")
        self.name = name
        self.guards = guards
        self.provider = guards[0].provider

    async def authenticate(self, request: Request) -> AuthContext:
        failures: list[AuthException] = []
        for guard in self.guards:
            try:
                return await _authenticate(guard, request)
            except AuthException as failure:
                if _rejected_presented_token(guard, request):
                    raise
                failures.append(failure)
        raise failures[0]

    async def user_from_token(self, access_token: str) -> AuthContext:
        failures: list[AuthException] = []
        for guard in _token_members(self.guards):
            try:
                return await call(guard.user_from_token, access_token)
            except AuthException as failure:
                failures.append(failure)
        raise _first_failure(failures)


def _rejected_presented_token(guard: Any, request: Request) -> bool:
    return _presented_token(guard, request) is not None


def _presented_token(guard: Any, request: Request) -> str | None:
    presented_token = getattr(guard, "presented_token", None)
    if presented_token is not None:
        return presented_token(request)
    if getattr(guard, "authenticate", None) is None:
        return _bearer_token(request)
    return None


def _token_members(guards: list[Guard]) -> list[Guard]:
    return [guard for guard in guards if not isinstance(guard, (SessionGuard, SessionGuard))]


def _first_failure(failures: list[AuthException]) -> AuthException:
    return failures[0] if failures else InvalidTokenException("Not authenticated.")


async def _authenticate(guard: Any, request: Request) -> AuthContext:
    authenticate = getattr(guard, "authenticate", None)
    if authenticate is not None:
        return await call(authenticate, request)
    token = _bearer_token(request)
    if token is None:
        raise InvalidTokenException("Not authenticated.")
    return await call(guard.user_from_token, token)
