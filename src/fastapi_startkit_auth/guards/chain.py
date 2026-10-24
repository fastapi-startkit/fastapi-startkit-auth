from __future__ import annotations

from typing import Any

from fastapi import Request

from ..concurrency import call, ensure_sync, is_async
from ..exceptions import AuthException, InvalidTokenException
from .guard import AuthContext, Guard


def _bearer_token(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def guard_is_async(guard: Any) -> bool:
    return is_async(guard, "authenticate") or is_async(guard, "user_from_token")


class ChainGuard:
    """Tries each member guard in order and returns the first that authenticates.

    Corresponds to a ``{"driver": "chain", "guards": [...]}`` entry, e.g. a
    bearer-token guard backed by the first-party browser session.
    """

    def __init__(self, name: str, guards: list[Guard]) -> None:
        if not guards:
            raise ValueError(f"Chain guard {name!r} needs at least one member guard.")
        self.name = name
        self.guards = guards
        self.provider = guards[0].provider

    def authenticate(self, request: Request) -> AuthContext:
        failures: list[AuthException] = []
        for guard in self.guards:
            try:
                return ensure_sync(_authenticate(guard, request), f"Guard {guard.name!r}")
            except AuthException as failure:
                failures.append(failure)
        raise failures[0]

    def user_from_token(self, access_token: str) -> AuthContext:
        failures: list[AuthException] = []
        for guard in self.guards:
            try:
                return ensure_sync(guard.user_from_token(access_token), f"Guard {guard.name!r}")
            except AuthException as failure:
                failures.append(failure)
        raise failures[0]


class AsyncChainGuard:
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
                return await _authenticate_async(guard, request)
            except AuthException as failure:
                failures.append(failure)
        raise failures[0]

    async def user_from_token(self, access_token: str) -> AuthContext:
        failures: list[AuthException] = []
        for guard in self.guards:
            try:
                return await call(guard.user_from_token, access_token)
            except AuthException as failure:
                failures.append(failure)
        raise failures[0]


def _authenticate(guard: Any, request: Request) -> Any:
    authenticate = getattr(guard, "authenticate", None)
    if authenticate is not None:
        return authenticate(request)
    token = _bearer_token(request)
    if token is None:
        raise InvalidTokenException("Not authenticated.")
    return guard.user_from_token(token)


async def _authenticate_async(guard: Any, request: Request) -> AuthContext:
    authenticate = getattr(guard, "authenticate", None)
    if authenticate is not None:
        return await call(authenticate, request)
    token = _bearer_token(request)
    if token is None:
        raise InvalidTokenException("Not authenticated.")
    return await call(guard.user_from_token, token)
