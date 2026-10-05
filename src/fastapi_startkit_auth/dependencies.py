from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer

from .concurrency import call
from .exceptions import AuthError, InsufficientScope, InvalidToken
from .guards.guard import AuthContext
from .manager import AuthManager
from .request_context import _auth_request

# auto_error=False so we can raise our own OAuth2-style JSON errors instead of
# FastAPI's default {"detail": ...} response.
_bearer = OAuth2PasswordBearer(tokenUrl="oauth/token", auto_error=False)


def get_auth_manager(request: Request) -> AuthManager:
    context = _auth_request.get()
    if context is not None and context.active:
        return context.manager
    manager = getattr(request.app.state, "auth_manager", None)
    if manager is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError("No AuthManager on the application. Did you register AuthProvider?")
    return manager


def _bearer_token(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


async def resolve_context(request: Request, manager: AuthManager, guard: str | None = None) -> AuthContext:
    """Resolve the request credential through ``guard`` (default guard if ``None``) or raise 401.

    Guards that implement ``authenticate(request)`` (session and token drivers)
    read the request themselves; the rest take the bearer token. Async guards
    are awaited; sync guards run in the threadpool.
    """
    resolved = manager.guard(guard)
    authenticate = getattr(resolved, "authenticate", None)
    if authenticate is not None:
        return await call(authenticate, request)
    token = _bearer_token(request)
    if not token:
        raise InvalidToken("Not authenticated.")
    return await call(resolved.user_from_token, token)


async def current_context(
    request: Request,
    token: str | None = Depends(_bearer),
    manager: AuthManager = Depends(get_auth_manager),
) -> AuthContext:
    """Resolve the request credential to an :class:`AuthContext` or raise 401."""
    return await resolve_context(request, manager)


async def auth(context: AuthContext = Depends(current_context)) -> AuthContext:
    """Like ``current_context`` but also rejects user-less (client_credentials) tokens."""
    if context.user is None:
        raise InvalidToken("This token is not associated with a user.")
    return context


def current_user(context: AuthContext = Depends(current_context)) -> Any:
    """Return the authenticated user model (401 if the token carries no user)."""
    if context.user is None:
        raise InvalidToken("This token is not associated with a user.")
    return context.user


async def optional_user(
    request: Request,
    token: str | None = Depends(_bearer),
    manager: AuthManager = Depends(get_auth_manager),
) -> Any | None:
    """Return the authenticated user, or ``None`` if unauthenticated/invalid."""
    try:
        return (await resolve_context(request, manager)).user
    except AuthError:
        return None


def require_scopes(*scopes: str, mode: str = "all") -> Callable[..., AuthContext]:
    """Dependency factory enforcing token abilities (Passport-style scopes).

    ``mode="all"`` requires every scope; ``mode="any"`` requires at least one.
    Raises 403 ``insufficient_scope`` when the token lacks them.
    """
    required = list(scopes)

    def dependency(context: AuthContext = Depends(current_context)) -> AuthContext:
        ok = context.can_any(required) if mode == "any" else context.can_all(required)
        if not ok:
            raise InsufficientScope(
                f"Requires scope(s): {' '.join(required)} (mode={mode})."
            )
        return context

    return dependency


# Sanctum-flavored name for the same check: API-token abilities live in
# ``AuthContext.scopes``, so scope and ability enforcement are one mechanism.
require_abilities = require_scopes
