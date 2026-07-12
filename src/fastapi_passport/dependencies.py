from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer

from .exceptions import AuthError, InsufficientScope, InvalidToken
from .guards.guard import AuthContext
from .manager import AuthManager

# auto_error=False so we can raise our own OAuth2-style JSON errors instead of
# FastAPI's default {"detail": ...} response.
_bearer = OAuth2PasswordBearer(tokenUrl="oauth/token", auto_error=False)


def get_auth_manager(request: Request) -> AuthManager:
    manager = getattr(request.app.state, "auth_manager", None)
    if manager is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError(
            "No AuthManager on the application. Did you register AuthProvider via Application?"
        )
    return manager


def current_context(
    token: str | None = Depends(_bearer),
    manager: AuthManager = Depends(get_auth_manager),
) -> AuthContext:
    """Resolve the bearer token to an :class:`AuthContext` or raise 401."""
    if not token:
        raise InvalidToken("Not authenticated.")
    return manager.guard().user_from_token(token)


def current_user(context: AuthContext = Depends(current_context)) -> Any:
    """Return the authenticated user model (401 if the token carries no user)."""
    if context.user is None:
        raise InvalidToken("This token is not associated with a user.")
    return context.user


def optional_user(
    token: str | None = Depends(_bearer),
    manager: AuthManager = Depends(get_auth_manager),
) -> Any | None:
    """Return the authenticated user, or ``None`` if unauthenticated/invalid."""
    if not token:
        return None
    try:
        return manager.guard().user_from_token(token).user
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
