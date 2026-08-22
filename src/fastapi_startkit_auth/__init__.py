"""Passport-style OAuth2 + JWT authentication for FastAPI.

Public API mirrors the config-driven guard/provider/passwords model of Laravel
Passport while staying idiomatic FastAPI:

    from fastapi_startkit_auth import Application, AuthProvider, AuthConfig

Attributes are resolved lazily so importing a single submodule never forces the
whole package to load.
"""
from __future__ import annotations

import importlib
from typing import Any

__version__ = "0.1.0"

_EXPORTS = {
    "AuthConfig": ("fastapi_startkit_auth.config", "AuthConfig"),
    "AuthProvider": ("fastapi_startkit_auth.provider", "AuthProvider"),
    "Application": ("fastapi_startkit_auth.application", "Application"),
    "AuthManager": ("fastapi_startkit_auth.manager", "AuthManager"),
    "current_user": ("fastapi_startkit_auth.dependencies", "current_user"),
    "optional_user": ("fastapi_startkit_auth.dependencies", "optional_user"),
    "require_scopes": ("fastapi_startkit_auth.dependencies", "require_scopes"),
    "AuthError": ("fastapi_startkit_auth.exceptions", "AuthError"),
    "InvalidGrant": ("fastapi_startkit_auth.exceptions", "InvalidGrant"),
    "InvalidClient": ("fastapi_startkit_auth.exceptions", "InvalidClient"),
    "InvalidToken": ("fastapi_startkit_auth.exceptions", "InvalidToken"),
    "InsufficientScope": ("fastapi_startkit_auth.exceptions", "InsufficientScope"),
    "InvalidSession": ("fastapi_startkit_auth.exceptions", "InvalidSession"),
    "CsrfTokenMismatch": ("fastapi_startkit_auth.exceptions", "CsrfTokenMismatch"),
    "Auth": ("fastapi_startkit_auth.facade", "Auth"),
    "SessionGuard": ("fastapi_startkit_auth.guards.session", "SessionGuard"),
    "SessionMiddleware": ("fastapi_startkit_auth.middleware.session", "SessionMiddleware"),
    "CsrfMiddleware": ("fastapi_startkit_auth.middleware.csrf", "CsrfMiddleware"),
    "AuthServiceProvider": ("fastapi_startkit_auth.startkit", "AuthServiceProvider"),
    "SessionRecord": ("fastapi_startkit_auth.sessions.models", "SessionRecord"),
    "SessionStore": ("fastapi_startkit_auth.sessions.store", "SessionStore"),
    "InMemorySessionStore": ("fastapi_startkit_auth.sessions.store", "InMemorySessionStore"),
    "SqlSessionStore": ("fastapi_startkit_auth.sessions.sql", "SqlSessionStore"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        module_name, attr = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(importlib.import_module(module_name), attr)


def __dir__() -> list[str]:
    return sorted(__all__)
