"""Passport-style OAuth2 + JWT authentication for FastAPI.

Public API mirrors the config-driven guard/provider/passwords model of Laravel
Passport while staying idiomatic FastAPI:

    from fastapi_passport import Application, AuthProvider, AuthConfig

Attributes are resolved lazily so importing a single submodule never forces the
whole package to load.
"""
from __future__ import annotations

import importlib
from typing import Any

__version__ = "0.1.0"

_EXPORTS = {
    "AuthConfig": ("fastapi_passport.config", "AuthConfig"),
    "AuthProvider": ("fastapi_passport.provider", "AuthProvider"),
    "Application": ("fastapi_passport.application", "Application"),
    "AuthManager": ("fastapi_passport.manager", "AuthManager"),
    "current_user": ("fastapi_passport.dependencies", "current_user"),
    "optional_user": ("fastapi_passport.dependencies", "optional_user"),
    "require_scopes": ("fastapi_passport.dependencies", "require_scopes"),
    "AuthError": ("fastapi_passport.exceptions", "AuthError"),
    "InvalidGrant": ("fastapi_passport.exceptions", "InvalidGrant"),
    "InvalidClient": ("fastapi_passport.exceptions", "InvalidClient"),
    "InvalidToken": ("fastapi_passport.exceptions", "InvalidToken"),
    "InsufficientScope": ("fastapi_passport.exceptions", "InsufficientScope"),
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
