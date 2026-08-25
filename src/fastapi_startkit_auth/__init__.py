"""Passport-style OAuth2 + JWT authentication for FastAPI.

Public API mirrors the config-driven guard/provider/passwords model of Laravel
Passport while staying idiomatic FastAPI:

    from fastapi_startkit_auth import AuthProvider, AuthConfig, register_auth
"""
from __future__ import annotations

from .apitokens.manager import ApiTokenManager, NewApiToken
from .apitokens.models import ApiTokenRecord
from .apitokens.repository import ApiTokenRepository, InMemoryApiTokenRepository
from .apitokens.sql import SqlApiTokenRepository
from .config import AuthConfig
from .dependencies import (
    current_user,
    optional_user,
    require_abilities,
    require_scopes,
)
from .exceptions import (
    AuthError,
    CsrfTokenMismatch,
    InsufficientScope,
    InvalidClient,
    InvalidGrant,
    InvalidSession,
    InvalidToken,
)
from .facade import Auth
from .guards.session import SessionGuard
from .guards.token import TokenGuard
from .manager import AuthManager
from .middleware.csrf import CsrfMiddleware
from .middleware.session import SessionMiddleware
from .provider import AuthProvider, register_auth
from .sessions.models import SessionRecord
from .startkit import AuthServiceProvider
from .sessions.sql import SqlSessionStore
from .sessions.store import InMemorySessionStore, SessionStore

__version__ = "0.2.0"

__all__ = (
    "AuthConfig",
    "AuthProvider",
    "register_auth",
    "AuthManager",
    "current_user",
    "optional_user",
    "require_scopes",
    "require_abilities",
    "AuthError",
    "InvalidGrant",
    "InvalidClient",
    "InvalidToken",
    "InsufficientScope",
    "InvalidSession",
    "CsrfTokenMismatch",
    "Auth",
    "SessionGuard",
    "SessionMiddleware",
    "CsrfMiddleware",
    "AuthServiceProvider",
    "SessionRecord",
    "SessionStore",
    "InMemorySessionStore",
    "SqlSessionStore",
    "TokenGuard",
    "ApiTokenManager",
    "NewApiToken",
    "ApiTokenRecord",
    "ApiTokenRepository",
    "InMemoryApiTokenRepository",
    "SqlApiTokenRepository",
)
