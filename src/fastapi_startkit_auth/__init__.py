"""Passport-style OAuth2 + JWT authentication for FastAPI.

Public API mirrors the config-driven guard/provider/passwords model of Laravel
Passport while staying idiomatic FastAPI:

    from fastapi_startkit_auth import Application, AuthProvider, AuthConfig
"""
from __future__ import annotations

from .apitokens.manager import ApiTokenManager, AsyncApiTokenManager, NewApiToken
from .apitokens.models import ApiTokenRecord
from .apitokens.repository import ApiTokenRepository, InMemoryApiTokenRepository
from .application import Application
from .concurrency import AsyncMisconfiguration
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
from .facade import AsyncAuth, Auth
from .guards.guard import AsyncPassportGuard, PassportGuard
from .guards.session import AsyncSessionGuard, SessionGuard
from .guards.token import AsyncTokenGuard, TokenGuard
from .manager import AuthManager
from .middleware.csrf import CsrfMiddleware
from .middleware.session import SessionMiddleware
from .passwords.broker import AsyncPasswordBroker, PasswordBroker
from .provider import AuthProvider
from .providers.memory import InMemoryUserProvider
from .providers.model import AsyncModelUserProvider, ModelUserProvider
from .sessions.models import SessionRecord
from .sessions.store import InMemorySessionStore, SessionStore
from .tokens.service import AsyncTokenService, TokenService

__version__ = "0.6.2"

__all__ = (
    "AuthConfig",
    "AuthProvider",
    "Application",
    "AuthManager",
    "current_user",
    "optional_user",
    "require_scopes",
    "require_abilities",
    "AuthError",
    "AsyncMisconfiguration",
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
    "TokenGuard",
    "ApiTokenManager",
    "NewApiToken",
    "ApiTokenRecord",
    "ApiTokenRepository",
    "InMemoryApiTokenRepository",
    "AsyncAuth",
    "PassportGuard",
    "AsyncPassportGuard",
    "AsyncSessionGuard",
    "AsyncTokenGuard",
    "AsyncApiTokenManager",
    "PasswordBroker",
    "AsyncPasswordBroker",
    "InMemoryUserProvider",
    "ModelUserProvider",
    "AsyncModelUserProvider",
    "TokenService",
    "AsyncTokenService",
)


def __getattr__(name: str):
    # AuthServiceProvider subclasses the optional `fastapi-startkit` framework,
    # which is not a runtime dependency. Resolve it on access so plain-FastAPI
    # installs import cleanly and only pay for the extra when they use it.
    if name == "AuthServiceProvider":
        from .startkit import AuthServiceProvider

        return AuthServiceProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
