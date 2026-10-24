"""Passport-style OAuth2 + JWT authentication for FastAPI.

Public API mirrors the config-driven guard/provider/passwords model of Laravel
Passport while staying idiomatic FastAPI:

    from fastapi_startkit_auth import AuthProvider, AuthConfig, OAuth2Config
"""
from __future__ import annotations

from .apitokens.facade import ApiToken
from .apitokens.manager import ApiTokenManager, AsyncApiTokenManager, NewApiToken
from .apitokens.models import ApiTokenRecord
from .apitokens.repository import ApiTokenRepository, InMemoryApiTokenRepository
from .concurrency import AsyncMisconfiguration
from .clients.models import Client
from .clients.repository import InMemoryClientRepository
from .config import (
    ApiTokenConfig,
    AuthConfig,
    OAuth2Config,
    OAuthClientConfig,
    OAuthClientsConfig,
    OAuthTokenConfig,
    OAuthTokensConfig,
    SessionConfig,
)
from .dependencies import (
    GuardDependency,
    auth,
    current_user,
    optional_user,
    require_abilities,
    require_scopes,
)
from .exceptions import (
    AccessDenied,
    AccessDeniedException,
    AuthenticationException,
    AuthError,
    AuthException,
    CsrfTokenMismatch,
    CsrfTokenMismatchException,
    InsufficientScope,
    InvalidClient,
    InvalidClientException,
    InvalidCredentialsException,
    InvalidGrant,
    InvalidGrantException,
    InvalidScope,
    InvalidScopeException,
    InvalidSession,
    InvalidTarget,
    InvalidTargetException,
    InvalidToken,
    InvalidTokenException,
    MissingScopeException,
    UnauthorizedClient,
    UnauthorizedClientException,
    UnsupportedGrantType,
    UnsupportedGrantTypeException,
    UnsupportedResponseType,
    UnsupportedResponseTypeException,
)
from .policy import GrantPolicy
from .facade import AsyncAuth, Auth
from .guards.chain import AsyncChainGuard, ChainGuard
from .guards.guard import AsyncPassportGuard, PassportGuard
from .guards.session import AsyncSessionGuard, SessionGuard
from .guards.token import AsyncTokenGuard, TokenGuard
from .manager import AuthManager, FeatureNotRegistered
from .middleware.context import AuthMiddleware
from .middleware.csrf import CsrfMiddleware
from .middleware.session import SessionMiddleware
from .passwords.broker import AsyncPasswordBroker, PasswordBroker
from .provider import AuthApiTokenProvider, AuthOAuth2Provider, AuthProvider, AuthSessionProvider
from .providers.memory import InMemoryUserProvider
from .providers.model import AsyncModelUserProvider, ModelUserProvider
from .sessions.facade import Session
from .sessions.models import SessionRecord
from .sessions.store import InMemorySessionStore, SessionStore
from .tokens.service import AsyncTokenService, TokenService

__version__ = "0.7.0"

__all__ = (
    "AuthConfig",
    "SessionConfig",
    "OAuth2Config",
    "OAuthClientConfig",
    "OAuthClientsConfig",
    "OAuthTokenConfig",
    "OAuthTokensConfig",
    "ApiTokenConfig",
    "AuthProvider",
    "AuthSessionProvider",
    "AuthOAuth2Provider",
    "AuthApiTokenProvider",
    "AuthMiddleware",
    "AuthManager",
    "FeatureNotRegistered",
    "auth",
    "Session",
    "ApiToken",
    "Client",
    "InMemoryClientRepository",
    "OrmClientRepository",
    "OrmSessionStore",
    "AccessDeniedException",
    "UnauthorizedClientException",
    "UnsupportedGrantTypeException",
    "UnsupportedResponseTypeException",
    "current_user",
    "GuardDependency",
    "optional_user",
    "require_scopes",
    "require_abilities",
    "AuthException",
    "AsyncMisconfiguration",
    "InvalidGrantException",
    "InvalidClientException",
    "InvalidCredentialsException",
    "InvalidTokenException",
    "MissingScopeException",
    "InvalidScopeException",
    "InvalidTargetException",
    "GrantPolicy",
    "AuthenticationException",
    "CsrfTokenMismatchException",
    "AccessDenied",
    "UnauthorizedClient",
    "UnsupportedGrantType",
    "UnsupportedResponseType",
    "AuthError",
    "InvalidGrant",
    "InvalidClient",
    "InvalidToken",
    "InsufficientScope",
    "InvalidScope",
    "InvalidTarget",
    "InvalidSession",
    "CsrfTokenMismatch",
    "Auth",
    "SessionGuard",
    "SessionMiddleware",
    "CsrfMiddleware",
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
    "ChainGuard",
    "AsyncChainGuard",
    "AsyncApiTokenManager",
    "PasswordBroker",
    "AsyncPasswordBroker",
    "InMemoryUserProvider",
    "ModelUserProvider",
    "AsyncModelUserProvider",
    "TokenService",
    "AsyncTokenService",
)


_ORM_EXPORTS = {
    "OrmClientRepository": ".clients.orm",
    "OrmSessionStore": ".sessions.orm",
}


def __getattr__(name: str):
    # The ORM stores need the optional fastapi-startkit framework; resolving them
    # on access keeps plain-FastAPI installs importable.
    if name in _ORM_EXPORTS:
        from importlib import import_module

        return getattr(import_module(_ORM_EXPORTS[name], __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
