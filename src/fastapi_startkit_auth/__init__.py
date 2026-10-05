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
from .clients.orm import OrmClientRepository
from .clients.repository import InMemoryClientRepository
from .config import (
    ApiTokenConfig,
    AuthConfig,
    OAuth2Config,
    OAuthClientsConfig,
    OAuthTokensConfig,
    SessionConfig,
)
from .dependencies import (
    auth,
    current_user,
    optional_user,
    require_abilities,
    require_scopes,
)
from .exceptions import (
    AccessDenied,
    AuthError,
    CsrfTokenMismatch,
    InsufficientScope,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    InvalidSession,
    InvalidTarget,
    InvalidToken,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
)
from .policy import GrantPolicy
from .facade import AsyncAuth, Auth
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
from .sessions.orm import OrmSessionStore
from .sessions.store import InMemorySessionStore, SessionStore
from .tokens.service import AsyncTokenService, TokenService

__version__ = "0.6.2"

__all__ = (
    "AuthConfig",
    "SessionConfig",
    "OAuth2Config",
    "OAuthClientsConfig",
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
    "AccessDenied",
    "UnauthorizedClient",
    "UnsupportedGrantType",
    "UnsupportedResponseType",
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
    "InvalidScope",
    "InvalidTarget",
    "GrantPolicy",
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
    "AsyncApiTokenManager",
    "PasswordBroker",
    "AsyncPasswordBroker",
    "InMemoryUserProvider",
    "ModelUserProvider",
    "AsyncModelUserProvider",
    "TokenService",
    "AsyncTokenService",
)

