from __future__ import annotations

import secrets
import warnings
from typing import Any, Callable

from .apitokens.manager import ApiTokenManager, AsyncApiTokenManager
from .apitokens.repository import ApiTokenRepository, InMemoryApiTokenRepository
from .clients.models import Client
from .clients.repository import InMemoryClientRepository
from .concurrency import call, ensure_sync, has_async_methods
from .config import (
    DEPRECATED_OAUTH2_ATTRIBUTES,
    ApiTokenConfig,
    AuthConfig,
    OAuth2Config,
    SessionConfig,
    as_config_class,
    config_values,
    resolve_config,
)
from .grants.authorization_code import AsyncAuthorizationCodeGrant, AuthorizationCodeGrant
from .grants.client_credentials import AsyncClientCredentialsGrant, ClientCredentialsGrant
from .grants.password import AsyncPasswordGrant, PasswordGrant
from .grants.refresh import AsyncRefreshTokenGrant, RefreshTokenGrant
from .guards.guard import AsyncPassportGuard, Guard, PassportGuard
from .guards.session import AsyncSessionGuard, SessionGuard
from .guards.token import AsyncTokenGuard, TokenGuard
from .passwords.broker import AsyncPasswordBroker, PasswordBroker
from .passwords.repository import InMemoryPasswordResetRepository
from .policy import GrantPolicy
from .providers.base import UserProvider, active_user_async, is_async_provider
from .providers.memory import InMemoryUserProvider
from .providers.model import AsyncModelUserProvider, ModelUserProvider
from .security.hashing import BcryptHasher
from .security.jwt import JWTEncoder
from .sessions.store import InMemorySessionStore, SessionStore
from .tokens.repository import InMemoryTokenRepository
from .tokens.service import AsyncTokenService, TokenService

GuardFactory = Callable[[str, dict[str, Any]], Guard]

FEATURE_PROVIDERS = {
    "session": "AuthSessionProvider",
    "oauth2": "AuthOAuth2Provider",
    "passport": "AuthOAuth2Provider",
    "token": "AuthApiTokenProvider",
}

SESSION_GUARDS = (SessionGuard, AsyncSessionGuard)

_REMOVED_STORES = ("sql", "async_sql")


def _reject_removed_store(kind: str, section: str) -> None:
    if kind in _REMOVED_STORES:
        raise ValueError(
            f'{section} store "{kind}" was removed: use store "database" (optional ORM '
            '"connection" name) after running the published migrations.'
        )


class FeatureNotRegistered(RuntimeError):
    def __init__(self, feature: str, provider: str) -> None:
        super().__init__(f"{feature} is not enabled; register {provider} after AuthProvider.")


class AuthManager:
    """Central registry built from an :class:`AuthConfig`.

    ``AuthConfig`` declares guards, user providers and password brokers. Each
    feature is switched on by its provider (``use_sessions``, ``use_oauth2``,
    ``use_api_tokens``) with its own config; guards are built lazily, so a guard
    whose feature was never registered fails with :class:`FeatureNotRegistered`.
    """

    def __init__(self, config: Any = None) -> None:
        self._config = as_config_class(config if config is not None else AuthConfig)
        cfg = self._config
        self.hasher = BcryptHasher(rounds=cfg.get("bcrypt_rounds", 12))
        self._notifier = cfg.get("password_reset_notifier")
        self.debug_expose_reset_token = bool(cfg.get("debug_expose_reset_token", False))
        self._guard_specs: dict[str, dict[str, Any]] = {
            name: {"driver": "passport", **config_values(spec)} for name, spec in cfg.get("guards", {}).items()
        }
        self._providers: dict[str, UserProvider] = {
            name: self._build_provider(spec) for name, spec in cfg.get("providers", {}).items()
        }
        self._brokers: dict[str, PasswordBroker | AsyncPasswordBroker] = {
            name: self._build_broker(spec) for name, spec in cfg.get("passwords", {}).items()
        }
        self._guard_drivers: dict[str, GuardFactory] = {}
        self._guards: dict[str, Guard] | None = None
        self._session_config: SessionConfig | None = None
        self._session_store: SessionStore | None = None
        self._oauth2_config: OAuth2Config | None = None
        self._api_token_config: ApiTokenConfig | None = None
        self._api_tokens: ApiTokenManager | AsyncApiTokenManager | None = None
        self.csrf_exempt_paths: list[str] = []

    @property
    def config(self) -> type[AuthConfig]:
        return self._config

    # --- features ------------------------------------------------------
    def use_sessions(self, config: Any = None) -> AuthManager:
        self._session_config = resolve_config(config, SessionConfig)
        self._session_store = None
        self.register_guard_driver("session", self._build_session_guard)
        return self

    def use_oauth2(self, config: Any = None) -> AuthManager:
        oauth2 = self._with_deprecated_fallback(resolve_config(config, OAuth2Config))
        self._oauth2_config = oauth2
        key = oauth2.key
        if not key:
            key = secrets.token_urlsafe(48)
            warnings.warn(
                "OAuth2Config.key is not set; generated an ephemeral signing key. "
                "Tokens will be invalidated on restart. Set a stable key in production.",
                stacklevel=2,
            )
        self.encoder = JWTEncoder(secret=key, algorithm=oauth2.algorithm, issuer=oauth2.issuer)
        self.grant_policy = GrantPolicy(
            scopes=frozenset(oauth2.scopes),
            resources=frozenset(oauth2.resources),
            pkce_methods=frozenset(oauth2.pkce_methods),
            require_pkce=oauth2.require_pkce,
            require_redirect_uri=oauth2.require_redirect_uri,
        )
        self.token_repository = self._build_token_repository(oauth2)
        token_service_class = AsyncTokenService if has_async_methods(self.token_repository) else TokenService
        self.token_service = token_service_class(
            encoder=self.encoder,
            repository=self.token_repository,
            access_ttl=oauth2.access_token_ttl,
            refresh_ttl=oauth2.refresh_token_ttl,
            personal_access_ttl=oauth2.personal_access_token_ttl,
        )
        self.client_repository = self._build_client_repository(oauth2)
        self.register_guard_driver("passport", self._build_passport_guard)
        self.register_guard_driver("oauth2", self._build_passport_guard)
        return self

    def use_api_tokens(self, config: Any = None) -> AuthManager:
        self._api_token_config = resolve_config(config, ApiTokenConfig)
        self._api_tokens = None
        self.register_guard_driver("token", self._build_token_guard)
        return self

    def _with_deprecated_fallback(self, oauth2: OAuth2Config) -> OAuth2Config:
        defaults = OAuth2Config()
        for name in DEPRECATED_OAUTH2_ATTRIBUTES:
            if not hasattr(self._config, name):
                continue
            warnings.warn(
                f"AuthConfig.{name} is deprecated; set OAuth2Config.{name} instead.",
                DeprecationWarning,
                stacklevel=3,
            )
            # An explicit OAuth2Config value always wins over the legacy attribute.
            if getattr(oauth2, name) == getattr(defaults, name):
                setattr(oauth2, name, getattr(self._config, name))
        oauth2.__post_init__()
        return oauth2

    @property
    def sessions_enabled(self) -> bool:
        return self._session_config is not None

    @property
    def oauth2_enabled(self) -> bool:
        return self._oauth2_config is not None

    @property
    def api_tokens_enabled(self) -> bool:
        return self._api_token_config is not None

    @property
    def session_config(self) -> SessionConfig:
        if self._session_config is None:
            raise FeatureNotRegistered("Session authentication", "AuthSessionProvider")
        return self._session_config

    @property
    def oauth2_config(self) -> OAuth2Config:
        if self._oauth2_config is None:
            raise FeatureNotRegistered("OAuth2", "AuthOAuth2Provider")
        return self._oauth2_config

    @property
    def api_token_config(self) -> ApiTokenConfig:
        if self._api_token_config is None:
            raise FeatureNotRegistered("API tokens", "AuthApiTokenProvider")
        return self._api_token_config

    @property
    def spa_enabled(self) -> bool:
        return self.api_tokens_enabled and self.api_token_config.stateful

    @property
    def stateful_origins(self) -> list[str]:
        return list(self.api_token_config.stateful_origins) if self.spa_enabled else []

    def validate(self) -> None:
        guards = self._all_guards()
        if self.spa_enabled:
            if not self.sessions_enabled:
                raise FeatureNotRegistered(
                    "SPA authentication (ApiTokenConfig.stateful_origins)", "AuthSessionProvider"
                )
            name = self.api_token_config.session_guard
            if not isinstance(guards.get(name), SESSION_GUARDS):
                raise ValueError(
                    f"ApiTokenConfig.session_guard {name!r} must name a session guard in AuthConfig.guards."
                )

    # --- guards ---------------------------------------------------------
    def register_guard_driver(self, driver: str, factory: GuardFactory) -> None:
        """Register a factory that builds guards for a config ``driver`` key.

        Guards are built on first use, so drivers may be registered any time
        before then; registering one drops already-built guards.
        """
        self._guard_drivers[driver] = factory
        self._guards = None

    def _all_guards(self) -> dict[str, Guard]:
        if self._guards is None:
            self._guards = {name: self._build_guard(name, spec) for name, spec in self._guard_specs.items()}
        return self._guards

    def _build_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        driver = spec["driver"]
        factory = self._guard_drivers.get(driver)
        if factory is not None:
            return factory(name, spec)
        if driver in FEATURE_PROVIDERS:
            raise FeatureNotRegistered(f"Guard {name!r} uses the {driver!r} driver, which", FEATURE_PROVIDERS[driver])
        raise ValueError(f"Unknown auth guard driver: {driver!r}")

    def _build_passport_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        provider = self._require_provider(spec.get("provider"))
        audience = spec.get("audience")
        if audience is not None and audience not in self.grant_policy.resources:
            warnings.warn(
                f"Guard {name!r} requires audience {audience!r}, which OAuth2Config.resources does not list; "
                "no token can be issued for it.",
                stacklevel=2,
            )
        guard_class = AsyncPassportGuard if is_async_provider(provider) or self._tokens_async() else PassportGuard
        return guard_class(name=name, token_service=self.token_service, provider=provider, audience=audience)

    def _build_session_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        provider = self._require_provider(spec.get("provider"))
        if not self.session_config.secure:
            warnings.warn(
                "SessionConfig.secure is False; the session cookie will be sent over plain HTTP. "
                "Enable it in production.",
                stacklevel=2,
            )
        store = self.session_store
        guard_class = AsyncSessionGuard if is_async_provider(provider) or has_async_methods(store) else SessionGuard
        return guard_class(name=name, store=store, provider=provider, ttl=self.session_config.ttl)

    def _build_token_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        provider = self._require_provider(spec.get("provider"))
        config = self.api_token_config
        session_guard = config.session_guard if config.stateful else None
        tokens = self.api_tokens
        session_async = session_guard is not None and has_async_methods(self.session_store)
        guard_class = (
            AsyncTokenGuard
            if is_async_provider(provider) or isinstance(tokens, AsyncApiTokenManager) or session_async
            else TokenGuard
        )
        return guard_class(
            name=name,
            tokens=tokens,
            provider=provider,
            header=config.header,
            session_guard=(lambda: self.guard(session_guard)) if session_guard else None,
        )

    def guard(self, name: str | None = None) -> Guard:
        name = name or self.default_guard_name()
        guards = self._all_guards()
        if name not in guards:
            raise ValueError(f"Auth guard {name!r} is not defined in AuthConfig.guards")
        return guards[name]

    def guard_for_driver(self, *drivers: str) -> Guard | None:
        return next(
            (self.guard(name) for name, spec in self._guard_specs.items() if spec.get("driver") in drivers),
            None,
        )

    def session_guard(self, name: str | None = None) -> SessionGuard | AsyncSessionGuard:
        if name is not None:
            guard: Any = self.guard(name)
        elif self.default_guard_is_session():
            guard = self.guard()
        else:
            guard = next((g for g in self._all_guards().values() if isinstance(g, SESSION_GUARDS)), None)
        if not isinstance(guard, SESSION_GUARDS):
            raise RuntimeError(
                f"Auth guard {name or self.default_guard_name()!r} is not a session guard; "
                "login and logout require a session guard registered by AuthSessionProvider."
            )
        return guard

    def default_guard_is_session(self) -> bool:
        return isinstance(self._all_guards().get(self.default_guard_name()), SESSION_GUARDS)

    def session_guard_name(self) -> str | None:
        return next((name for name, guard in self._all_guards().items() if isinstance(guard, SESSION_GUARDS)), None)

    def has_session_guard(self) -> bool:
        return self.session_guard_name() is not None

    def default_guard_name(self) -> str:
        return self._config.get("default", {}).get("guard")

    # --- stores ---------------------------------------------------------
    @property
    def session_store(self) -> SessionStore:
        if self._session_store is None:
            self._session_store = self._build_session_store()
        return self._session_store

    def _build_session_store(self) -> SessionStore:
        config = self.session_config
        if config.store == "memory":
            return InMemorySessionStore(idle_ttl=config.idle_ttl)
        if config.store == "database":
            from .sessions.orm import OrmSessionStore

            return OrmSessionStore(config.connection, idle_ttl=config.idle_ttl, purge_interval=config.purge_interval)
        _reject_removed_store(config.store, "SessionConfig")
        if config.store == "instance":
            return config.instance
        raise ValueError(f"Unknown session store: {config.store!r}")

    @property
    def api_tokens(self) -> ApiTokenManager | AsyncApiTokenManager:
        if self._api_tokens is None:
            config = self.api_token_config
            repository = self._build_api_token_repository(config)
            manager_class = AsyncApiTokenManager if has_async_methods(repository) else ApiTokenManager
            self._api_tokens = manager_class(
                repository=repository, default_ttl=config.ttl, purge_interval=config.purge_interval
            )
        return self._api_tokens

    def _build_api_token_repository(self, config: ApiTokenConfig) -> ApiTokenRepository:
        if config.store == "memory":
            return InMemoryApiTokenRepository()
        if config.store == "database":
            from .apitokens.orm import OrmApiTokenRepository

            return OrmApiTokenRepository(config.connection)
        _reject_removed_store(config.store, "ApiTokenConfig")
        if config.store == "instance":
            return config.instance
        raise ValueError(f"Unknown API token store: {config.store!r}")

    def _build_token_repository(self, config: OAuth2Config) -> Any:
        tokens = config.tokens
        if tokens.store == "memory":
            return InMemoryTokenRepository()
        if tokens.store == "database":
            from .tokens.orm import OrmTokenRepository

            return OrmTokenRepository(tokens.connection)
        _reject_removed_store(tokens.store, "OAuth2Config.tokens")
        if tokens.store == "instance":
            return tokens.instance
        raise ValueError(f"Unknown OAuth token store: {tokens.store!r}")

    def _build_client_repository(self, config: OAuth2Config) -> Any:
        clients = config.clients
        if clients.store == "memory":
            return InMemoryClientRepository(hasher=self.hasher)
        if clients.store == "database":
            from .clients.orm import OrmClientRepository

            return OrmClientRepository(clients.connection, hasher=self.hasher)
        if clients.store == "instance":
            return clients.instance
        raise ValueError(f"Unknown OAuth client store: {clients.store!r}")

    # --- providers and brokers -----------------------------------------
    def _build_provider(self, spec: dict[str, Any]) -> UserProvider:
        driver = spec.get("driver", "instance")
        if driver == "instance":
            return spec["instance"]
        if driver == "factory":
            return spec["factory"]()
        if driver == "memory":
            provider = InMemoryUserProvider(
                hasher=self.hasher,
                username_field=spec.get("username_field", "email"),
                password_field=spec.get("password_field", "password"),
                password_key=spec.get("password_key"),
                is_active=spec.get("is_active"),
            )
            for user in spec.get("users", []):
                provider.add(user)
            return provider
        if driver in ("masoniteorm", "orm", "model", "async_model"):
            provider_class = AsyncModelUserProvider if driver == "async_model" else ModelUserProvider
            return provider_class(
                model=spec["model"],
                hasher=self.hasher,
                username_field=spec.get("username_field", "email"),
                password_field=spec.get("password_field", "password"),
                password_key=spec.get("password_key"),
                is_active=spec.get("is_active"),
                id_field=spec.get("id_field", "id"),
            )
        raise ValueError(f"Unknown user provider driver: {driver!r}")

    def _build_broker(self, spec: dict[str, Any]) -> PasswordBroker | AsyncPasswordBroker:
        provider = self._resolve_broker_provider(spec.get("provider"))
        broker_class = AsyncPasswordBroker if is_async_provider(provider) else PasswordBroker
        return broker_class(
            user_provider=provider,
            repository=InMemoryPasswordResetRepository(),
            hasher=self.hasher,
            expire_minutes=spec.get("expire", 60),
            throttle_seconds=spec.get("throttle", 60),
            notifier=self._notifier,
        )

    def _resolve_broker_provider(self, name: str | None) -> UserProvider:
        # The passwords `provider` key may reference a providers entry; fall back
        # to the default guard's provider if the name doesn't resolve.
        if name and name in self._providers:
            return self._providers[name]
        guard_spec = self._guard_specs.get(self.default_guard_name(), {})
        return self._require_provider(guard_spec.get("provider"))

    def _require_provider(self, name: str | None) -> UserProvider:
        if name not in self._providers:
            raise ValueError(f"Auth provider {name!r} is not defined in AuthConfig.providers")
        return self._providers[name]

    def provider(self, name: str) -> UserProvider:
        return self._require_provider(name)

    def broker(self, name: str | None = None) -> PasswordBroker | AsyncPasswordBroker:
        name = name or self._config.get("default", {}).get("passwords")
        if name not in self._brokers:
            raise ValueError(f"Password broker {name!r} is not defined in AuthConfig.passwords")
        return self._brokers[name]

    @property
    def has_password_brokers(self) -> bool:
        return bool(self._brokers)

    # --- OAuth2 ---------------------------------------------------------
    @property
    def grant_types(self) -> list[str]:
        return list(self.oauth2_config.grant_types)

    def grant_enabled(self, grant: str) -> bool:
        return grant in self.oauth2_config.grant_types

    @property
    def oauth_issuer(self) -> str | None:
        return self.oauth2_config.issuer

    @property
    def authorization_guard_name(self) -> str:
        return self.oauth2_config.authorization_guard or self.default_guard_name()

    @property
    def scopes(self) -> dict[str, str]:
        return dict(self.oauth2_config.scopes)

    def resolve_scopes(self, scopes: list[str] | None) -> list[str]:
        """Apply ``default_scopes`` to a request naming none, then dedupe and check the catalog."""
        requested = list(self.oauth2_config.default_scopes) if not scopes else list(scopes)
        self.grant_policy.check_scopes(requested)
        return list(dict.fromkeys(requested))

    def _tokens_async(self) -> bool:
        return isinstance(self.token_service, AsyncTokenService)

    def _grants_async(self, provider: Any) -> bool:
        return self._tokens_async() or (provider is not None and is_async_provider(provider))

    def _owner_grants_async(self) -> bool:
        # Owner re-checks resolve their provider per token, so any async
        # provider or client store requires the async grant.
        return (
            self._tokens_async()
            or has_async_methods(self.client_repository)
            or any(is_async_provider(p) for p in self._providers.values())
        )

    def _default_owner_provider(self) -> Any:
        if self.authorization_guard_name not in self._guard_specs:
            return None
        return getattr(self.guard(self.authorization_guard_name), "provider", None)

    def provider_for_client(self, client: Client | None) -> Any:
        """The user provider whose users ``client`` acts for.

        A client registered with a ``provider`` acts for that provider's users;
        otherwise (or with no client) the authorization guard's provider applies.
        """
        if client is not None and client.provider:
            return self._require_provider(client.provider)
        return self._default_owner_provider()

    def owner_provider(self, client_id: str | None = None) -> Any:
        client = ensure_sync(self.client_repository.find(client_id), "The client store's find") if client_id else None
        return self.provider_for_client(client)

    async def owner_provider_async(self, client_id: str | None = None) -> Any:
        client = await call(self.client_repository.find, client_id) if client_id else None
        return self.provider_for_client(client)

    def password_grant(self, guard: str | None = None, client: Client | None = None) -> PasswordGrant | AsyncPasswordGrant:
        provider = self.provider_for_client(client) if client is not None and client.provider else None
        if provider is None:
            provider = self.guard(guard).provider
        grant_class = AsyncPasswordGrant if self._grants_async(provider) else PasswordGrant
        return grant_class(self.token_service, provider, self.grant_policy, client)

    def client_credentials_grant(self) -> ClientCredentialsGrant | AsyncClientCredentialsGrant:
        grant_class = AsyncClientCredentialsGrant if self._tokens_async() else ClientCredentialsGrant
        return grant_class(self.token_service, self.grant_policy)

    def refresh_grant(self) -> RefreshTokenGrant | AsyncRefreshTokenGrant:
        if self._owner_grants_async():
            return AsyncRefreshTokenGrant(self.token_service, owner_provider=self.owner_provider_async)
        return RefreshTokenGrant(self.token_service, owner_provider=self.owner_provider)

    def authorization_code_grant(self) -> AuthorizationCodeGrant | AsyncAuthorizationCodeGrant:
        code_ttl = self.oauth2_config.authorization_code_ttl
        if self._owner_grants_async():
            return AsyncAuthorizationCodeGrant(
                self.token_service, code_ttl=code_ttl, owner_provider=self.owner_provider_async, policy=self.grant_policy
            )
        return AuthorizationCodeGrant(
            self.token_service, code_ttl=code_ttl, owner_provider=self.owner_provider, policy=self.grant_policy
        )

    async def introspect(self, token: str) -> dict[str, Any]:
        result = await call(self.token_service.introspect, token)
        sub = result.get("sub") if result.get("active") else None
        if sub is None:
            return result
        provider = await self.owner_provider_async(result.get("client_id"))
        if provider is not None and await active_user_async(provider, sub) is None:
            return {"active": False}
        return result

    async def warm_up(self) -> None:
        """Precompute provider state (e.g. the dummy hash) off the event loop.

        Run once at startup so the first unknown-user login is not a bcrypt
        round slower than later ones.
        """
        for provider in self._providers.values():
            warm_up = getattr(provider, "warm_up", None)
            if callable(warm_up):
                await call(warm_up)

