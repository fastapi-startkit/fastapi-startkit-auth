from __future__ import annotations

import secrets
import warnings
from typing import Any, Callable

from .apitokens.manager import ApiTokenManager, AsyncApiTokenManager
from .apitokens.repository import ApiTokenRepository, InMemoryApiTokenRepository
from .clients.repository import InMemoryClientRepository
from .concurrency import call, has_async_methods
from .config import AuthConfig, as_config_class
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


_REMOVED_STORES = ("sql", "async_sql")


def _reject_removed_store(kind: str, section: str) -> None:
    if kind in _REMOVED_STORES:
        raise ValueError(
            f'AuthConfig.{section} store "{kind}" was removed: use store "orm" (optional ORM '
            '"connection" name) after running the published migrations.'
        )


class AuthManager:
    """Central registry built from an :class:`AuthConfig`.

    Wires the shared hasher, JWT encoder, token store/service, client registry,
    guards, providers, grant handlers, and password brokers, and resolves them by
    the names declared in config. This is what ``AuthProvider`` registers onto the
    application and what the FastAPI dependencies read from.
    """

    def __init__(self, config: Any) -> None:
        self._config = as_config_class(config)
        cfg = self._config

        rounds = cfg.get("bcrypt_rounds", 12)
        self.hasher = BcryptHasher(rounds=rounds)

        key = cfg.get("key")
        if not key:
            key = secrets.token_urlsafe(48)
            warnings.warn(
                "AuthConfig.key is not set; generated an ephemeral signing key. "
                "Tokens will be invalidated on restart. Set a stable key in production.",
                stacklevel=2,
            )
        self.encoder = JWTEncoder(secret=key, algorithm=cfg.get("algorithm", "HS256"), issuer=cfg.get("issuer"))
        self.grant_policy = GrantPolicy(
            scopes=frozenset(cfg.get("scopes", {})),
            resources=frozenset(cfg.get("resources", [])),
            pkce_methods=frozenset(cfg.get("pkce_methods", ["S256", "plain"])),
            require_pkce=bool(cfg.get("require_pkce", False)),
        )

        self.tokens_config = {**AuthConfig.tokens, **cfg.get("tokens", {})}
        self.token_repository = self._build_token_repository()
        token_service_class = AsyncTokenService if has_async_methods(self.token_repository) else TokenService
        self.token_service = token_service_class(
            encoder=self.encoder,
            repository=self.token_repository,
            access_ttl=cfg.get("access_token_ttl", 3600),
            refresh_ttl=cfg.get("refresh_token_ttl", 1209600),
            personal_access_ttl=cfg.get("personal_access_token_ttl", 31536000),
        )
        self.client_repository = InMemoryClientRepository(hasher=self.hasher)

        self._notifier = cfg.get("password_reset_notifier")
        self.debug_expose_reset_token = bool(cfg.get("debug_expose_reset_token", False))

        self.session_config = {**AuthConfig.session, **cfg.get("session", {})}
        self.spa_config = {**AuthConfig.spa, **cfg.get("spa", {})}
        self.api_tokens_config = {**AuthConfig.api_tokens, **cfg.get("api_tokens", {})}
        self._session_store: SessionStore | None = None
        self._api_tokens: ApiTokenManager | None = None

        self._providers: dict[str, UserProvider] = {
            name: self._build_provider(spec) for name, spec in cfg.get("providers", {}).items()
        }
        self._guard_drivers: dict[str, GuardFactory] = {}
        self.register_guard_driver("passport", self._build_passport_guard)
        self.register_guard_driver("session", self._build_session_guard)
        self.register_guard_driver("token", self._build_token_guard)
        self._guards: dict[str, Guard] = {
            name: self._build_guard(name, spec) for name, spec in cfg.get("guards", {}).items()
        }
        self._brokers: dict[str, PasswordBroker] = {
            name: self._build_broker(spec) for name, spec in cfg.get("passwords", {}).items()
        }

    # --- construction helpers -----------------------------------------
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

    def register_guard_driver(self, driver: str, factory: GuardFactory) -> None:
        """Register a factory that builds a guard for a config ``driver`` key.

        Guards are constructed by their ``spec["driver"]`` rather than hardcoded,
        so app-defined drivers register alongside the built-in ``passport``,
        ``session``, and ``token`` drivers without touching the resolution
        logic.

        Ordering: config-declared guards are built during ``__init__`` right after
        the ``passport`` driver registers, so calling this post-construction does
        NOT retroactively build config-declared guards — register custom drivers
        before or at construction (e.g. in a subclass ``__init__`` before
        ``super().__init__``, or by extending this manager).
        """
        self._guard_drivers[driver] = factory

    def _build_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        driver = spec.get("driver", "passport")
        factory = self._guard_drivers.get(driver)
        if factory is None:
            raise ValueError(f"Unknown auth guard driver: {driver!r}")
        return factory(name, spec)

    def _build_passport_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        provider = self._require_provider(spec.get("provider"))
        audience = spec.get("audience")
        if audience is not None and audience not in self.grant_policy.resources:
            warnings.warn(
                f"Guard {name!r} requires audience {audience!r}, which AuthConfig.resources does not list; "
                "no token can be issued for it.",
                stacklevel=2,
            )
        guard_class = AsyncPassportGuard if is_async_provider(provider) or self._tokens_async() else PassportGuard
        return guard_class(name=name, token_service=self.token_service, provider=provider, audience=audience)

    def _build_session_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        provider = self._require_provider(spec.get("provider"))
        if not self.session_config.get("secure", True):
            warnings.warn(
                "AuthConfig.session['secure'] is False; the session cookie will be sent "
                "over plain HTTP. Enable it in production.",
                stacklevel=2,
            )
        guard_class = (
            AsyncSessionGuard if is_async_provider(provider) or has_async_methods(self.session_store) else SessionGuard
        )
        return guard_class(
            name=name,
            store=self.session_store,
            provider=provider,
            ttl=self.session_config.get("ttl"),
        )

    def _build_token_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        provider = self._require_provider(spec.get("provider"))
        guard_class = (
            AsyncTokenGuard
            if is_async_provider(provider) or isinstance(self.api_tokens, AsyncApiTokenManager)
            else TokenGuard
        )
        return guard_class(
            name=name,
            tokens=self.api_tokens,
            provider=provider,
            header=self.api_tokens_config.get("header", "Authorization"),
        )

    @property
    def api_tokens(self) -> ApiTokenManager | AsyncApiTokenManager:
        """The API-token manager, built on first use.

        Lazy for the same reason as :attr:`session_store`: apps without a token
        guard never pay for (or have to configure) the repository — notably the
        SQL connection.
        """
        if self._api_tokens is None:
            repository = self._build_api_token_repository()
            manager_class = AsyncApiTokenManager if has_async_methods(repository) else ApiTokenManager
            self._api_tokens = manager_class(
                repository=repository,
                default_ttl=self.api_tokens_config.get("ttl"),
                purge_interval=self.api_tokens_config.get("purge_interval", 300),
            )
        return self._api_tokens

    def _build_api_token_repository(self) -> ApiTokenRepository:
        spec = self.api_tokens_config
        kind = spec.get("store", "memory")
        if kind == "memory":
            return InMemoryApiTokenRepository()
        if kind == "orm":
            from .apitokens.orm import OrmApiTokenRepository

            return OrmApiTokenRepository(spec.get("connection"))
        _reject_removed_store(kind, "api_tokens")
        if kind == "instance":
            return spec["instance"]
        raise ValueError(f"Unknown api_tokens store: {kind!r}")

    @property
    def session_store(self) -> SessionStore:
        """The configured session store, built on first use.

        Lazy so apps without a session guard never pay for (or have to
        configure) a store — notably the SQL connection.
        """
        if self._session_store is None:
            self._session_store = self._build_session_store()
        return self._session_store

    def _build_session_store(self) -> SessionStore:
        spec = self.session_config
        kind = spec.get("store", "memory")
        idle_ttl = spec.get("idle_ttl")
        if kind == "memory":
            return InMemorySessionStore(idle_ttl=idle_ttl)
        if kind == "orm":
            from .sessions.orm import OrmSessionStore

            return OrmSessionStore(
                spec.get("connection"),
                idle_ttl=idle_ttl,
                purge_interval=spec.get("purge_interval", 300),
            )
        _reject_removed_store(kind, "session")
        if kind == "instance":
            return spec["instance"]
        raise ValueError(f"Unknown session store: {kind!r}")

    def _build_token_repository(self) -> Any:
        spec = self.tokens_config
        kind = spec.get("store", "memory")
        if kind == "memory":
            return InMemoryTokenRepository()
        if kind == "orm":
            from .tokens.orm import OrmTokenRepository

            return OrmTokenRepository(spec.get("connection"))
        _reject_removed_store(kind, "tokens")
        if kind == "instance":
            return spec["instance"]
        raise ValueError(f"Unknown tokens store: {kind!r}")

    def session_guard_name(self) -> str | None:
        """Name of the first configured session guard, or ``None``."""
        return next(
            (name for name, guard in self._guards.items() if isinstance(guard, (SessionGuard, AsyncSessionGuard))),
            None,
        )

    def has_session_guard(self) -> bool:
        return self.session_guard_name() is not None

    def spa_enabled(self) -> bool:
        return bool(self.spa_config.get("enabled"))

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
        default_guard = self._config.get("default", {}).get("guard")
        guard_spec = self._config.get("guards", {}).get(default_guard, {})
        return self._require_provider(guard_spec.get("provider"))

    def _require_provider(self, name: str | None) -> UserProvider:
        if name not in self._providers:
            raise ValueError(f"Auth provider {name!r} is not defined in AuthConfig.providers")
        return self._providers[name]

    # --- public accessors ---------------------------------------------
    def guard(self, name: str | None = None) -> Guard:
        name = name or self._config.get("default", {}).get("guard")
        if name not in self._guards:
            raise ValueError(f"Auth guard {name!r} is not defined in AuthConfig.guards")
        return self._guards[name]

    def provider(self, name: str) -> UserProvider:
        return self._require_provider(name)

    def broker(self, name: str | None = None) -> PasswordBroker | AsyncPasswordBroker:
        name = name or self._config.get("default", {}).get("passwords")
        if name not in self._brokers:
            raise ValueError(f"Password broker {name!r} is not defined in AuthConfig.passwords")
        return self._brokers[name]

    def default_guard_name(self) -> str:
        return self._config.get("default", {}).get("guard")

    # --- grant factories ----------------------------------------------
    def _tokens_async(self) -> bool:
        return isinstance(self.token_service, AsyncTokenService)

    def _grants_async(self, provider: Any) -> bool:
        return self._tokens_async() or (provider is not None and is_async_provider(provider))

    def _owner_grants_async(self) -> bool:
        # Owner re-checks resolve their provider per token, so any async
        # provider requires the async grant.
        return self._tokens_async() or any(is_async_provider(p) for p in self._providers.values())

    def _default_owner_provider(self) -> Any:
        guards = self._config.get("guards", {})
        if self.default_guard_name() not in guards:
            return None
        return getattr(self.guard(), "provider", None)

    def _client_provider(self, client_id: str | None) -> UserProvider | None:
        client = self.client_repository.find(client_id) if client_id else None
        if client is None or not client.provider:
            return None
        return self._require_provider(client.provider)

    def owner_provider(self, client_id: str | None = None) -> Any:
        """Return the user provider behind tokens and codes issued to ``client_id``.

        A client registered with a ``provider`` acts for that provider's users;
        otherwise (or with no client) the default guard's provider applies.
        """
        provider = self._client_provider(client_id)
        return provider if provider is not None else self._default_owner_provider()

    def password_grant(
        self, guard: str | None = None, client_id: str | None = None
    ) -> PasswordGrant | AsyncPasswordGrant:
        provider = self._client_provider(client_id)
        if provider is None:
            provider = self.guard(guard).provider
        if self._grants_async(provider):
            return AsyncPasswordGrant(self.token_service, provider, self.grant_policy)
        return PasswordGrant(self.token_service, provider, self.grant_policy)

    def client_credentials_grant(self) -> ClientCredentialsGrant | AsyncClientCredentialsGrant:
        grant_class = AsyncClientCredentialsGrant if self._tokens_async() else ClientCredentialsGrant
        return grant_class(self.token_service, self.grant_policy)

    def refresh_grant(self) -> RefreshTokenGrant | AsyncRefreshTokenGrant:
        grant_class = AsyncRefreshTokenGrant if self._owner_grants_async() else RefreshTokenGrant
        return grant_class(self.token_service, owner_provider=self.owner_provider)

    def authorization_code_grant(self) -> AuthorizationCodeGrant | AsyncAuthorizationCodeGrant:
        grant_class = AsyncAuthorizationCodeGrant if self._owner_grants_async() else AuthorizationCodeGrant
        return grant_class(
            self.token_service,
            code_ttl=self._config.get("authorization_code_ttl", 600),
            owner_provider=self.owner_provider,
            policy=self.grant_policy,
        )

    async def introspect(self, access_token: str) -> dict[str, Any]:
        result = await call(self.token_service.introspect, access_token)
        sub = result.get("sub") if result.get("active") else None
        provider = self.owner_provider(result.get("client_id"))
        if sub is not None and provider is not None and await active_user_async(provider, sub) is None:
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
