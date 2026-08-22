from __future__ import annotations

import secrets
import warnings
from typing import Any, Callable

from .clients.repository import InMemoryClientRepository
from .config import AuthConfig, as_config_class
from .grants.authorization_code import AuthorizationCodeGrant
from .grants.client_credentials import ClientCredentialsGrant
from .grants.password import PasswordGrant
from .grants.refresh import RefreshTokenGrant
from .guards.guard import Guard, PassportGuard
from .guards.session import SessionGuard
from .passwords.broker import PasswordBroker
from .passwords.repository import InMemoryPasswordResetRepository
from .providers.base import UserProvider
from .providers.memory import InMemoryUserProvider
from .providers.model import ModelUserProvider
from .security.hashing import BcryptHasher
from .security.jwt import JWTEncoder
from .sessions.sql import SqlSessionStore
from .sessions.store import InMemorySessionStore, SessionStore
from .tokens.repository import InMemoryTokenRepository
from .tokens.service import TokenService

GuardFactory = Callable[[str, dict[str, Any]], Guard]


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
        self.encoder = JWTEncoder(secret=key, algorithm=cfg.get("algorithm", "HS256"))

        self.token_repository = InMemoryTokenRepository()
        self.token_service = TokenService(
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
        self._session_store: SessionStore | None = None

        self._providers: dict[str, UserProvider] = {
            name: self._build_provider(spec) for name, spec in cfg.get("providers", {}).items()
        }
        self._guard_drivers: dict[str, GuardFactory] = {}
        self.register_guard_driver("passport", self._build_passport_guard)
        self.register_guard_driver("session", self._build_session_guard)
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
            )
            for user in spec.get("users", []):
                provider.add(user)
            return provider
        if driver in ("masoniteorm", "orm", "model"):
            return ModelUserProvider(
                model=spec["model"],
                hasher=self.hasher,
                username_field=spec.get("username_field", "email"),
                password_field=spec.get("password_field", "password"),
                id_field=spec.get("id_field", "id"),
            )
        raise ValueError(f"Unknown user provider driver: {driver!r}")

    def register_guard_driver(self, driver: str, factory: GuardFactory) -> None:
        """Register a factory that builds a guard for a config ``driver`` key.

        Guards are constructed by their ``spec["driver"]`` rather than hardcoded,
        so new modes — the future ``token`` driver, or app-defined ones —
        register alongside the built-in ``passport`` and ``session`` drivers
        without touching the resolution logic.

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
        return PassportGuard(name=name, token_service=self.token_service, provider=provider)

    def _build_session_guard(self, name: str, spec: dict[str, Any]) -> Guard:
        provider = self._require_provider(spec.get("provider"))
        if not self.session_config.get("secure", True):
            warnings.warn(
                "AuthConfig.session['secure'] is False; the session cookie will be sent "
                "over plain HTTP. Enable it in production.",
                stacklevel=2,
            )
        return SessionGuard(
            name=name,
            store=self.session_store,
            provider=provider,
            ttl=self.session_config.get("ttl"),
        )

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
        if kind == "sql":
            connection = spec.get("connection")
            if connection is None:
                raise ValueError('AuthConfig.session with store "sql" requires a "connection".')
            if callable(connection):
                connection = connection()
            return SqlSessionStore(
                connection,
                table=spec.get("table", "sessions"),
                idle_ttl=idle_ttl,
            )
        if kind == "instance":
            return spec["instance"]
        raise ValueError(f"Unknown session store: {kind!r}")

    def session_guard_name(self) -> str | None:
        """Name of the first configured session guard, or ``None``."""
        return next(
            (name for name, guard in self._guards.items() if isinstance(guard, SessionGuard)),
            None,
        )

    def has_session_guard(self) -> bool:
        return self.session_guard_name() is not None

    def spa_enabled(self) -> bool:
        return bool(self.spa_config.get("enabled"))

    def _build_broker(self, spec: dict[str, Any]) -> PasswordBroker:
        provider = self._resolve_broker_provider(spec.get("provider"))
        return PasswordBroker(
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

    def broker(self, name: str | None = None) -> PasswordBroker:
        name = name or self._config.get("default", {}).get("passwords")
        if name not in self._brokers:
            raise ValueError(f"Password broker {name!r} is not defined in AuthConfig.passwords")
        return self._brokers[name]

    def default_guard_name(self) -> str:
        return self._config.get("default", {}).get("guard")

    # --- grant factories ----------------------------------------------
    def password_grant(self, guard: str | None = None) -> PasswordGrant:
        return PasswordGrant(self.token_service, self.guard(guard).provider)

    def client_credentials_grant(self) -> ClientCredentialsGrant:
        return ClientCredentialsGrant(self.token_service)

    def refresh_grant(self) -> RefreshTokenGrant:
        return RefreshTokenGrant(self.token_service)

    def authorization_code_grant(self) -> AuthorizationCodeGrant:
        return AuthorizationCodeGrant(
            self.token_service, code_ttl=self._config.get("authorization_code_ttl", 600)
        )
