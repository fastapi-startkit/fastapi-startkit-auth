from __future__ import annotations

import copy
import warnings
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Literal, TypeVar

ConfigT = TypeVar("ConfigT")


def _canonical_store(store: str, section: str) -> str:
    if store == "orm":
        # stacklevel 4: this helper, __post_init__, the dataclass __init__, then the caller.
        warnings.warn(
            f'{section}(store="orm") is deprecated; use store="database".', DeprecationWarning, stacklevel=4
        )
        return "database"
    return store


@dataclass
class SessionGuard:
    provider: str = "users"
    driver: Literal["session"] = "session"


@dataclass
class OAuth2Guard:
    provider: str = "users"
    audience: str | None = None
    driver: Literal["oauth2"] = "oauth2"


@dataclass
class ApiTokenGuard:
    provider: str = "users"
    driver: Literal["token"] = "token"


@dataclass
class SessionConfig:
    """Cookie sessions, enabled by ``AuthSessionProvider``.

    ``store`` is "memory", "database" (the ORM ``sessions`` table; "orm" is a
    deprecated alias) or "instance" (a ready-made store under ``instance``).
    """

    store: str = "memory"
    connection: str | None = None
    instance: Any = None
    cookie: str = "startkit_session"
    ttl: float | None = 7200
    idle_ttl: float | None = None
    http_only: bool = True
    same_site: str = "lax"
    secure: bool = True
    domain: str | None = None
    path: str = "/"
    purge_interval: float = 300
    csrf_cookie: str = "XSRF-TOKEN"
    csrf_header: str = "X-XSRF-TOKEN"
    csrf_field: str = "_token"
    csrf_exempt_paths: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.store = _canonical_store(self.store, "SessionConfig")


@dataclass
class ApiTokenConfig:
    """Opaque API tokens, enabled by ``AuthApiTokenProvider``.

    A non-empty ``stateful_origins`` turns on SPA mode: token guards also
    accept the ``session_guard`` cookie session from those origins.
    """

    store: str = "memory"
    connection: str | None = None
    instance: Any = None
    header: str = "Authorization"
    ttl: float | None = None
    purge_interval: float = 300
    stateful_origins: list[str] = field(default_factory=list)
    session_guard: str = "web"

    def __post_init__(self) -> None:
        self.store = _canonical_store(self.store, "ApiTokenConfig")

    @property
    def stateful(self) -> bool:
        return bool(self.stateful_origins)


@dataclass
class OAuthClientsConfig:
    """Where OAuth clients live: "database" (the ORM ``oauth_clients`` table), "memory" or "instance"."""

    store: str = "database"
    connection: str | None = None
    instance: Any = None

    def __post_init__(self) -> None:
        self.store = _canonical_store(self.store, "OAuthClientsConfig")


@dataclass
class OAuthTokensConfig:
    store: str = "memory"
    connection: str | None = None
    instance: Any = None

    def __post_init__(self) -> None:
        self.store = _canonical_store(self.store, "OAuthTokensConfig")


DEFAULT_GRANT_TYPES = ("authorization_code", "client_credentials", "refresh_token")


@dataclass
class OAuth2Config:
    """The OAuth 2.1 authorization server, enabled by ``AuthOAuth2Provider``.

    ``issuer`` adds an ``iss`` claim to access tokens and requires it on
    decode. ``resources`` lists the RFC 8707 resource indicators clients may
    request; a granted resource becomes the token's ``aud``. ``scopes`` is the
    scope catalog (name -> description); empty accepts any scope.
    ``default_scopes`` applies when a request names none. ``grant_types``
    lists the enabled grants; add ``"password"`` to re-enable the legacy
    password grant. Never list ``"*"`` in an MCP scope catalog: it grants
    every ability.
    """

    key: str | None = None
    algorithm: str = "HS256"
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 60 * 60 * 24 * 14
    personal_access_token_ttl: int = 60 * 60 * 24 * 365
    authorization_code_ttl: int = 600
    issuer: str | None = None
    resources: list[str] = field(default_factory=list)
    scopes: dict[str, str] = field(default_factory=dict)
    default_scopes: list[str] = field(default_factory=list)
    pkce_methods: list[str] = field(default_factory=lambda: ["S256"])
    require_pkce: bool = True
    require_redirect_uri: bool = True
    grant_types: list[str] = field(default_factory=lambda: list(DEFAULT_GRANT_TYPES))
    authorization_guard: str | None = None
    tokens: OAuthTokensConfig = field(default_factory=OAuthTokensConfig)
    clients: OAuthClientsConfig = field(default_factory=OAuthClientsConfig)

    def __post_init__(self) -> None:
        self.tokens = resolve_config(self.tokens, OAuthTokensConfig)
        self.clients = resolve_config(self.clients, OAuthClientsConfig)


# v0.6 AuthConfig attributes that moved to OAuth2Config; still read, with a warning.
DEPRECATED_OAUTH2_ATTRIBUTES = (
    "key",
    "algorithm",
    "access_token_ttl",
    "refresh_token_ttl",
    "personal_access_token_ttl",
    "authorization_code_ttl",
    "tokens",
    "issuer",
    "resources",
    "scopes",
    "pkce_methods",
    "require_pkce",
)


class AuthConfig:
    """Guards, user providers and password brokers, mirroring ``config/auth.php``.

    Feature settings live on the feature configs (``SessionConfig``,
    ``OAuth2Config``, ``ApiTokenConfig``) handed to their providers.
    """

    default: dict[str, str] = {"guard": "web", "passwords": "users"}
    guards: dict[str, Any] = {}
    providers: dict[str, dict[str, Any]] = {}
    passwords: dict[str, dict[str, Any]] = {}
    bcrypt_rounds: int = 12

    # Called as ``notifier(email, token)`` when a reset link is requested. The
    # plaintext token is never put in the HTTP response unless
    # ``debug_expose_reset_token`` is explicitly True.
    password_reset_notifier: Any = None
    debug_expose_reset_token: bool = False

    @classmethod
    def get(cls, name: str, default: Any = None) -> Any:
        return getattr(cls, name, default)


def as_config_class(config: Any) -> type[AuthConfig]:
    if isinstance(config, dict):
        return type("AuthConfigFromDict", (AuthConfig,), config)
    if isinstance(config, type):
        return config
    return config.__class__


def resolve_config(config: Any, config_type: type[ConfigT]) -> ConfigT:
    if config is None:
        return config_type()
    if isinstance(config, config_type):
        return config
    if isinstance(config, type) and issubclass(config, config_type):
        # A plain subclass overriding fields as class attributes: the dataclass
        # __init__ would otherwise shadow them with the base defaults.
        overrides = {item.name: copy.copy(getattr(config, item.name)) for item in fields(config) if hasattr(config, item.name)}
        return config(**overrides)
    if isinstance(config, dict):
        return config_type(**config)
    raise TypeError(f"Expected {config_type.__name__}, a dict, or None; got {config!r}.")


def config_values(config: Any) -> dict[str, Any]:
    if is_dataclass(config):
        return {item.name: getattr(config, item.name) for item in fields(config)}
    return dict(config)
