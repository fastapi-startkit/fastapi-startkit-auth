from __future__ import annotations

from typing import Any


class AuthConfig:
    """Config-driven auth definition, mirroring Laravel's ``config/auth.php``.

    Subclass and override the class attributes. ``default``/``guards``/
    ``providers``/``passwords`` match the Passport model; the remaining
    attributes tune JWT signing and token lifetimes and all have sane defaults so
    a minimal config only needs to set ``key`` and a provider.

    Example::

        class AuthConfig(BaseAuthConfig):
            key = os.environ["APP_KEY"]
            default = {"guard": "api", "passwords": "users"}
            guards = {"api": {"driver": "passport", "provider": "users"}}
            providers = {"users": {"driver": "masoniteorm", "model": User}}
            passwords = {"users": {"provider": "users", "table": "password_reset_tokens",
                                    "expire": 60, "throttle": 60}}
    """

    default: dict[str, str] = {"guard": "api", "passwords": "users"}
    guards: dict[str, dict[str, Any]] = {"api": {"driver": "passport", "provider": "users"}}
    providers: dict[str, dict[str, Any]] = {}
    passwords: dict[str, dict[str, Any]] = {}

    # --- session settings (cookie auth; used by {"driver": "session"} guards) --
    # ``store`` selects the backend: "memory" (default), "orm" (the
    # fastapi-startkit ORM and the published migrations; optional ORM
    # ``connection`` name, default connection otherwise), or
    # "instance" (a ready-made SessionStore under ``instance``). Overrides
    # are merged over these defaults, so partial dicts are fine.
    # ``purge_interval`` throttles the ORM store's opportunistic purge-on-create
    # (seconds between sweeps of expired rows).
    session: dict[str, Any] = {
        "store": "memory",
        "cookie": "startkit_session",
        "ttl": 7200,
        "idle_ttl": None,
        "http_only": True,
        "same_site": "lax",
        "secure": True,
        "domain": None,
        "path": "/",
        "purge_interval": 300,
    }

    # --- SPA settings (CSRF protection on top of session guards) -------
    # ``enabled`` turns on the ``/__auth__/csrf-cookie`` endpoint and the
    # double-submit CSRF middleware. ``stateful_origins`` (Sanctum-style) lists
    # the first-party origins allowed to make cookie-authenticated unsafe
    # requests; empty disables the Origin check. ``csrf_exempt_paths`` entries
    # match exactly, or as a prefix when they end with ``*``.
    spa: dict[str, Any] = {
        "enabled": False,
        "csrf_cookie": "XSRF-TOKEN",
        "csrf_header": "X-XSRF-TOKEN",
        "csrf_exempt_paths": [],
        "stateful_origins": [],
    }

    # --- API token settings (opaque tokens; used by {"driver": "token"} guards) --
    # ``store`` selects the backend like the session block: "memory" (default),
    # "orm" (as for sessions), or "instance" (a ready-made ApiTokenRepository under
    # ``instance``). ``header`` is where the guard reads the token: the default
    # "Authorization" expects a ``Bearer`` scheme, any other name is read raw.
    # ``ttl`` is the default token lifetime in seconds (None = non-expiring);
    # ``purge_interval`` throttles the opportunistic purge-on-issue.
    api_tokens: dict[str, Any] = {
        "store": "memory",
        "header": "Authorization",
        "ttl": None,
        "purge_interval": 300,
    }

    # --- OAuth token store (access/refresh tokens and authorization codes) --
    # "memory" (default), "orm" (as for sessions), or "instance".
    tokens: dict[str, Any] = {
        "store": "memory",
    }

    # --- OAuth client registry -------------------------------------------
    # "memory" (default), "orm" (``oauth_clients`` table), or "instance".
    clients: dict[str, Any] = {
        "store": "memory",
    }

    # --- JWT / token settings (overridable) ----------------------------
    key: str | None = None
    algorithm: str = "HS256"
    access_token_ttl: int = 3600  # 1 hour
    refresh_token_ttl: int = 60 * 60 * 24 * 14  # 14 days
    personal_access_token_ttl: int = 60 * 60 * 24 * 365  # 1 year
    authorization_code_ttl: int = 600  # 10 minutes
    bcrypt_rounds: int = 12

    # --- OAuth authorization-server policy --------------------------------
    # ``issuer`` adds an ``iss`` claim to access tokens and requires it on
    # decode (tokens minted before it was set stop validating). ``resources``
    # lists the RFC 8707 resource indicators clients may request; a granted
    # resource becomes the token's ``aud``, and only a guard declaring that
    # ``audience`` accepts it. ``scopes`` is the scope catalog (name ->
    # description); empty accepts any scope. ``pkce_methods`` restricts
    # ``code_challenge_method`` (OAuth 2.1 / MCP: ``["S256"]``) and
    # ``require_pkce`` demands a challenge from confidential clients too.
    # Never list ``"*"`` in an MCP scope catalog: it grants every ability.
    issuer: str | None = None
    resources: list[str] = []
    scopes: dict[str, str] = {}
    pkce_methods: list[str] = ["S256", "plain"]
    require_pkce: bool = False

    # Called as ``notifier(email, token)`` when a reset link is requested so the
    # app can deliver the token (e.g. email it). The plaintext token is NEVER put
    # in the HTTP response unless ``debug_expose_reset_token`` is explicitly True.
    password_reset_notifier: Any = None
    debug_expose_reset_token: bool = False

    @classmethod
    def get(cls, name: str, default: Any = None) -> Any:
        return getattr(cls, name, default)


def as_config_class(config: Any) -> type[AuthConfig]:
    """Accept either an ``AuthConfig`` subclass or an instance and return a class-like accessor."""
    if isinstance(config, type):
        return config
    return config.__class__
