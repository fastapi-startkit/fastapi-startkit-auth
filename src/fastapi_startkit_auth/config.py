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
    # ``store`` selects the backend: "memory" (default), "sql" (requires a
    # DB-API ``connection`` — or zero-arg factory — plus optional ``table``),
    # or "instance" (a ready-made SessionStore under ``instance``). Overrides
    # are merged over these defaults, so partial dicts are fine.
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
    }

    # --- JWT / token settings (overridable) ----------------------------
    key: str | None = None
    algorithm: str = "HS256"
    access_token_ttl: int = 3600            # 1 hour
    refresh_token_ttl: int = 60 * 60 * 24 * 14   # 14 days
    personal_access_token_ttl: int = 60 * 60 * 24 * 365  # 1 year
    authorization_code_ttl: int = 600       # 10 minutes
    bcrypt_rounds: int = 12

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
