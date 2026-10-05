from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import ApiTokenConfig, AuthConfig, OAuth2Config, SessionConfig
from .exceptions import AuthError, InvalidClient
from .manager import AuthManager, FeatureNotRegistered
from .middleware.context import AuthMiddleware
from .routes import build_router
from .routes_password import build_password_router
from .routes_spa import build_spa_router

try:
    from fastapi_startkit.support import Provider
except ModuleNotFoundError as exc:
    if exc.name != "fastapi_startkit":
        raise
    Provider = object

_PUBLISHABLE = Path(__file__).resolve().parent / "publishable"

OAUTH2_MIGRATIONS = (
    "create_oauth_access_tokens_table",
    "create_oauth_refresh_tokens_table",
    "create_oauth_auth_codes_table",
    "add_resource_to_oauth_tables",
    "create_oauth_clients_table",
    "add_family_id_to_oauth_refresh_tokens_table",
)


def _migrations(*names: str) -> dict[str, str]:
    published = {}
    for name in names:
        path = next((_PUBLISHABLE / "migrations").glob(f"*_{name}.py"))
        published[str(path)] = f"databases/migrations/{path.name}"
    return published


async def _auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    # Error bodies can describe credentials or tokens, so no cache may keep them.
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    if exc.status_code == 401:
        # RFC 6749 §5.2: a failed client authentication challenges with the client's scheme.
        headers["WWW-Authenticate"] = "Basic" if isinstance(exc, InvalidClient) else "Bearer"
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict(), headers=headers)


def _warm_up_on_startup(app: FastAPI, manager: AuthManager) -> None:
    # Wrap rather than replace the lifespan so an app-supplied one still runs.
    inner = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: Any):
        await manager.warm_up()
        async with inner(application) as state:
            yield state

    app.router.lifespan_context = lifespan


class _AuthFeatureProvider(Provider):
    """Works standalone (``Provider(config).register(fastapi_app)``) or as a Startkit provider."""

    default_config: Any = None

    def __init__(self, application: Any = None, prefix: str = "", *, config: Any = None) -> None:
        self.prefix = prefix
        self.app = None
        if application is not None and hasattr(application, "published_resources"):
            super().__init__(application, config=config)
            self.config = config if config is not None else self.default_config
        else:
            self.config = config if config is not None else application
        self.fastapi: FastAPI | None = None

    @property
    def startkit(self) -> bool:
        return self.app is not None

    @property
    def manager(self) -> AuthManager:
        if self.startkit:
            return self.app.make("auth_manager")
        if self.fastapi is None:
            raise RuntimeError(f"{type(self).__name__} is not registered on an app yet.")
        return self._standalone_manager(self.fastapi)

    def _standalone_manager(self, app: FastAPI) -> AuthManager:
        manager = getattr(app.state, "auth_manager", None)
        if manager is None:
            raise RuntimeError(f"Register AuthProvider before {type(self).__name__}.")
        return manager

    def register(self, app: FastAPI | None = None) -> None:
        if app is not None:
            self.fastapi = app
            self.enable(self._standalone_manager(app))
            self.mount(app)
            return
        if not self.startkit:
            raise TypeError(f"Pass a FastAPI app to register() or a Startkit application to {type(self).__name__}().")
        if not self.app.has("auth_manager"):
            raise RuntimeError(f"List AuthProvider before {type(self).__name__} in the application providers.")
        self.enable(self.manager)
        self.register_startkit()

    def boot(self) -> None:
        if self.startkit:
            self.mount(self.app.fastapi)

    def enable(self, manager: AuthManager) -> None:
        pass

    def register_startkit(self) -> None:
        pass

    def mount(self, app: FastAPI) -> None:
        pass


class AuthProvider(_AuthFeatureProvider):
    """Builds the :class:`AuthManager` and installs the shared auth plumbing.

    Register it first, then the feature providers (``AuthSessionProvider``,
    ``AuthOAuth2Provider``, ``AuthApiTokenProvider``) that the configured
    guards need.
    """

    provider_key = "auth"
    default_config = AuthConfig

    def __init__(self, application: Any = None, prefix: str = "", *, config: Any = None) -> None:
        super().__init__(application, prefix, config=config)
        self._manager = AuthManager(self.config)

    @property
    def manager(self) -> AuthManager:
        return self._manager

    def register(self, app: FastAPI | None = None) -> None:
        if app is not None:
            self.fastapi = app
            self._install(app)
            return
        if not self.startkit:
            raise TypeError("Pass a FastAPI app to register() or a Startkit application to AuthProvider().")
        self.app.bind("auth_manager", self._manager)

    def boot(self) -> None:
        if self.startkit:
            self._install(self.app.fastapi)
            self._manager.validate()

    def _install(self, app: FastAPI) -> None:
        manager = self._manager
        app.state.auth_manager = manager
        app.add_exception_handler(AuthError, _auth_error_handler)
        # Starlette builds the middleware stack on the first request, after every
        # feature provider has registered, so AuthMiddleware sees them all.
        app.add_middleware(AuthMiddleware, manager=manager)
        _warm_up_on_startup(app, manager)
        if manager.has_password_brokers:
            app.include_router(build_password_router(prefix=self.prefix))


class AuthSessionProvider(_AuthFeatureProvider):
    provider_key = "auth-session"
    default_config = SessionConfig

    def enable(self, manager: AuthManager) -> None:
        manager.use_sessions(self.config)

    def register_startkit(self) -> None:
        self.publishes(_migrations("create_sessions_table"))


class AuthOAuth2Provider(_AuthFeatureProvider):
    provider_key = "auth-oauth2"
    default_config = OAuth2Config

    def enable(self, manager: AuthManager) -> None:
        manager.use_oauth2(self.config)

    def register_startkit(self) -> None:
        from .commands.oauth2_client import OAuth2ClientCommand

        self.commands([OAuth2ClientCommand])
        self.publishes(_migrations(*OAUTH2_MIGRATIONS))

    def mount(self, app: FastAPI) -> None:
        app.include_router(build_router(prefix=self.prefix))
        # Token endpoints authenticate the client, never the browser session.
        self.manager.csrf_exempt_paths.extend(
            f"{self.prefix}/oauth/{endpoint}" for endpoint in ("token", "introspect", "revoke")
        )


class AuthApiTokenProvider(_AuthFeatureProvider):
    provider_key = "auth-api-token"
    default_config = ApiTokenConfig

    def enable(self, manager: AuthManager) -> None:
        manager.use_api_tokens(self.config)

    def register_startkit(self) -> None:
        cors_stub = str(_PUBLISHABLE / "cors.py")
        self.merge_config_from(cors_stub, "cors")
        self.publishes({cors_stub: "config/cors.py", **_migrations("create_personal_api_tokens_table")})

    def mount(self, app: FastAPI) -> None:
        if self.manager.spa_enabled:
            if not self.manager.sessions_enabled:
                raise FeatureNotRegistered("SPA authentication (ApiTokenConfig.stateful_origins)", "AuthSessionProvider")
            app.include_router(build_spa_router(prefix=self.prefix))
