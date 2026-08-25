from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi_startkit.support import Provider

from .config import AuthConfig, as_config_class
from .exceptions import AuthError
from .manager import AuthManager
from .middleware.csrf import CsrfMiddleware
from .middleware.session import SessionMiddleware
from .routes import build_router
from .routes_spa import build_spa_router


async def _auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    headers = {}
    if exc.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict(), headers=headers)


def register_auth(api: FastAPI, config: Any, prefix: str = "") -> AuthManager:
    """Wire the auth stack onto an existing FastAPI app.

    Standalone entry point for plain-FastAPI applications: builds the
    :class:`AuthManager` and installs the routers, the ``AuthError`` handler
    and the session/CSRF middleware. The caller owns the app — the package
    never creates one. Startkit applications list :class:`AuthProvider` in
    the application's providers instead.
    """
    manager = AuthManager(config)
    _install(api, manager, prefix or _config_prefix(config))
    return manager


def _config_prefix(config: Any) -> str:
    return as_config_class(config).get("prefix", "")


class AuthProvider(Provider):
    """Startkit service provider for the auth stack.

    ``register()`` builds the :class:`AuthManager`; ``boot()`` wires the HTTP
    layer (routers, error handler, middleware) onto ``application.fastapi``.
    List it in the application's providers::

        Application(providers=[..., (AuthProvider, AuthConfig)])

    All FastAPI wiring happens in ``boot()``: the framework only exposes its
    FastAPI instance after the register phase.
    """

    provider_key = "auth"

    def __init__(self, application: Any, config: Any = None, prefix: str = "") -> None:
        super().__init__(application, config)
        self.prefix = prefix
        self.manager: AuthManager | None = None

    def register(self) -> None:
        config = self.config or AuthConfig
        self.manager = AuthManager(config)
        self.prefix = self.prefix or _config_prefix(config)

    def boot(self) -> None:
        _install(self.app.fastapi, self.manager, self.prefix)


def _install(api: FastAPI, manager: AuthManager, prefix: str) -> None:
    api.state.auth_manager = manager
    api.include_router(build_router(prefix=prefix))
    api.add_exception_handler(AuthError, _auth_error_handler)
    if manager.has_session_guard():
        session = manager.session_config
        if manager.spa_enabled():
            spa = manager.spa_config
            api.include_router(build_spa_router(prefix=prefix))
            # Added before SessionMiddleware so it ends up inside it and
            # sees the loaded session on the request state.
            api.add_middleware(
                CsrfMiddleware,
                cookie=spa["csrf_cookie"],
                header=spa["csrf_header"],
                exempt_paths=spa["csrf_exempt_paths"],
                stateful_origins=spa["stateful_origins"],
                ttl=session["ttl"],
                same_site=session["same_site"],
                secure=session["secure"],
                domain=session["domain"],
                path=session["path"],
            )
        api.add_middleware(
            SessionMiddleware,
            store=manager.session_store,
            cookie=session["cookie"],
            ttl=session["ttl"],
            http_only=session["http_only"],
            same_site=session["same_site"],
            secure=session["secure"],
            domain=session["domain"],
            path=session["path"],
        )
