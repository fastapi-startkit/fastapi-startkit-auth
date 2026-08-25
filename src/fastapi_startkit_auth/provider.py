from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

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


class AuthProvider:
    """Service provider for the auth stack, following the startkit contract.

    Mirrors ``fastapi_startkit.support.Provider`` without depending on the
    framework: constructed as ``AuthProvider(application, config)``,
    ``register()`` builds the :class:`AuthManager`, and ``boot()`` wires the
    HTTP layer (routers, error handler, middleware) onto
    ``application.fastapi``. List it in the application's providers::

        Application(providers=[..., (AuthProvider, AuthConfig)])

    All FastAPI wiring happens in ``boot()``: the framework only exposes its
    FastAPI instance after the register phase.
    """

    provider_key = "auth"

    def __init__(self, application: Any, config: Any = None, prefix: str = "") -> None:
        self.app = application
        self.config = config
        self.prefix = prefix
        self.manager: AuthManager | None = None

    def register(self) -> None:
        self.manager = AuthManager(self.config)

    def boot(self) -> None:
        api: FastAPI = self.app.fastapi
        api.state.auth_manager = self.manager
        api.include_router(build_router(prefix=self.prefix))
        api.add_exception_handler(AuthError, _auth_error_handler)
        if self.manager.has_session_guard():
            session = self.manager.session_config
            if self.manager.spa_enabled():
                spa = self.manager.spa_config
                api.include_router(build_spa_router(prefix=self.prefix))
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
                store=self.manager.session_store,
                cookie=session["cookie"],
                ttl=session["ttl"],
                http_only=session["http_only"],
                same_site=session["same_site"],
                secure=session["secure"],
                domain=session["domain"],
                path=session["path"],
            )
