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
    """Registers the auth stack onto a FastAPI application.

    Instantiated with an :class:`AuthConfig`, it builds the :class:`AuthManager`,
    stores it on ``app.state.auth_manager`` (where the dependencies read it),
    mounts the OAuth2 router, and installs the OAuth2 error handler.
    """

    def __init__(self, config: Any, prefix: str = "") -> None:
        self.config = config
        self.prefix = prefix
        self.manager = AuthManager(config)

    def register(self, app: FastAPI) -> None:
        app.state.auth_manager = self.manager
        app.include_router(build_router(prefix=self.prefix))
        app.add_exception_handler(AuthError, _auth_error_handler)
        if self.manager.has_session_guard():
            session = self.manager.session_config
            if self.manager.spa_enabled():
                spa = self.manager.spa_config
                app.include_router(build_spa_router(prefix=self.prefix))
                # Added before SessionMiddleware so it ends up inside it and
                # sees the loaded session on the request state.
                app.add_middleware(
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
            app.add_middleware(
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
