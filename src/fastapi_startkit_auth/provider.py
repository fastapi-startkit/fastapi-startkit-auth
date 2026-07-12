from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .exceptions import AuthError
from .manager import AuthManager
from .routes import build_router


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
