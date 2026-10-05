from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from .dependencies import get_auth_manager
from .manager import AuthManager


def build_spa_router(prefix: str = "") -> APIRouter:
    router = APIRouter(prefix=prefix)

    @router.get("/__auth__/csrf-cookie", status_code=204)
    async def csrf_cookie(request: Request, manager: AuthManager = Depends(get_auth_manager)) -> Response:
        """Prime a SPA for cookie auth (``axios.get("/__auth__/csrf-cookie")``).

        Ensures a session exists — starting a guest one (no user) when the
        request carries none — so the middleware pair can deliver both the
        HttpOnly session cookie and the JS-readable CSRF cookie on the way out.
        """
        manager.session_guard().start_guest_session(request)
        # no-store: the response's only payload is Set-Cookie material; caching
        # it would hand a shared cache a session bootstrap.
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

    return router
