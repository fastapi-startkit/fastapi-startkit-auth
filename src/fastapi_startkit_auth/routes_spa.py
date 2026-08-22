from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from .dependencies import get_auth_manager
from .manager import AuthManager
from .sessions.state import FORGET_KEY, SESSION_KEY


def build_spa_router(prefix: str = "") -> APIRouter:
    router = APIRouter(prefix=prefix)

    @router.get("/__auth__/csrf-cookie", status_code=204)
    def csrf_cookie(request: Request, manager: AuthManager = Depends(get_auth_manager)) -> Response:
        """Prime a SPA for cookie auth (``axios.get("/__auth__/csrf-cookie")``).

        Ensures a session exists — starting a guest one (no user) when the
        request carries none — so the middleware pair can deliver both the
        HttpOnly session cookie and the JS-readable CSRF cookie on the way out.
        """
        record = getattr(request.state, SESSION_KEY, None)
        if record is None:
            record = manager.session_store.create(
                user_id=None,
                guard=manager.session_guard_name(),
                ttl=manager.session_config.get("ttl"),
            )
            setattr(request.state, SESSION_KEY, record)
            setattr(request.state, FORGET_KEY, False)
        return Response(status_code=204)

    return router
