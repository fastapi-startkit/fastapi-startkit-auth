from __future__ import annotations

from collections.abc import Callable

from fastapi import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from ..manager import AuthManager
from ..request_context import AuthRequestContext, _auth_request


class AuthContextMiddleware:
    def __init__(self, app: ASGIApp, manager: Callable[[], AuthManager]) -> None:
        self.app = app
        self.manager = manager

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        context = AuthRequestContext(self.manager(), Request(scope, receive))
        token = _auth_request.set(context)
        try:
            await self.app(scope, receive, send)
        finally:
            context.active = False
            _auth_request.reset(token)


class AuthMiddleware:
    def __init__(self, app: ASGIApp, manager: AuthManager) -> None:
        manager.validate()
        if manager.sessions_enabled:
            app = self._with_sessions(app, manager)
        self.app = AuthContextMiddleware(app, manager=lambda: manager)

    @staticmethod
    def _with_sessions(app: ASGIApp, manager: AuthManager) -> ASGIApp:
        from .csrf import CsrfMiddleware
        from .session import SessionMiddleware

        session = manager.session_config
        cookie_options = {
            "ttl": session.ttl,
            "same_site": session.same_site,
            "secure": session.secure,
            "domain": session.domain,
            "path": session.path,
        }
        csrf = CsrfMiddleware(
            app,
            cookie=session.csrf_cookie,
            header=session.csrf_header,
            field=session.csrf_field,
            exempt_paths=[*session.csrf_exempt_paths, *manager.csrf_exempt_paths],
            stateful_origins=manager.stateful_origins,
            **cookie_options,
        )
        return SessionMiddleware(
            csrf,
            store=manager.session_store,
            cookie=session.cookie,
            http_only=session.http_only,
            **cookie_options,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)
