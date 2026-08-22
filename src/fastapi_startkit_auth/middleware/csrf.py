from __future__ import annotations

import secrets
from http.cookies import SimpleCookie
from typing import Any, Iterable

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..exceptions import CsrfTokenMismatch
from ..sessions.state import FORGET_KEY, SESSION_KEY

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class CsrfMiddleware:
    """Session-bound double-submit CSRF protection for SPA cookie auth.

    Runs *inside* :class:`~.session.SessionMiddleware` (added to the app before
    it), so the session record is already on the request state.

    Request phase — unsafe methods (POST/PUT/PATCH/DELETE) on requests that
    carry a live session must present the configured header (default
    ``X-XSRF-TOKEN``) matching the session's ``csrf_token``; the comparison is
    constant-time and failure is a 403 ``csrf_token_mismatch``. Requests
    without a session (bearer/token clients — no ambient credential) and safe
    methods are exempt, as are configured exempt paths. When
    ``stateful_origins`` is set, a foreign ``Origin`` header is rejected before
    the token is even checked (defense in depth).

    Response phase — whenever the session's CSRF token differs from the
    incoming CSRF cookie (first issue, or rotation on login), the cookie
    (default ``XSRF-TOKEN``) is (re)set. It is deliberately **not** HttpOnly:
    the SPA must read it to echo it in the header, and it is useless to an
    attacker without the HttpOnly session cookie. A stale cookie with no
    backing session is deleted.
    """

    def __init__(
        self,
        app: ASGIApp,
        cookie: str = "XSRF-TOKEN",
        header: str = "X-XSRF-TOKEN",
        exempt_paths: Iterable[str] = (),
        stateful_origins: Iterable[str] = (),
        ttl: float | None = 7200,
        same_site: str = "lax",
        secure: bool = True,
        domain: str | None = None,
        path: str = "/",
    ) -> None:
        self.app = app
        self.cookie = cookie
        self.header = header.lower().encode("latin-1")
        self.exempt_paths = tuple(exempt_paths)
        self.stateful_origins = frozenset(stateful_origins)
        self.ttl = ttl
        self.same_site = same_site
        self.secure = secure
        self.domain = domain
        self.path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        record = state.get(SESSION_KEY)
        if scope["method"] in UNSAFE_METHODS and record is not None:
            rejection = self._reject(scope, record)
            if rejection is not None:
                await rejection(scope, receive, send)
                return

        incoming_token = self._read_cookie(scope)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                header = self._cookie_header(state, incoming_token)
                if header is not None:
                    MutableHeaders(scope=message).append("set-cookie", header)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _reject(self, scope: Scope, record: Any) -> Response | None:
        origin = self._header_value(scope, b"origin")
        if self.stateful_origins and origin is not None and origin not in self.stateful_origins:
            return self._forbidden("Origin is not in the configured stateful origins.")
        if self._exempt(scope["path"]):
            return None
        supplied = self._header_value(scope, self.header)
        if supplied is None or not secrets.compare_digest(
            supplied.encode("latin-1"), record.csrf_token.encode("latin-1")
        ):
            return self._forbidden("CSRF token missing or invalid.")
        return None

    @staticmethod
    def _forbidden(description: str) -> Response:
        error = CsrfTokenMismatch(description)
        return JSONResponse(status_code=error.status_code, content=error.to_dict())

    def _exempt(self, path: str) -> bool:
        for pattern in self.exempt_paths:
            if pattern.endswith("*"):
                if path.startswith(pattern[:-1]):
                    return True
            elif path == pattern:
                return True
        return False

    @staticmethod
    def _header_value(scope: Scope, name: bytes) -> str | None:
        raw = next((value for key, value in scope.get("headers", []) if key == name), None)
        return raw.decode("latin-1") if raw is not None else None

    def _read_cookie(self, scope: Scope) -> str | None:
        raw = self._header_value(scope, b"cookie")
        if raw is None:
            return None
        jar: SimpleCookie = SimpleCookie()
        jar.load(raw)
        morsel = jar.get(self.cookie)
        return morsel.value if morsel is not None else None

    def _cookie_header(self, state: dict[str, Any], incoming_token: str | None) -> str | None:
        record = state.get(SESSION_KEY)
        response = Response()
        if record is not None:
            if incoming_token == record.csrf_token:
                return None
            response.set_cookie(
                self.cookie,
                record.csrf_token,
                max_age=int(self.ttl) if self.ttl is not None else None,
                path=self.path,
                domain=self.domain,
                secure=self.secure,
                httponly=False,
                samesite=self.same_site,
            )
        elif state.get(FORGET_KEY) or incoming_token is not None:
            response.delete_cookie(
                self.cookie,
                path=self.path,
                domain=self.domain,
                secure=self.secure,
                httponly=False,
                samesite=self.same_site,
            )
        else:
            return None
        return next(
            value.decode("latin-1")
            for name, value in response.raw_headers
            if name == b"set-cookie"
        )
