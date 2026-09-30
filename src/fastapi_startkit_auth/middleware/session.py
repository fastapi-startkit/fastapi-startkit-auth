from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..concurrency import call
from ..sessions.state import FORGET_KEY, LOADED_ID_KEY, SESSION_KEY
from ..sessions.store import SessionStore


class SessionMiddleware:
    """Loads the server-side session from the cookie and issues the cookie back.

    Before the app runs: parse the configured cookie, look the id up in the
    store, and attach the live :class:`SessionRecord` (or ``None``) to
    ``request.state``. After the app decides (via ``Auth.login`` / ``logout``):

    - a session with an id different from the incoming cookie gets ``Set-Cookie``
      with the configured flags (HttpOnly / SameSite / Secure);
    - an explicit logout — or a stale cookie that resolved to no session —
      gets a deletion ``Set-Cookie``.
    """

    def __init__(
        self,
        app: ASGIApp,
        store: SessionStore | Any,
        cookie: str = "startkit_session",
        ttl: float | None = 7200,
        http_only: bool = True,
        same_site: str = "lax",
        secure: bool = True,
        domain: str | None = None,
        path: str = "/",
    ) -> None:
        self.app = app
        self.store = store
        self.cookie = cookie
        self.ttl = ttl
        self.http_only = http_only
        self.same_site = same_site
        self.secure = secure
        self.domain = domain
        self.path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        incoming_id = self._read_cookie(scope)
        record = await call(self.store.find, incoming_id) if incoming_id else None
        if record is not None:
            await call(self.store.touch, record.id)
        state[SESSION_KEY] = record
        state[LOADED_ID_KEY] = incoming_id
        state[FORGET_KEY] = False

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                header = self._cookie_header(state)
                if header is not None:
                    MutableHeaders(scope=message).append("set-cookie", header)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _read_cookie(self, scope: Scope) -> str | None:
        raw = next(
            (value for name, value in scope.get("headers", []) if name == b"cookie"),
            None,
        )
        if raw is None:
            return None
        jar: SimpleCookie = SimpleCookie()
        jar.load(raw.decode("latin-1"))
        morsel = jar.get(self.cookie)
        return morsel.value if morsel is not None else None

    def _cookie_header(self, state: dict[str, Any]) -> str | None:
        record = state.get(SESSION_KEY)
        incoming_id = state.get(LOADED_ID_KEY)
        response = Response()
        if record is not None:
            if record.id == incoming_id:
                return None
            response.set_cookie(
                self.cookie,
                record.id,
                max_age=int(self.ttl) if self.ttl is not None else None,
                path=self.path,
                domain=self.domain,
                secure=self.secure,
                httponly=self.http_only,
                samesite=self.same_site,
            )
        elif state.get(FORGET_KEY) or incoming_id:
            # Explicit logout, or a cookie that resolved to no live session.
            response.delete_cookie(
                self.cookie,
                path=self.path,
                domain=self.domain,
                secure=self.secure,
                httponly=self.http_only,
                samesite=self.same_site,
            )
        else:
            return None
        return next(value.decode("latin-1") for name, value in response.raw_headers if name == b"set-cookie")
