from __future__ import annotations

from ..concurrency import call
from ..exceptions import InvalidSession
from ..request_context import current_auth_request
from .models import SessionRecord
from .state import FORGET_KEY, PENDING_KEY, SESSION_KEY
from .store import generate_session_id


class Session:
    @staticmethod
    def id() -> str | None:
        record = getattr(current_auth_request().request.state, SESSION_KEY, None)
        return record.id if record is not None else None

    @staticmethod
    def token() -> str:
        context = current_auth_request()
        return context.manager.session_guard().start_guest_session(context.request).csrf_token

    @staticmethod
    async def regenerate() -> SessionRecord:
        context = current_auth_request()
        state = context.request.state
        record = getattr(state, SESSION_KEY, None)
        if record is None:
            return context.manager.session_guard().start_guest_session(context.request)
        if getattr(state, PENDING_KEY, None) is record:
            record.id = generate_session_id()
            return record
        record = await call(context.manager.session_guard(record.guard).store.regenerate_id, record.id)
        if record is None:
            raise InvalidSession("The session has expired.")
        setattr(state, SESSION_KEY, record)
        setattr(state, FORGET_KEY, False)
        return record

    @staticmethod
    async def invalidate() -> None:
        context = current_auth_request()
        state = context.request.state
        record = getattr(state, SESSION_KEY, None)
        if record is not None:
            await call(context.manager.session_guard(record.guard).store.invalidate, record.id)
        setattr(state, SESSION_KEY, None)
        setattr(state, PENDING_KEY, None)
        setattr(state, FORGET_KEY, True)
