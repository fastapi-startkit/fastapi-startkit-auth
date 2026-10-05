from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Request

if TYPE_CHECKING:
    from .manager import AuthManager


@dataclass
class AuthRequestContext:
    manager: AuthManager
    request: Request
    active: bool = True


_auth_request: ContextVar[AuthRequestContext | None] = ContextVar("auth_request", default=None)


def current_auth_request() -> AuthRequestContext:
    context = _auth_request.get()
    if context is None or not context.active:
        raise RuntimeError("Auth and Session facades require an active request handled by AuthProvider.")
    return context
