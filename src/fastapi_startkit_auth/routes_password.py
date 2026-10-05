from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .concurrency import call
from .dependencies import get_auth_manager
from .exceptions import InvalidGrant, ThrottleException
from .manager import AuthManager

GENERIC_RESET_RESPONSE = {"status": "If that account exists, a reset link has been sent."}


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    token: str
    password: str


def build_password_router(prefix: str = "") -> APIRouter:
    """Password reset endpoints, mounted by AuthProvider when password brokers are configured."""
    router = APIRouter(prefix=prefix)

    @router.post("/password/email")
    async def send_reset_link(
        body: ForgotPasswordRequest,
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        # Identical answers for known and unknown emails, throttled or not, so the
        # endpoint cannot enumerate accounts; the token travels out-of-band.
        try:
            token = await call(manager.broker().send_reset_link, body.email)
        except (InvalidGrant, ThrottleException):
            return GENERIC_RESET_RESPONSE
        if manager.debug_expose_reset_token:
            return {**GENERIC_RESET_RESPONSE, "token": token}
        return GENERIC_RESET_RESPONSE

    @router.post("/password/reset")
    async def reset_password(
        body: ResetPasswordRequest,
        manager: AuthManager = Depends(get_auth_manager),
    ) -> dict[str, Any]:
        await call(manager.broker().reset, body.email, body.token, body.password)
        return {"status": "password reset"}

    return router
