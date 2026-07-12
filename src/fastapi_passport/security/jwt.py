from __future__ import annotations

import time
import uuid
from typing import Any

import jwt

from ..exceptions import InvalidToken


class JWTEncoder:
    """Encode/decode signed JWTs for access tokens.

    Every token gets a unique ``jti`` so it can be individually revoked and
    introspected even though JWT verification itself is stateless.
    """

    def __init__(self, secret: str, algorithm: str = "HS256", leeway: int = 0) -> None:
        if not secret:
            raise ValueError("JWTEncoder requires a non-empty secret")
        self._secret = secret
        self._algorithm = algorithm
        self._leeway = leeway

    def encode(self, claims: dict[str, Any], ttl_seconds: int) -> str:
        now = int(time.time())
        payload = {
            "iat": now,
            "nbf": now,
            "exp": now + ttl_seconds,
            "jti": uuid.uuid4().hex,
            **claims,
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def decode(self, token: str, verify_exp: bool = True) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                leeway=self._leeway,
                # sub may be null (client-credentials tokens have no user); we
                # never rely on PyJWT's built-in sub type check.
                options={"verify_exp": verify_exp, "verify_sub": False},
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(str(exc)) from exc
