from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AccessTokenRecord:
    """Server-side record of an issued JWT access token.

    The JWT itself is stateless; this record is what makes revocation and
    introspection possible and also backs personal access tokens.
    """

    jti: str
    user_id: Any | None
    client_id: str | None
    scopes: list[str] = field(default_factory=list)
    expires_at: float | None = None
    revoked: bool = False
    name: str | None = None
    personal_access: bool = False
    created_at: float = field(default_factory=lambda: time.time())

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < time.time()

    @property
    def active(self) -> bool:
        return not self.revoked and not self.expired


@dataclass
class RefreshTokenRecord:
    token_id: str
    access_jti: str
    user_id: Any | None
    client_id: str | None
    scopes: list[str] = field(default_factory=list)
    expires_at: float | None = None
    revoked: bool = False
    created_at: float = field(default_factory=lambda: time.time())
    resource: str | None = None

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < time.time()

    @property
    def active(self) -> bool:
        return not self.revoked and not self.expired


@dataclass
class AuthorizationCode:
    code: str
    client_id: str
    user_id: Any
    scopes: list[str]
    redirect_uri: str | None
    code_challenge: str | None
    code_challenge_method: str | None
    expires_at: float
    resource: str | None = None

    @property
    def expired(self) -> bool:
        return self.expires_at < time.time()
