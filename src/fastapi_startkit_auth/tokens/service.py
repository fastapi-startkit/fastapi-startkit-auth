from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

from ..exceptions import InvalidGrant, InvalidToken
from ..security.jwt import JWTEncoder
from .repository import InMemoryTokenRepository


@dataclass
class IssuedToken:
    """The result of minting a token, serialisable to an OAuth2 token response."""

    access_token: str
    token_type: str
    expires_in: int
    scopes: list[str]
    jti: str
    refresh_token: str | None = None

    def to_response(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": " ".join(self.scopes),
        }
        if self.refresh_token is not None:
            body["refresh_token"] = self.refresh_token
        return body


class TokenService:
    """Mints, rotates, revokes, and introspects tokens.

    Access tokens are signed JWTs; a server-side record per ``jti`` enables
    revocation and introspection. Refresh tokens are opaque high-entropy strings
    mapped to stored records, and are rotated (old access + refresh revoked) on
    every use.
    """

    def __init__(
        self,
        encoder: JWTEncoder,
        repository: InMemoryTokenRepository | None = None,
        access_ttl: int = 3600,
        refresh_ttl: int = 1209600,
        personal_access_ttl: int = 31536000,
        purge_interval: int = 300,
    ) -> None:
        self.encoder = encoder
        self.repository = repository or InMemoryTokenRepository()
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self.personal_access_ttl = personal_access_ttl
        self._purge_interval = purge_interval
        self._last_purge = time.time()

    def _maybe_purge(self) -> None:
        """Drop expired records periodically so in-memory stores stay bounded."""
        now = time.time()
        if now - self._last_purge >= self._purge_interval:
            self._last_purge = now
            self.repository.purge_expired()

    def issue(
        self,
        *,
        user_id: Any | None,
        client_id: str | None,
        scopes: list[str],
        with_refresh: bool = False,
        ttl: int | None = None,
        name: str | None = None,
        personal_access: bool = False,
    ) -> IssuedToken:
        self._maybe_purge()
        ttl = self.access_ttl if ttl is None else ttl
        sub = None if user_id is None else str(user_id)
        access_token = self.encoder.encode(
            {
                "sub": sub,
                "client_id": client_id,
                "scopes": list(scopes),
                "token_type": "access",
            },
            ttl_seconds=ttl,
        )
        jti = self.encoder.decode(access_token, verify_exp=False)["jti"]
        self.repository.store_access_token(
            jti=jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=time.time() + ttl,
            name=name,
            personal_access=personal_access,
        )
        refresh_token = None
        if with_refresh:
            refresh_token = self._issue_refresh(jti, user_id, client_id, scopes)
        return IssuedToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ttl,
            scopes=list(scopes),
            jti=jti,
            refresh_token=refresh_token,
        )

    def _issue_refresh(self, access_jti: str, user_id, client_id, scopes) -> str:
        token_id = secrets.token_urlsafe(48)
        self.repository.store_refresh_token(
            token_id=token_id,
            access_jti=access_jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=time.time() + self.refresh_ttl,
        )
        return token_id

    def create_personal_access_token(
        self, *, user_id: Any, name: str, scopes: list[str], ttl: int | None = None
    ) -> IssuedToken:
        return self.issue(
            user_id=user_id,
            client_id=None,
            scopes=scopes,
            ttl=self.personal_access_ttl if ttl is None else ttl,
            name=name,
            personal_access=True,
        )

    def refresh(self, refresh_token: str, scopes: list[str] | None = None) -> IssuedToken:
        record = self.repository.find_refresh_token(refresh_token)
        if record is None or not record.active:
            raise InvalidGrant("The refresh token is invalid, expired, or revoked.")

        new_scopes = list(record.scopes)
        if scopes is not None:
            widened = set(scopes) - set(record.scopes)
            if widened:
                raise InvalidGrant("Requested scopes exceed those of the original grant.")
            new_scopes = list(scopes)

        # Rotate: revoke the previous access + refresh pair before minting a new one.
        self.repository.revoke_access_token(record.access_jti)
        self.repository.revoke_refresh_token(record.token_id)

        return self.issue(
            user_id=record.user_id,
            client_id=record.client_id,
            scopes=new_scopes,
            with_refresh=True,
        )

    def authenticate(self, access_token: str) -> dict[str, Any]:
        claims = self.encoder.decode(access_token)
        record = self.repository.find_access_token(claims.get("jti", ""))
        if record is None or not record.active:
            raise InvalidToken("The access token has been revoked or is unknown.")
        return claims

    def revoke_access(self, jti: str) -> bool:
        return self.repository.revoke_access_token(jti)

    def revoke_refresh(self, token_id: str) -> bool:
        return self.repository.revoke_refresh_token(token_id)

    def introspect(self, access_token: str) -> dict[str, Any]:
        try:
            claims = self.authenticate(access_token)
        except InvalidToken:
            return {"active": False}
        record = self.repository.find_access_token(claims["jti"])
        return {
            "active": True,
            "scope": " ".join(record.scopes),
            "client_id": record.client_id,
            "sub": claims.get("sub"),
            "token_type": "Bearer",
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "jti": claims["jti"],
        }
