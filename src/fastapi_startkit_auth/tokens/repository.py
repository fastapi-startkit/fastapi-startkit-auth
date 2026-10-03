from __future__ import annotations

import time
from typing import Any

from .models import AccessTokenRecord, AuthorizationCode, RefreshTokenRecord


class InMemoryTokenRepository:
    """Default token store.

    Holds access-token records (for revocation/introspection), refresh tokens,
    and pending authorization codes. Implement the same method surface against a
    real database to persist tokens across processes.
    """

    def __init__(self) -> None:
        self._access: dict[str, AccessTokenRecord] = {}
        self._refresh: dict[str, RefreshTokenRecord] = {}
        self._codes: dict[str, AuthorizationCode] = {}

    # --- access tokens -------------------------------------------------
    def store_access_token(
        self,
        *,
        jti: str,
        user_id: Any | None,
        client_id: str | None,
        scopes: list[str],
        expires_at: float | None,
        name: str | None = None,
        personal_access: bool = False,
    ) -> AccessTokenRecord:
        rec = AccessTokenRecord(
            jti=jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=expires_at,
            name=name,
            personal_access=personal_access,
        )
        self._access[jti] = rec
        return rec

    def find_access_token(self, jti: str) -> AccessTokenRecord | None:
        return self._access.get(jti)

    def revoke_access_token(self, jti: str) -> bool:
        rec = self._access.get(jti)
        if rec is None:
            return False
        rec.revoked = True
        return True

    def list_access_tokens(self, user_id: Any, personal_access: bool | None = None) -> list[AccessTokenRecord]:
        out = [r for r in self._access.values() if r.user_id == user_id]
        if personal_access is not None:
            out = [r for r in out if r.personal_access == personal_access]
        return out

    # --- refresh tokens ------------------------------------------------
    def store_refresh_token(
        self,
        *,
        token_id: str,
        access_jti: str,
        user_id: Any | None,
        client_id: str | None,
        scopes: list[str],
        expires_at: float | None,
        resource: str | None = None,
    ) -> RefreshTokenRecord:
        rec = RefreshTokenRecord(
            token_id=token_id,
            access_jti=access_jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=expires_at,
            resource=resource,
        )
        self._refresh[token_id] = rec
        return rec

    def find_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        return self._refresh.get(token_id)

    def revoke_refresh_token(self, token_id: str) -> bool:
        rec = self._refresh.get(token_id)
        if rec is None:
            return False
        rec.revoked = True
        return True

    # --- authorization codes ------------------------------------------
    def store_auth_code(
        self,
        *,
        code: str,
        client_id: str,
        user_id: Any,
        scopes: list[str],
        redirect_uri: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        expires_at: float,
        resource: str | None = None,
    ) -> AuthorizationCode:
        rec = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            scopes=list(scopes),
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at,
            resource=resource,
        )
        self._codes[code] = rec
        return rec

    def pull_auth_code(self, code: str) -> AuthorizationCode | None:
        """Return and consume an authorization code (single use)."""
        return self._codes.pop(code, None)

    # --- maintenance ---------------------------------------------------
    def purge_expired(self) -> None:
        now = time.time()
        self._access = {k: v for k, v in self._access.items() if not (v.expires_at and v.expires_at < now)}
        self._refresh = {k: v for k, v in self._refresh.items() if not (v.expires_at and v.expires_at < now)}
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at >= now}
