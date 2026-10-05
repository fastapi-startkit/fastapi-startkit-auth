from __future__ import annotations

import threading
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
        self.refresh_lock = threading.RLock()

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
        family_id: str | None = None,
    ) -> RefreshTokenRecord:
        rec = RefreshTokenRecord(
            token_id=token_id,
            access_jti=access_jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=expires_at,
            resource=resource,
            family_id=family_id,
        )
        with self.refresh_lock:
            self._refresh[token_id] = rec
        return rec

    def find_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        return self._refresh.get(token_id)

    def revoke_refresh_token(self, token_id: str) -> bool:
        with self.refresh_lock:
            rec = self._refresh.get(token_id)
            if rec is None or rec.revoked:
                return False
            rec.revoked = True
            return True

    def consume_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        """Atomically rotate out a refresh token; replaying a used one revokes its family."""
        with self.refresh_lock:
            record = self._refresh.get(token_id)
            if record is None or record.expired:
                return None
            if record.revoked:
                self._revoke_families({record.family_id})
                return None
            record.revoked = True
            return record

    def revoke_token_chain(self, jti: str) -> bool:
        """Revoke an access token plus every refresh token (and its access token) in the same family."""
        with self.refresh_lock:
            revoked = self.revoke_access_token(jti)
            families = {record.family_id for record in self._refresh.values() if record.access_jti == jti}
            self._revoke_families(families)
            return revoked or bool(families)

    def _revoke_families(self, families: set[str | None]) -> None:
        for record in self._refresh.values():
            if record.family_id in families:
                record.revoked = True
                self.revoke_access_token(record.access_jti)

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
        with self.refresh_lock:
            self._refresh = {k: v for k, v in self._refresh.items() if not (v.expires_at and v.expires_at < now)}
            # A live refresh token still needs its access record so a chain revocation can find it.
            linked = {record.access_jti for record in self._refresh.values() if record.active}
            self._access = {k: v for k, v in self._access.items() if not v.expired or k in linked}
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at >= now}
