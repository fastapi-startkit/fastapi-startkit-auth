from __future__ import annotations

import secrets
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from ..concurrency import call
from ..exceptions import InvalidGrant, InvalidToken
from ..policy import ensure_same_resource
from ..security.jwt import JWTEncoder
from .models import AccessTokenRecord, RefreshTokenRecord
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


def _encode_access_token(
    encoder: JWTEncoder,
    user_id: Any | None,
    client_id: str | None,
    scopes: list[str],
    ttl: int,
    audience: str | None,
) -> tuple[str, str]:
    jti = uuid.uuid4().hex
    claims = {
        "jti": jti,
        "sub": None if user_id is None else str(user_id),
        "client_id": client_id,
        "scopes": list(scopes),
        "token_type": "access",
    }
    if audience is not None:
        claims["aud"] = audience
    return encoder.encode(claims, ttl_seconds=ttl), jti


def _refreshed_scopes(
    record: RefreshTokenRecord | None,
    scopes: list[str] | None,
    resource: str | None,
    client_id: str | None,
) -> list[str]:
    if record is None or not record.active:
        raise InvalidGrant("The refresh token is invalid, expired, or revoked.")
    if client_id is not None and record.client_id != client_id:
        raise InvalidGrant("The refresh token was issued to a different client.")
    ensure_same_resource(record.resource, resource)
    if scopes is None:
        return list(record.scopes)
    if set(scopes) - set(record.scopes):
        raise InvalidGrant("Requested scopes exceed those of the original grant.")
    return list(scopes)


def _bound_to(record: AccessTokenRecord | RefreshTokenRecord, client_id: str, allow_unbound: bool) -> bool:
    # Only the password grant issues client-less tokens, so they are honoured only while it is enabled.
    return record.client_id == client_id or (allow_unbound and record.client_id is None)


def _introspection(record: AccessTokenRecord, claims: dict[str, Any]) -> dict[str, Any]:
    result = {
        "active": True,
        "scope": " ".join(record.scopes),
        "client_id": record.client_id,
        "sub": claims.get("sub"),
        "token_type": "Bearer",
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "jti": claims["jti"],
    }
    for claim in ("aud", "iss"):
        if claim in claims:
            result[claim] = claims[claim]
    return result


def _refresh_introspection(record: RefreshTokenRecord) -> dict[str, Any]:
    if not record.active:
        return {"active": False}
    result = {
        "active": True,
        "scope": " ".join(record.scopes),
        "client_id": record.client_id,
        "sub": None if record.user_id is None else str(record.user_id),
        "token_type": "refresh_token",
        "exp": None if record.expires_at is None else int(record.expires_at),
        "iat": int(record.created_at),
    }
    if record.resource is not None:
        result["aud"] = record.resource
    return result


def _owned_by(record: AccessTokenRecord | None, user_id: Any, personal_access: bool | None) -> bool:
    if record is None or record.user_id != user_id:
        return False
    return personal_access is None or record.personal_access == personal_access


def _decoded_jti(encoder: JWTEncoder, token: str) -> str | None:
    try:
        return encoder.decode(token, verify_exp=False, verify_audience=False).get("jti")
    except InvalidToken:
        return None


class TokenService:
    """Mints, rotates, revokes, and introspects tokens.

    Access tokens are signed JWTs; a server-side record per ``jti`` enables
    revocation and introspection. Refresh tokens are opaque high-entropy strings
    mapped to stored records and rotated on every use; every rotation of one
    grant shares a family, and replaying a rotated-out token revokes the family.
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

    def _refresh_lock(self) -> Any:
        return getattr(self.repository, "refresh_lock", None) or nullcontext()

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
        audience: str | None = None,
        refresh_family_id: str | None = None,
    ) -> IssuedToken:
        self._maybe_purge()
        ttl = self.access_ttl if ttl is None else ttl
        access_token, jti = _encode_access_token(self.encoder, user_id, client_id, scopes, ttl, audience)
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
            refresh_token = secrets.token_urlsafe(48)
            self.repository.store_refresh_token(
                token_id=refresh_token,
                access_jti=jti,
                user_id=user_id,
                client_id=client_id,
                scopes=list(scopes),
                expires_at=time.time() + self.refresh_ttl,
                resource=audience,
                family_id=refresh_family_id,
            )
        return IssuedToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ttl,
            scopes=list(scopes),
            jti=jti,
            refresh_token=refresh_token,
        )

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

    def refresh(
        self,
        refresh_token: str,
        scopes: list[str] | None = None,
        resource: str | None = None,
        client_id: str | None = None,
    ) -> IssuedToken:
        # Held across rotation so a concurrent replay revokes the family only after the new pair has joined it.
        with self._refresh_lock():
            record = self.repository.find_refresh_token(refresh_token)
            if record is not None and record.revoked:
                # A replayed, rotated-out token: consuming it revokes the whole family.
                self.repository.consume_refresh_token(refresh_token)
            new_scopes = _refreshed_scopes(record, scopes, resource, client_id)
            if self.repository.consume_refresh_token(refresh_token) is None:
                raise InvalidGrant("The refresh token is invalid, expired, or revoked.")
            self.repository.revoke_access_token(record.access_jti)
            return self.issue(
                user_id=record.user_id,
                client_id=record.client_id,
                scopes=new_scopes,
                with_refresh=True,
                audience=record.resource,
                refresh_family_id=record.family_id,
            )

    def authenticate(self, access_token: str, audience: str | None = None) -> dict[str, Any]:
        return self._active(self.encoder.decode(access_token, audience=audience))

    def _active(self, claims: dict[str, Any]) -> dict[str, Any]:
        record = self.repository.find_access_token(claims.get("jti", ""))
        if record is None or not record.active:
            raise InvalidToken("The access token has been revoked or is unknown.")
        return claims

    def revoke_access(self, jti: str) -> bool:
        return self.repository.revoke_access_token(jti)

    def revoke_refresh(self, token_id: str) -> bool:
        return self.repository.revoke_refresh_token(token_id)

    def tokens_for(self, user_id: Any, personal_access: bool | None = None) -> list[AccessTokenRecord]:
        return [r for r in self.repository.list_access_tokens(user_id, personal_access) if not r.revoked]

    def revoke_for_user(self, jti: str, user_id: Any, personal_access: bool | None = None) -> bool:
        if not _owned_by(self.repository.find_access_token(jti), user_id, personal_access):
            return False
        return self.repository.revoke_token_chain(jti)

    def revoke_all_for_user(self, user_id: Any, personal_access: bool | None = None) -> int:
        with self._refresh_lock():
            records = self.tokens_for(user_id, personal_access)
            return sum(bool(self.repository.revoke_token_chain(r.jti)) for r in records)

    def revoke_token(self, token: str, client_id: str, allow_unbound: bool = False) -> bool:
        """RFC 7009: revoke an access or refresh token, with its whole chain, on behalf of ``client_id``."""
        record: AccessTokenRecord | RefreshTokenRecord | None = self.repository.find_refresh_token(token)
        if record is not None:
            jti = record.access_jti
        else:
            jti = _decoded_jti(self.encoder, token)
            record = None if jti is None else self.repository.find_access_token(jti)
        if record is None or not _bound_to(record, client_id, allow_unbound):
            return False
        return self.repository.revoke_token_chain(jti)

    def introspect(self, token: str) -> dict[str, Any]:
        refresh = self.repository.find_refresh_token(token)
        if refresh is not None:
            return _refresh_introspection(refresh)
        try:
            claims = self._active(self.encoder.decode(token, verify_audience=False))
        except InvalidToken:
            return {"active": False}
        return _introspection(self.repository.find_access_token(claims["jti"]), claims)


class AsyncTokenService:
    def __init__(
        self,
        encoder: JWTEncoder,
        repository: Any,
        access_ttl: int = 3600,
        refresh_ttl: int = 1209600,
        personal_access_ttl: int = 31536000,
        purge_interval: int = 300,
    ) -> None:
        self.encoder = encoder
        self.repository = repository
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self.personal_access_ttl = personal_access_ttl
        self._purge_interval = purge_interval
        self._last_purge = time.time()

    async def _maybe_purge(self) -> None:
        now = time.time()
        if now - self._last_purge >= self._purge_interval:
            self._last_purge = now
            await call(self.repository.purge_expired)

    async def issue(
        self,
        *,
        user_id: Any | None,
        client_id: str | None,
        scopes: list[str],
        with_refresh: bool = False,
        ttl: int | None = None,
        name: str | None = None,
        personal_access: bool = False,
        audience: str | None = None,
        refresh_family_id: str | None = None,
    ) -> IssuedToken:
        await self._maybe_purge()
        ttl = self.access_ttl if ttl is None else ttl
        access_token, jti = _encode_access_token(self.encoder, user_id, client_id, scopes, ttl, audience)
        await call(
            self.repository.store_access_token,
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
            refresh_token = secrets.token_urlsafe(48)
            await call(
                self.repository.store_refresh_token,
                token_id=refresh_token,
                access_jti=jti,
                user_id=user_id,
                client_id=client_id,
                scopes=list(scopes),
                expires_at=time.time() + self.refresh_ttl,
                resource=audience,
                family_id=refresh_family_id,
            )
        return IssuedToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ttl,
            scopes=list(scopes),
            jti=jti,
            refresh_token=refresh_token,
        )

    async def create_personal_access_token(
        self, *, user_id: Any, name: str, scopes: list[str], ttl: int | None = None
    ) -> IssuedToken:
        return await self.issue(
            user_id=user_id,
            client_id=None,
            scopes=scopes,
            ttl=self.personal_access_ttl if ttl is None else ttl,
            name=name,
            personal_access=True,
        )

    async def refresh(
        self,
        refresh_token: str,
        scopes: list[str] | None = None,
        resource: str | None = None,
        client_id: str | None = None,
    ) -> IssuedToken:
        record = await call(self.repository.find_refresh_token, refresh_token)
        if record is not None and record.revoked:
            # A replayed, rotated-out token: consuming it revokes the whole family.
            await call(self.repository.consume_refresh_token, refresh_token)
        new_scopes = _refreshed_scopes(record, scopes, resource, client_id)
        # There is no lock shared across workers, so the successor joins the family before the old
        # token is consumed: any replay that sees the token used then revokes the successor too.
        issued = await self.issue(
            user_id=record.user_id,
            client_id=record.client_id,
            scopes=new_scopes,
            with_refresh=True,
            audience=record.resource,
            refresh_family_id=record.family_id,
        )
        # The repository's atomic consume picks one winner; replaying a used token revokes its family.
        if await call(self.repository.consume_refresh_token, refresh_token) is None:
            await call(self.repository.revoke_refresh_token, issued.refresh_token)
            await call(self.repository.revoke_access_token, issued.jti)
            raise InvalidGrant("The refresh token is invalid, expired, or revoked.")
        await call(self.repository.revoke_access_token, record.access_jti)
        return issued

    async def authenticate(self, access_token: str, audience: str | None = None) -> dict[str, Any]:
        return await self._active(self.encoder.decode(access_token, audience=audience))

    async def _active(self, claims: dict[str, Any]) -> dict[str, Any]:
        record = await call(self.repository.find_access_token, claims.get("jti", ""))
        if record is None or not record.active:
            raise InvalidToken("The access token has been revoked or is unknown.")
        return claims

    async def revoke_access(self, jti: str) -> bool:
        return await call(self.repository.revoke_access_token, jti)

    async def revoke_refresh(self, token_id: str) -> bool:
        return await call(self.repository.revoke_refresh_token, token_id)

    async def tokens_for(self, user_id: Any, personal_access: bool | None = None) -> list[AccessTokenRecord]:
        records = await call(self.repository.list_access_tokens, user_id, personal_access)
        return [r for r in records if not r.revoked]

    async def revoke_for_user(self, jti: str, user_id: Any, personal_access: bool | None = None) -> bool:
        if not _owned_by(await call(self.repository.find_access_token, jti), user_id, personal_access):
            return False
        return await call(self.repository.revoke_token_chain, jti)

    async def revoke_all_for_user(self, user_id: Any, personal_access: bool | None = None) -> int:
        revoked = 0
        for record in await self.tokens_for(user_id, personal_access):
            revoked += bool(await call(self.repository.revoke_token_chain, record.jti))
        return revoked

    async def revoke_token(self, token: str, client_id: str, allow_unbound: bool = False) -> bool:
        """RFC 7009: revoke an access or refresh token, with its whole chain, on behalf of ``client_id``."""
        record: AccessTokenRecord | RefreshTokenRecord | None = await call(self.repository.find_refresh_token, token)
        if record is not None:
            jti = record.access_jti
        else:
            jti = _decoded_jti(self.encoder, token)
            record = None if jti is None else await call(self.repository.find_access_token, jti)
        if record is None or not _bound_to(record, client_id, allow_unbound):
            return False
        return await call(self.repository.revoke_token_chain, jti)

    async def introspect(self, token: str) -> dict[str, Any]:
        refresh = await call(self.repository.find_refresh_token, token)
        if refresh is not None:
            return _refresh_introspection(refresh)
        try:
            claims = await self._active(self.encoder.decode(token, verify_audience=False))
        except InvalidToken:
            return {"active": False}
        return _introspection(await call(self.repository.find_access_token, claims["jti"]), claims)
