from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .. import orm
from .models import AccessTokenRecord, AuthorizationCode, RefreshTokenRecord


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class OrmTokenRepository:
    """OAuth access/refresh tokens and authorization codes on the tables created by the published migrations.

    Refresh tokens and authorization codes are stored by SHA-256 digest only.
    """

    def __init__(self, connection: str | None = None) -> None:
        self._connection = connection

    def _access(self) -> Any:
        return orm.query(orm.AuthAccessToken, self._connection)

    def _refresh(self) -> Any:
        return orm.query(orm.AuthRefreshToken, self._connection)

    def _codes(self) -> Any:
        return orm.query(orm.AuthCode, self._connection)

    async def store_access_token(
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
        record = AccessTokenRecord(
            jti=jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=expires_at,
            name=name,
            personal_access=personal_access,
        )
        await self._access().insert(
            {
                "jti": record.jti,
                "user_id": json.dumps(record.user_id),
                "client_id": record.client_id,
                "scopes": json.dumps(record.scopes),
                "expires_at": record.expires_at,
                "revoked": record.revoked,
                "name": record.name,
                "personal_access": record.personal_access,
                "created_at": record.created_at,
            }
        )
        return record

    async def find_access_token(self, jti: str) -> AccessTokenRecord | None:
        row = await self._access().where("jti", jti).first()
        return None if row is None else _access_record(orm.attributes(row))

    async def revoke_access_token(self, jti: str) -> bool:
        return await self._access().where("jti", jti).update({"revoked": True}) > 0

    async def list_access_tokens(self, user_id: Any, personal_access: bool | None = None) -> list[AccessTokenRecord]:
        query = self._access().where("user_id", json.dumps(user_id))
        if personal_access is not None:
            query = query.where("personal_access", personal_access)
        rows = await query.order_by("created_at").get()
        return [_access_record(orm.attributes(row)) for row in rows]

    async def store_refresh_token(
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
        record = RefreshTokenRecord(
            token_id=token_id,
            access_jti=access_jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=expires_at,
            resource=resource,
            # A new family is named after its first token, so only its digest may be stored.
            family_id=_digest(token_id) if family_id is None else family_id,
        )
        await self._refresh().insert(
            {
                "token_hash": _digest(token_id),
                "access_jti": record.access_jti,
                "user_id": json.dumps(record.user_id),
                "client_id": record.client_id,
                "scopes": json.dumps(record.scopes),
                "expires_at": record.expires_at,
                "revoked": record.revoked,
                "created_at": record.created_at,
                "resource": record.resource,
                "family_id": record.family_id,
            }
        )
        return record

    async def find_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        row = await self._refresh().where("token_hash", _digest(token_id)).first()
        return None if row is None else _refresh_record(token_id, orm.attributes(row))

    async def revoke_refresh_token(self, token_id: str) -> bool:
        # The conditional UPDATE is the atomic step: only the caller that flips revoked wins a rotation race.
        updated = (
            await self._refresh()
            .where("token_hash", _digest(token_id))
            .where("revoked", False)
            .update({"revoked": True})
        )
        return updated > 0

    async def consume_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        """Atomically rotate out a refresh token; replaying a used one revokes its family."""
        record = await self.find_refresh_token(token_id)
        if record is None or record.expired:
            return None
        if record.revoked or not await self.revoke_refresh_token(token_id):
            await self._revoke_families([record.family_id])
            return None
        record.revoked = True
        return record

    async def revoke_token_chain(self, jti: str) -> bool:
        """Revoke an access token plus every refresh token (and its access token) in the same family."""
        revoked = await self.revoke_access_token(jti)
        rows = await self._refresh().where("access_jti", jti).get()
        families = [orm.attributes(row)["family_id"] for row in rows]
        await self._revoke_families(families)
        return revoked or bool(families)

    async def _revoke_families(self, families: list[str | None]) -> None:
        # Rows written before the family_id migration keep a NULL family_id, so a
        # replay reaches only the tokens rotated from them after the upgrade.
        families = [family for family in families if family]
        if not families:
            return
        rows = await self._refresh().where_in("family_id", families).get()
        jtis = [orm.attributes(row)["access_jti"] for row in rows]
        await self._refresh().where_in("family_id", families).update({"revoked": True})
        if jtis:
            await self._access().where_in("jti", jtis).update({"revoked": True})

    async def store_auth_code(
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
        record = AuthorizationCode(
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
        await self._codes().insert(
            {
                "code_hash": _digest(code),
                "client_id": record.client_id,
                "user_id": json.dumps(record.user_id),
                "scopes": json.dumps(record.scopes),
                "redirect_uri": record.redirect_uri,
                "code_challenge": record.code_challenge,
                "code_challenge_method": record.code_challenge_method,
                "expires_at": record.expires_at,
                "resource": record.resource,
            }
        )
        return record

    async def pull_auth_code(self, code: str) -> AuthorizationCode | None:
        code_hash = _digest(code)
        row = await self._codes().where("code_hash", code_hash).first()
        if row is None:
            return None
        # Only the caller whose DELETE removes the row redeems it, so concurrent replays get one winner.
        if await self._codes().where("code_hash", code_hash).delete() != 1:
            return None
        data = orm.attributes(row)
        return AuthorizationCode(
            code=code,
            client_id=data["client_id"],
            user_id=json.loads(data["user_id"]),
            scopes=json.loads(data["scopes"]),
            redirect_uri=data["redirect_uri"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
            expires_at=data["expires_at"],
            resource=data.get("resource"),
        )

    async def purge_expired(self) -> None:
        now = time.time()
        await self._refresh().where("expires_at", "<", now).delete()
        # A live refresh token still needs its access record so a chain revocation can find it.
        rows = await self._refresh().where("revoked", False).get()
        linked = [orm.attributes(row)["access_jti"] for row in rows]
        expired = self._access().where("expires_at", "<", now)
        if linked:
            expired = expired.where_not_in("jti", linked)
        await expired.delete()
        await self._codes().where("expires_at", "<", now).delete()


def _refresh_record(token_id: str, data: dict[str, Any]) -> RefreshTokenRecord:
    return RefreshTokenRecord(
        token_id=token_id,
        access_jti=data["access_jti"],
        user_id=json.loads(data["user_id"]),
        client_id=data["client_id"],
        scopes=json.loads(data["scopes"]),
        expires_at=data["expires_at"],
        revoked=bool(data["revoked"]),
        created_at=data["created_at"],
        resource=data.get("resource"),
        family_id=data.get("family_id") or _digest(token_id),
    )


def _access_record(row: dict[str, Any]) -> AccessTokenRecord:
    return AccessTokenRecord(
        jti=row["jti"],
        user_id=json.loads(row["user_id"]),
        client_id=row["client_id"],
        scopes=json.loads(row["scopes"]),
        expires_at=row["expires_at"],
        revoked=bool(row["revoked"]),
        name=row["name"],
        personal_access=bool(row["personal_access"]),
        created_at=row["created_at"],
    )
