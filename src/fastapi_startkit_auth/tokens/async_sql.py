from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Sequence

from ..database import async_database
from .models import AccessTokenRecord, AuthorizationCode, RefreshTokenRecord

_ACCESS_COLUMNS = "jti, user_id, client_id, scopes, expires_at, revoked, name, personal_access, created_at"
_REFRESH_COLUMNS = "token_hash, access_jti, user_id, client_id, scopes, expires_at, revoked, created_at"
_CODE_COLUMNS = "code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at"


def token_table_ddl(
    access_table: str = "oauth_access_tokens",
    refresh_table: str = "oauth_refresh_tokens",
    codes_table: str = "oauth_auth_codes",
) -> list[str]:
    return [
        f"CREATE TABLE IF NOT EXISTS {access_table} ("
        "jti VARCHAR(255) PRIMARY KEY, "
        "user_id TEXT, "
        "client_id VARCHAR(255), "
        "scopes TEXT NOT NULL, "
        "expires_at DOUBLE PRECISION, "
        "revoked BOOLEAN NOT NULL DEFAULT FALSE, "
        "name VARCHAR(255), "
        "personal_access BOOLEAN NOT NULL DEFAULT FALSE, "
        "created_at DOUBLE PRECISION NOT NULL)",
        f"CREATE INDEX IF NOT EXISTS {access_table}_user_id_index ON {access_table} (user_id)",
        f"CREATE INDEX IF NOT EXISTS {access_table}_expires_at_index ON {access_table} (expires_at)",
        f"CREATE TABLE IF NOT EXISTS {refresh_table} ("
        "token_hash VARCHAR(64) PRIMARY KEY, "
        "access_jti VARCHAR(255) NOT NULL, "
        "user_id TEXT, "
        "client_id VARCHAR(255), "
        "scopes TEXT NOT NULL, "
        "expires_at DOUBLE PRECISION, "
        "revoked BOOLEAN NOT NULL DEFAULT FALSE, "
        "created_at DOUBLE PRECISION NOT NULL)",
        f"CREATE INDEX IF NOT EXISTS {refresh_table}_expires_at_index ON {refresh_table} (expires_at)",
        f"CREATE TABLE IF NOT EXISTS {codes_table} ("
        "code_hash VARCHAR(64) PRIMARY KEY, "
        "client_id VARCHAR(255) NOT NULL, "
        "user_id TEXT, "
        "scopes TEXT NOT NULL, "
        "redirect_uri TEXT, "
        "code_challenge VARCHAR(255), "
        "code_challenge_method VARCHAR(32), "
        "expires_at DOUBLE PRECISION NOT NULL)",
    ]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class AsyncSqlTokenRepository:
    def __init__(
        self,
        connection: Any,
        access_table: str = "oauth_access_tokens",
        refresh_table: str = "oauth_refresh_tokens",
        codes_table: str = "oauth_auth_codes",
    ) -> None:
        self._db = async_database(connection)
        self._access = access_table
        self._refresh = refresh_table
        self._codes = codes_table

    async def create_table(self) -> None:
        for statement in token_table_ddl(self._access, self._refresh, self._codes):
            await self._db.execute(statement)

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
        await self._db.execute(
            f"INSERT INTO {self._access} ({_ACCESS_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.jti,
                json.dumps(record.user_id),
                record.client_id,
                json.dumps(record.scopes),
                record.expires_at,
                record.revoked,
                record.name,
                record.personal_access,
                record.created_at,
            ),
        )
        return record

    async def find_access_token(self, jti: str) -> AccessTokenRecord | None:
        row = await self._db.fetch_one(f"SELECT {_ACCESS_COLUMNS} FROM {self._access} WHERE jti = ?", (jti,))
        return None if row is None else _access_record(row)

    async def revoke_access_token(self, jti: str) -> bool:
        return await self._db.execute(f"UPDATE {self._access} SET revoked = ? WHERE jti = ?", (True, jti)) > 0

    async def list_access_tokens(self, user_id: Any, personal_access: bool | None = None) -> list[AccessTokenRecord]:
        sql = f"SELECT {_ACCESS_COLUMNS} FROM {self._access} WHERE user_id = ?"
        params: list[Any] = [json.dumps(user_id)]
        if personal_access is not None:
            sql += " AND personal_access = ?"
            params.append(personal_access)
        rows = await self._db.fetch_all(sql + " ORDER BY created_at", params)
        return [_access_record(row) for row in rows]

    async def store_refresh_token(
        self,
        *,
        token_id: str,
        access_jti: str,
        user_id: Any | None,
        client_id: str | None,
        scopes: list[str],
        expires_at: float | None,
    ) -> RefreshTokenRecord:
        record = RefreshTokenRecord(
            token_id=token_id,
            access_jti=access_jti,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=expires_at,
        )
        await self._db.execute(
            f"INSERT INTO {self._refresh} ({_REFRESH_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _digest(token_id),
                record.access_jti,
                json.dumps(record.user_id),
                record.client_id,
                json.dumps(record.scopes),
                record.expires_at,
                record.revoked,
                record.created_at,
            ),
        )
        return record

    async def find_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        row = await self._db.fetch_one(
            f"SELECT {_REFRESH_COLUMNS} FROM {self._refresh} WHERE token_hash = ?", (_digest(token_id),)
        )
        if row is None:
            return None
        return RefreshTokenRecord(
            token_id=token_id,
            access_jti=row[1],
            user_id=json.loads(row[2]),
            client_id=row[3],
            scopes=json.loads(row[4]),
            expires_at=row[5],
            revoked=bool(row[6]),
            created_at=row[7],
        )

    async def revoke_refresh_token(self, token_id: str) -> bool:
        updated = await self._db.execute(
            f"UPDATE {self._refresh} SET revoked = ? WHERE token_hash = ? AND revoked = ?",
            (True, _digest(token_id), False),
        )
        return updated > 0

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
        )
        await self._db.execute(
            f"INSERT INTO {self._codes} ({_CODE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _digest(code),
                record.client_id,
                json.dumps(record.user_id),
                json.dumps(record.scopes),
                record.redirect_uri,
                record.code_challenge,
                record.code_challenge_method,
                record.expires_at,
            ),
        )
        return record

    async def pull_auth_code(self, code: str) -> AuthorizationCode | None:
        code_hash = _digest(code)
        row = await self._db.fetch_one(f"SELECT {_CODE_COLUMNS} FROM {self._codes} WHERE code_hash = ?", (code_hash,))
        if row is None:
            return None
        # Only the caller whose DELETE removes the row redeems it, so concurrent replays get one winner.
        if await self._db.execute(f"DELETE FROM {self._codes} WHERE code_hash = ?", (code_hash,)) != 1:
            return None
        return AuthorizationCode(
            code=code,
            client_id=row[1],
            user_id=json.loads(row[2]),
            scopes=json.loads(row[3]),
            redirect_uri=row[4],
            code_challenge=row[5],
            code_challenge_method=row[6],
            expires_at=row[7],
        )

    async def purge_expired(self) -> None:
        now = time.time()
        await self._db.execute(f"DELETE FROM {self._access} WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        await self._db.execute(f"DELETE FROM {self._refresh} WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        await self._db.execute(f"DELETE FROM {self._codes} WHERE expires_at < ?", (now,))


def _access_record(row: Sequence[Any]) -> AccessTokenRecord:
    return AccessTokenRecord(
        jti=row[0],
        user_id=json.loads(row[1]),
        client_id=row[2],
        scopes=json.loads(row[3]),
        expires_at=row[4],
        revoked=bool(row[5]),
        name=row[6],
        personal_access=bool(row[7]),
        created_at=row[8],
    )
