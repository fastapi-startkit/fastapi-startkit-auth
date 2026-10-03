"""ORM models for the auth tables, on the fastapi-startkit ORM.

The models only describe the tables created by the published migrations; the
stores read and write them through the query builder, so timestamps stay the
epoch floats the records use. Importing this module requires the ``startkit``
extra.
"""
from __future__ import annotations

from typing import Any

try:
    from fastapi_startkit.masoniteorm.models import Model
except ImportError as exc:  # pragma: no cover - exercised via the manager
    raise ImportError(
        "The ORM-backed stores require the optional 'fastapi-startkit' framework with its database "
        "support. Install it with: pip install fastapi-startkit-auth[startkit]"
    ) from exc


class _AuthModel(Model):
    __timestamps__ = False
    __incrementing__ = False


class AuthSession(_AuthModel):
    __table__ = "sessions"
    __primary_key__ = "id"

    id: str
    user_id: str
    guard: str
    csrf_token: str
    created_at: float
    last_activity: float
    expires_at: float


class AuthApiToken(_AuthModel):
    __table__ = "personal_api_tokens"
    __primary_key__ = "id"

    id: str
    user_id: str
    token_hash: str
    name: str
    abilities: str
    last_used_at: float
    expires_at: float
    created_at: float


class AuthAccessToken(_AuthModel):
    __table__ = "oauth_access_tokens"
    __primary_key__ = "jti"

    jti: str
    user_id: str
    client_id: str
    scopes: str
    expires_at: float
    revoked: bool
    name: str
    personal_access: bool
    created_at: float


class AuthRefreshToken(_AuthModel):
    __table__ = "oauth_refresh_tokens"
    __primary_key__ = "token_hash"

    token_hash: str
    access_jti: str
    user_id: str
    client_id: str
    scopes: str
    expires_at: float
    revoked: bool
    created_at: float
    resource: str


class AuthCode(_AuthModel):
    __table__ = "oauth_auth_codes"
    __primary_key__ = "code_hash"

    code_hash: str
    client_id: str
    user_id: str
    scopes: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    expires_at: float
    resource: str


class AuthClient(_AuthModel):
    __table__ = "oauth_clients"
    __primary_key__ = "id"

    id: str
    name: str
    secret: str
    redirect_uris: str
    confidential: bool
    grant_types: str
    scopes: str
    provider: str
    owner_id: str
    revoked: bool
    created_at: float


def query(model: type[Model], connection: str | None = None) -> Any:
    """A query builder for ``model`` on the named ORM connection (default: the app default)."""
    instance = model()
    if connection is not None:
        instance.set_connection(connection)
    return instance.new_query()


def attributes(row: Model) -> dict[str, Any]:
    return row.get_attributes()
