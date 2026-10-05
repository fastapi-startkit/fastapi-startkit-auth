"""Shared test fixtures.

Consolidates the PKCE ``s256`` helper and the OAuth app/``TestClient`` builders
used across the integration and security test modules. Everything stays
in-memory (no DB, no network) unless a test asks for ``orm_database``.
"""
import asyncio
import base64
import hashlib
import os
import secrets
import uuid
from inspect import isawaitable
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import fastapi_startkit_auth
from fastapi_startkit_auth import (
    AuthApiTokenProvider,
    AuthConfig,
    AuthManager,
    AuthOAuth2Provider,
    AuthProvider,
    AuthSessionProvider,
    OAuth2Config,
    OAuthClientsConfig,
    current_user,
    require_scopes,
)
from fastapi_startkit_auth.clients.models import Client
from fastapi_startkit_auth.config import DEFAULT_GRANT_TYPES
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

TEST_OAUTH_KEY = "conftest-shared-secret-key-32-bytes-minimum!"
PASSWORD_GRANTS = [*DEFAULT_GRANT_TYPES, "password"]
# RFC 7636 §4.1: a verifier is 43-128 unreserved characters.
VERIFIER = "v" * 43


class BrowserTestClient(TestClient):
    """Echoes the XSRF-TOKEN cookie into the header, like an SPA's HTTP client."""

    def request(self, method, url, **kwargs):
        token = self.cookies.get("XSRF-TOKEN")
        if token is not None:
            kwargs["headers"] = {"X-XSRF-TOKEN": token, **dict(kwargs.get("headers") or {})}
        return super().request(method, url, **kwargs)


class SyncClientRepository:
    """A synchronous client store.

    The shipped stores are async, which makes the manager pick the async grants;
    this double keeps the sync grant classes covered by the suite.
    ``authenticate`` mirrors ``verified_client`` in clients/credentials.py, the
    source of truth; keep the two in step.
    """

    def __init__(self, hasher=None):
        self._hasher = hasher or BcryptHasher(rounds=4)
        self._clients = {}

    def register(self, *, name, redirect_uris=None, confidential=True, grant_types=None, provider=None, scopes=None):
        secret = secrets.token_urlsafe(40) if confidential else None
        client = Client(
            id=uuid.uuid4().hex,
            name=name,
            redirect_uris=list(redirect_uris or []),
            confidential=confidential,
            grant_types=list(grant_types or []),
            provider=provider,
            scopes=[] if scopes is None else scopes,
        )
        if secret is not None:
            client.secret = self._hasher.make(secret)
        return self.add(client), secret

    def add(self, client):
        self._clients[client.id] = client
        return client

    def find(self, client_id):
        return self._clients.get(client_id)

    def all(self):
        return list(self._clients.values())

    def authenticate(self, client_id, secret):
        client = self._clients.get(client_id)
        if client is None or client.revoked:
            return None
        if not client.confidential:
            return client
        if secret is None or client.secret is None:
            return None
        return client if self._hasher.verify(secret, client.secret) else None

    def revoke(self, client_id):
        client = self._clients.get(client_id)
        if client is None:
            return False
        client.revoked = True
        return True

    def delete(self, client_id):
        return self._clients.pop(client_id, None) is not None


def oauth2_config(**overrides):
    overrides.setdefault("key", TEST_OAUTH_KEY)
    overrides.setdefault("clients", OAuthClientsConfig(store="instance", instance=SyncClientRepository()))
    return OAuth2Config(**overrides)


def register_auth(app, config, *, session=None, oauth2=None, api_tokens=None, prefix=""):
    core = AuthProvider(config, prefix)
    core.register(app)
    if session is not None:
        AuthSessionProvider(session, prefix).register(app)
    if oauth2 is not None:
        AuthOAuth2Provider(oauth2, prefix).register(app)
    if api_tokens is not None:
        AuthApiTokenProvider(api_tokens, prefix).register(app)
    core.manager.validate()
    return core.manager


def auth_manager(config, *, session=None, oauth2=None, api_tokens=None):
    manager = AuthManager(config)
    if session is not None:
        manager.use_sessions(session)
    if oauth2 is not None:
        manager.use_oauth2(oauth2)
    if api_tokens is not None:
        manager.use_api_tokens(api_tokens)
    return manager


def _register_with(manager, **attributes):
    attributes.setdefault("redirect_uris", [])
    registered = manager.client_repository.register(**attributes)
    return asyncio.run(registered) if isawaitable(registered) else registered


def register_client(test_client_or_manager, **attributes):
    """Register an OAuth client straight on the store (the HTTP CRUD routes are gone)."""
    manager = getattr(getattr(test_client_or_manager, "app", None), "state", None)
    manager = manager.auth_manager if manager is not None else test_client_or_manager
    client, secret = _register_with(manager, **attributes)
    return {
        "id": client.id,
        "name": client.name,
        "secret": secret,
        "redirect_uris": client.redirect_uris,
        "confidential": client.confidential,
        "grant_types": client.grant_types,
    }


def s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


DEFAULT_USERS = (
    {"id": 1, "email": "ada@example.com", "password": "secret"},
    {"id": 2, "email": "grace@example.com", "password": "hopper"},
)


@pytest.fixture
def s256():
    """PKCE ``S256`` code challenge for a verifier."""
    return s256_challenge


def seed_provider(users=DEFAULT_USERS):
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    for user in users:
        row = dict(user)
        row["password"] = hasher.make(row["password"])
        provider.add(row)
    return provider


def _build_app(*, users, notifier, debug_expose, throttle, expire, configure_api, oauth2=None):
    provider = seed_provider(users)

    class Config(AuthConfig):
        bcrypt_rounds = 4
        debug_expose_reset_token = debug_expose
        password_reset_notifier = staticmethod(notifier) if notifier else None
        default = {"guard": "api", "passwords": "users"}
        guards = {"api": {"driver": "passport", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": provider}}
        passwords = {
            "users": {"provider": "users", "table": "password_reset_tokens",
                      "expire": expire, "throttle": throttle}
        }

    app = FastAPI(title="FastAPI Startkit Auth")
    register_auth(app, Config, oauth2=oauth2 or oauth2_config(grant_types=list(PASSWORD_GRANTS)))
    if configure_api is not None:
        configure_api(app)
    return app


def make_auth_client(*, users=DEFAULT_USERS, debug_expose=False, throttle=60,
                     expire=60, configure_api=None, oauth2=None):
    """Build a ``TestClient`` for a seeded OAuth app (password grant enabled).

    Returns ``(client, sent)`` where ``sent`` collects ``(email, token)`` pairs
    delivered through the password-reset notifier, so tests can assert on
    out-of-band delivery without reading tokens from the HTTP response.
    """
    sent = []
    app = _build_app(
        users=users,
        notifier=lambda email, token: sent.append((email, token)),
        debug_expose=debug_expose,
        throttle=throttle,
        expire=expire,
        configure_api=configure_api,
        oauth2=oauth2,
    )
    return TestClient(app), sent


@pytest.fixture
def auth_client():
    """Factory fixture: call it to build a fresh, isolated ``(client, sent)``."""
    return make_auth_client


@pytest.fixture
def client():
    """Integration client wiring the package's public FastAPI dependencies the
    way a consuming application would, plus the debug reset-token echo so tests
    can read the token from the response."""
    def configure_api(api):
        @api.get("/user")
        def read_current_user(user=Depends(current_user)):
            return user

        @api.get("/needs-read")
        def needs_read(ctx=Depends(require_scopes("read"))):
            return {"ok": True}

        @api.get("/needs-admin")
        def needs_admin(ctx=Depends(require_scopes("admin"))):
            return {"ok": True}

    test_client, _ = make_auth_client(debug_expose=True, configure_api=configure_api)
    return test_client


MIGRATIONS_DIR = Path(fastapi_startkit_auth.__file__).parent / "publishable" / "migrations"
POSTGRES_DSN = os.environ.get("TEST_ASYNCPG_DSN")
ORM_CONNECTION = "auth_test"


def _orm_config(backend, tmp_path):
    if backend == "sqlite":
        return {"driver": "sqlite", "database": str(tmp_path / "auth.db")}
    if not POSTGRES_DSN:
        pytest.skip("TEST_ASYNCPG_DSN is not set")
    # Discrete keys rather than "url": the ORM lists tables by the "database" key when dropping them.
    dsn = urlparse(POSTGRES_DSN)
    return {
        "driver": "postgres",
        "host": dsn.hostname,
        "port": dsn.port or 5432,
        "database": dsn.path.lstrip("/"),
        "username": unquote(dsn.username or ""),
        "password": unquote(dsn.password or ""),
    }


@pytest.fixture(params=["sqlite", "postgres"])
async def orm_database(request, tmp_path):
    """Name of a migrated ORM connection: SQLite, or the throwaway Postgres in TEST_ASYNCPG_DSN."""
    pytest.importorskip("fastapi_startkit.masoniteorm.models")
    from fastapi_startkit.application import Application as StartkitApplication
    from fastapi_startkit.masoniteorm import Migrator, Model
    from fastapi_startkit.masoniteorm.connections.factory import ConnectionFactory
    from fastapi_startkit.masoniteorm.connections.manager import DatabaseManager

    config = _orm_config(request.param, tmp_path)
    StartkitApplication(env="testing")
    manager = DatabaseManager(ConnectionFactory(), {"default": ORM_CONNECTION, "connections": {ORM_CONNECTION: config}})
    Model.db_manager = manager
    Migrator.db_manager = manager
    migrator = Migrator(migration_directory=str(MIGRATIONS_DIR), connection=ORM_CONNECTION)
    await migrator.create_table_if_not_exists()
    await migrator.fresh(ignore_fk=True)
    yield ORM_CONNECTION
    await manager.clear()
