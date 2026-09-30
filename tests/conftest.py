"""Shared test fixtures.

Consolidates the PKCE ``s256`` helper and the OAuth app/``TestClient`` builders
that were previously copy-pasted across the integration and security test
modules. Everything stays in-memory (no DB, no network): providers use
``InMemoryUserProvider`` and the ASGI app is driven in-process by ``TestClient``.
"""
import base64
import hashlib
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

import fastapi_startkit_auth
from fastapi_startkit_auth import (
    Application,
    AuthProvider,
    AuthConfig,
    current_user,
    require_scopes,
)
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider


DEFAULT_USERS = (
    {"id": 1, "email": "ada@example.com", "password": "secret"},
    {"id": 2, "email": "grace@example.com", "password": "hopper"},
)


@pytest.fixture
def s256():
    """PKCE ``S256`` code challenge for a verifier."""
    def _s256(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    return _s256


def _seed_provider(users):
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    for user in users:
        row = dict(user)
        row["password"] = hasher.make(row["password"])
        provider.add(row)
    return provider


def _build_app(*, users, notifier, debug_expose, throttle, expire, configure_api):
    provider = _seed_provider(users)

    class Config(AuthConfig):
        key = "conftest-shared-secret-key-32-bytes-minimum!"
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

    application = Application([(AuthProvider, Config)])
    if configure_api is not None:
        configure_api(application.api)
    return application


def make_auth_client(*, users=DEFAULT_USERS, debug_expose=False, throttle=60,
                     expire=60, configure_api=None):
    """Build a ``TestClient`` for a seeded OAuth app.

    Returns ``(client, sent)`` where ``sent`` collects ``(email, token)`` pairs
    delivered through the password-reset notifier, so tests can assert on
    out-of-band delivery without reading tokens from the HTTP response.
    """
    sent = []
    application = _build_app(
        users=users,
        notifier=lambda email, token: sent.append((email, token)),
        debug_expose=debug_expose,
        throttle=throttle,
        expire=expire,
        configure_api=configure_api,
    )
    return TestClient(application.api), sent


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
