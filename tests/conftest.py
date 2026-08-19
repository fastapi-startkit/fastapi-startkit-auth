"""Shared test fixtures.

Consolidates the PKCE ``s256`` helper and the OAuth app/``TestClient`` builders
that were previously copy-pasted across the integration and security test
modules. Everything stays in-memory (no DB, no network): providers use
``InMemoryUserProvider`` and the ASGI app is driven in-process by ``TestClient``.
"""
import base64
import hashlib

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

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
