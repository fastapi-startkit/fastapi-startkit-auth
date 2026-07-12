import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

from fastapi_passport import (
    Application,
    AuthProvider,
    AuthConfig,
    current_user,
    require_scopes,
)
from fastapi_passport.security.hashing import BcryptHasher
from fastapi_passport.providers.memory import InMemoryUserProvider


@pytest.fixture
def seeded_provider():
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    provider.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})
    provider.add({"id": 2, "email": "grace@example.com", "password": hasher.make("hopper")})
    return provider


@pytest.fixture
def app(seeded_provider):
    provider = seeded_provider

    class Config(AuthConfig):
        key = "integration-test-secret-key-32-bytes-min!"
        bcrypt_rounds = 4
        access_token_ttl = 3600
        # Tests read the reset token from the response; production leaves this off
        # and delivers via the notifier. Covered directly in test_security_fixes.
        debug_expose_reset_token = True
        default = {"guard": "api", "passwords": "users"}
        guards = {"api": {"driver": "passport", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": provider}}
        passwords = {
            "users": {"provider": "users", "table": "password_reset_tokens", "expire": 60, "throttle": 60}
        }

    application = Application([(AuthProvider, Config)])
    api = application.api

    # Demo routes exercising the package's public FastAPI dependencies, the way
    # a consuming application would wire them up.
    @api.get("/user")
    def read_current_user(user=Depends(current_user)):
        return user

    @api.get("/needs-read")
    def needs_read(ctx=Depends(require_scopes("read"))):
        return {"ok": True}

    @api.get("/needs-admin")
    def needs_admin(ctx=Depends(require_scopes("admin"))):
        return {"ok": True}

    return application


@pytest.fixture
def client(app):
    return TestClient(app.api)
