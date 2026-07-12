"""Covers the pluggable model-based provider and the ``masoniteorm`` driver
config shape from the user sketch, using a fake active-record model so the ORM
stays an optional dependency."""
from __future__ import annotations

from fastapi_passport.config import AuthConfig
from fastapi_passport.manager import AuthManager
from fastapi_passport.providers.model import ModelUserProvider
from fastapi_passport.security.hashing import BcryptHasher


class FakeQuery:
    def __init__(self, rows, field, value):
        self._match = next((r for r in rows if r.get(field) == value), None)

    def first(self):
        return self._match


class FakeUserModel:
    """Minimal masoniteorm-style model: dict rows with find/where classmethods."""

    _rows: list[dict] = []

    @classmethod
    def seed(cls, rows):
        cls._rows = rows

    @classmethod
    def find(cls, identifier):
        return next((r for r in cls._rows if r.get("id") == identifier), None)

    @classmethod
    def where(cls, field, value):
        return FakeQuery(cls._rows, field, value)


def build_model():
    hasher = BcryptHasher(rounds=4)
    FakeUserModel.seed([{"id": 1, "email": "ada@example.com", "password": hasher.make("secret")}])
    return FakeUserModel, hasher


def test_model_provider_retrieve_and_validate():
    model, hasher = build_model()
    provider = ModelUserProvider(model=model, hasher=hasher)
    user = provider.retrieve_by_credentials({"email": "ada@example.com"})
    assert user["id"] == 1
    assert provider.validate_credentials(user, {"password": "secret"}) is True
    assert provider.validate_credentials(user, {"password": "nope"}) is False
    assert provider.get_identifier(provider.retrieve_by_id(1)) == 1


def test_manager_accepts_masoniteorm_driver_config():
    model, hasher = build_model()

    class Config(AuthConfig):
        key = "model-provider-secret-key-32-bytes-minimum!"
        bcrypt_rounds = 4
        default = {"guard": "api", "passwords": "users"}
        guards = {"api": {"driver": "passport", "provider": "users"}}
        providers = {"users": {"driver": "masoniteorm", "model": model}}
        passwords = {"users": {"provider": "users", "expire": 60, "throttle": 60}}

    manager = AuthManager(Config)
    issued = manager.password_grant().handle(
        username="ada@example.com", password="secret", scopes=["read"], client_id=None
    )
    assert manager.guard().user_from_token(issued.access_token).user["id"] == 1
