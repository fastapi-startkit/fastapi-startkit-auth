import pytest

from fastapi_passport.config import AuthConfig
from fastapi_passport.manager import AuthManager
from fastapi_passport.security.hashing import BcryptHasher
from fastapi_passport.providers.memory import InMemoryUserProvider
from fastapi_passport.exceptions import InvalidToken


@pytest.fixture
def manager():
    hasher = BcryptHasher(rounds=4)
    seeded = InMemoryUserProvider(hasher=hasher, username_field="email")
    seeded.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})

    class Config(AuthConfig):
        key = "manager-test-secret-key-32-bytes-minimum!"
        bcrypt_rounds = 4
        default = {"guard": "api", "passwords": "users"}
        guards = {"api": {"driver": "passport", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": seeded}}
        passwords = {
            "users": {"provider": "users", "table": "password_reset_tokens", "expire": 60, "throttle": 60}
        }

    return AuthManager(Config)


def test_manager_resolves_default_guard(manager):
    guard = manager.guard()
    assert guard.name == "api"


def test_manager_resolves_named_provider(manager):
    provider = manager.provider("users")
    assert provider.retrieve_by_id(1)["email"] == "ada@example.com"


def test_guard_authenticates_issued_token(manager):
    issued = manager.token_service.issue(user_id=1, client_id="c1", scopes=["read"])
    ctx = manager.guard().user_from_token(issued.access_token)
    assert ctx.user["email"] == "ada@example.com"
    assert ctx.scopes == ["read"]
    assert ctx.can("read") is True
    assert ctx.can("write") is False


def test_guard_rejects_revoked_token(manager):
    issued = manager.token_service.issue(user_id=1, client_id="c1", scopes=["read"])
    manager.token_service.revoke_access(manager.token_service.authenticate(issued.access_token)["jti"])
    with pytest.raises(InvalidToken):
        manager.guard().user_from_token(issued.access_token)


def test_manager_builds_password_broker(manager):
    broker = manager.broker()
    token = broker.send_reset_link("ada@example.com")
    assert broker.reset("ada@example.com", token, "new-secret") is True


def test_manager_exposes_grants(manager):
    issued = manager.password_grant().handle(
        username="ada@example.com", password="secret", scopes=["read"], client_id="c1"
    )
    assert manager.guard().user_from_token(issued.access_token).user["id"] == 1


def test_config_defaults_are_readable_without_subclass_overrides():
    # A minimal config must still yield working token TTLs.
    class Config(AuthConfig):
        key = "another-secret-key-that-is-32-bytes-long!"
        providers = {"users": {"driver": "instance", "instance": InMemoryUserProvider()}}

    manager = AuthManager(Config)
    assert manager.token_service.access_ttl == AuthConfig.access_token_ttl
