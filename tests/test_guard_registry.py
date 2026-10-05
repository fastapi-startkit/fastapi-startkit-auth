import pytest

from fastapi_startkit_auth.config import AuthConfig
from fastapi_startkit_auth.guards import AuthContext, Guard, PassportGuard
from fastapi_startkit_auth.manager import AuthManager
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

from conftest import auth_manager, oauth2_config


def _config(guards):
    hasher = BcryptHasher(rounds=4)
    seeded = InMemoryUserProvider(hasher=hasher, username_field="email")
    seeded.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})

    class Config(AuthConfig):
        bcrypt_rounds = 4
        default = {"guard": "api", "passwords": "users"}
        providers = {"users": {"driver": "instance", "instance": seeded}}

    Config.guards = guards
    return Config


def _manager(config):
    return auth_manager(config, oauth2=oauth2_config())


def test_passport_driver_resolves_through_registry():
    manager = _manager(_config({"api": {"driver": "passport", "provider": "users"}}))
    guard = manager.guard("api")
    assert isinstance(guard, PassportGuard)
    assert guard.name == "api"


def test_guard_spec_defaults_to_passport_driver():
    # Behavior is unchanged for specs that omit an explicit driver.
    manager = _manager(_config({"api": {"provider": "users"}}))
    assert isinstance(manager.guard("api"), PassportGuard)


def test_unknown_guard_driver_raises_clear_error():
    manager = _manager(_config({"web": {"driver": "quantum", "provider": "users"}}))
    with pytest.raises(ValueError, match="Unknown auth guard driver: 'quantum'"):
        manager.guard("web")


def test_custom_guard_driver_can_be_registered_and_resolved():
    class StubGuard:
        def __init__(self, name, provider):
            self.name = name
            self.provider = provider

        def user_from_token(self, access_token):
            return AuthContext(user=None)

    class StubManager(AuthManager):
        def __init__(self, config):
            super().__init__(config)
            self.use_oauth2(oauth2_config())
            self.register_guard_driver("stub", self._build_stub_guard)
            self._guard_specs["custom"] = {"driver": "stub", "provider": "users"}

        def _build_stub_guard(self, name, spec):
            return StubGuard(name, self._require_provider(spec.get("provider")))

    manager = StubManager(_config({"api": {"driver": "passport", "provider": "users"}}))
    guard = manager.guard("custom")
    assert isinstance(guard, StubGuard)
    assert guard.name == "custom"


def test_passport_guard_satisfies_guard_protocol():
    manager = _manager(_config({"api": {"driver": "passport", "provider": "users"}}))
    assert isinstance(manager.guard("api"), Guard)
