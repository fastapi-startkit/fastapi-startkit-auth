import pytest

from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider


@pytest.fixture
def provider():
    hasher = BcryptHasher(rounds=4)
    p = InMemoryUserProvider(hasher=hasher, username_field="email")
    p.add({"id": 1, "email": "ada@example.com", "password": hasher.make("pw1")})
    p.add({"id": 2, "email": "grace@example.com", "password": hasher.make("pw2")})
    return p


async def test_retrieve_by_id(provider):
    user = await provider.retrieve_by_id(1)
    assert user["email"] == "ada@example.com"


async def test_retrieve_by_id_missing_returns_none(provider):
    assert await provider.retrieve_by_id(999) is None


async def test_retrieve_by_credentials_finds_user_without_checking_password(provider):
    user = await provider.retrieve_by_credentials({"email": "grace@example.com", "password": "anything"})
    assert user["id"] == 2


async def test_retrieve_by_credentials_unknown_user(provider):
    assert await provider.retrieve_by_credentials({"email": "nobody@example.com"}) is None


async def test_validate_credentials_accepts_correct_password(provider):
    user = await provider.retrieve_by_id(1)
    assert await provider.validate_credentials(user, {"password": "pw1"}) is True


async def test_validate_credentials_rejects_wrong_password(provider):
    user = await provider.retrieve_by_id(1)
    assert await provider.validate_credentials(user, {"password": "nope"}) is False


async def test_get_identifier(provider):
    user = await provider.retrieve_by_id(2)
    assert provider.get_identifier(user) == 2


async def test_add_returns_stored_user_and_update_password(provider):
    user = await provider.retrieve_by_id(1)
    await provider.update_password(user, "brand-new-password")
    assert await provider.validate_credentials(await provider.retrieve_by_id(1), {"password": "brand-new-password"}) is True
    assert await provider.validate_credentials(await provider.retrieve_by_id(1), {"password": "pw1"}) is False


async def test_protocol_declares_dummy_verify(provider):
    # Timing equalization is part of the contract: custom providers get told
    # (by the protocol) to implement it, not just the shipped ones.
    from fastapi_startkit_auth.providers.base import UserProvider

    assert callable(getattr(UserProvider, "dummy_verify"))
    assert isinstance(provider, UserProvider)
    await provider.dummy_verify()  # must not raise


def test_provider_without_dummy_verify_fails_the_protocol_check():
    from fastapi_startkit_auth.providers.base import UserProvider

    class Incomplete:
        def retrieve_by_id(self, identifier): ...
        def retrieve_by_credentials(self, credentials): ...
        def validate_credentials(self, user, credentials): ...
        def get_identifier(self, user): ...
        def update_password(self, user, plain): ...

    assert not isinstance(Incomplete(), UserProvider)
