import pytest

from fastapi_passport.security.hashing import BcryptHasher
from fastapi_passport.providers.memory import InMemoryUserProvider


@pytest.fixture
def provider():
    hasher = BcryptHasher(rounds=4)
    p = InMemoryUserProvider(hasher=hasher, username_field="email")
    p.add({"id": 1, "email": "ada@example.com", "password": hasher.make("pw1")})
    p.add({"id": 2, "email": "grace@example.com", "password": hasher.make("pw2")})
    return p


def test_retrieve_by_id(provider):
    user = provider.retrieve_by_id(1)
    assert user["email"] == "ada@example.com"


def test_retrieve_by_id_missing_returns_none(provider):
    assert provider.retrieve_by_id(999) is None


def test_retrieve_by_credentials_finds_user_without_checking_password(provider):
    user = provider.retrieve_by_credentials({"email": "grace@example.com", "password": "anything"})
    assert user["id"] == 2


def test_retrieve_by_credentials_unknown_user(provider):
    assert provider.retrieve_by_credentials({"email": "nobody@example.com"}) is None


def test_validate_credentials_accepts_correct_password(provider):
    user = provider.retrieve_by_id(1)
    assert provider.validate_credentials(user, {"password": "pw1"}) is True


def test_validate_credentials_rejects_wrong_password(provider):
    user = provider.retrieve_by_id(1)
    assert provider.validate_credentials(user, {"password": "nope"}) is False


def test_get_identifier(provider):
    user = provider.retrieve_by_id(2)
    assert provider.get_identifier(user) == 2


def test_add_returns_stored_user_and_update_password(provider):
    user = provider.retrieve_by_id(1)
    provider.update_password(user, "brand-new-password")
    assert provider.validate_credentials(provider.retrieve_by_id(1), {"password": "brand-new-password"}) is True
    assert provider.validate_credentials(provider.retrieve_by_id(1), {"password": "pw1"}) is False
