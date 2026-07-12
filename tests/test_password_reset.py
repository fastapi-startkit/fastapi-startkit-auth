import time

import pytest

from fastapi_startkit_auth.exceptions import InvalidGrant, ThrottleException
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.passwords.repository import InMemoryPasswordResetRepository
from fastapi_startkit_auth.passwords.broker import PasswordBroker


@pytest.fixture
def hasher():
    return BcryptHasher(rounds=4)


@pytest.fixture
def users(hasher):
    p = InMemoryUserProvider(hasher=hasher, username_field="email")
    p.add({"id": 1, "email": "ada@example.com", "password": hasher.make("old-password")})
    return p


def make_broker(users, hasher, **kw):
    return PasswordBroker(
        user_provider=users,
        repository=InMemoryPasswordResetRepository(),
        hasher=hasher,
        expire_minutes=kw.get("expire_minutes", 60),
        throttle_seconds=kw.get("throttle_seconds", 60),
    )


def test_send_reset_link_returns_token(users, hasher):
    broker = make_broker(users, hasher)
    token = broker.send_reset_link("ada@example.com")
    assert isinstance(token, str) and token


def test_send_reset_link_unknown_email_raises(users, hasher):
    broker = make_broker(users, hasher)
    with pytest.raises(InvalidGrant):
        broker.send_reset_link("ghost@example.com")


def test_reset_changes_password(users, hasher):
    broker = make_broker(users, hasher)
    token = broker.send_reset_link("ada@example.com")
    assert broker.reset("ada@example.com", token, "new-password") is True
    assert users.validate_credentials(users.retrieve_by_id(1), {"password": "new-password"}) is True
    assert users.validate_credentials(users.retrieve_by_id(1), {"password": "old-password"}) is False


def test_reset_with_wrong_token_fails(users, hasher):
    broker = make_broker(users, hasher)
    broker.send_reset_link("ada@example.com")
    with pytest.raises(InvalidGrant):
        broker.reset("ada@example.com", "not-the-token", "new-password")


def test_reset_token_is_single_use(users, hasher):
    broker = make_broker(users, hasher)
    token = broker.send_reset_link("ada@example.com")
    broker.reset("ada@example.com", token, "new-password")
    with pytest.raises(InvalidGrant):
        broker.reset("ada@example.com", token, "another-password")


def test_expired_token_is_rejected(users, hasher):
    broker = make_broker(users, hasher, expire_minutes=0)
    token = broker.send_reset_link("ada@example.com")
    time.sleep(0.01)
    with pytest.raises(InvalidGrant):
        broker.reset("ada@example.com", token, "new-password")


def test_throttle_blocks_rapid_requests(users, hasher):
    broker = make_broker(users, hasher, throttle_seconds=60)
    broker.send_reset_link("ada@example.com")
    with pytest.raises(ThrottleException):
        broker.send_reset_link("ada@example.com")


def test_throttle_allows_after_window(users, hasher):
    broker = make_broker(users, hasher, throttle_seconds=0)
    broker.send_reset_link("ada@example.com")
    # zero throttle window: a second request is permitted immediately
    assert broker.send_reset_link("ada@example.com")
