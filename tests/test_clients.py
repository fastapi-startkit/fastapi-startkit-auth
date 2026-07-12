import pytest

from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.clients.repository import InMemoryClientRepository


@pytest.fixture
def clients():
    return InMemoryClientRepository(hasher=BcryptHasher(rounds=4))


def test_register_confidential_client_returns_plaintext_secret_once(clients):
    client, secret = clients.register(name="web", redirect_uris=["https://app/cb"], confidential=True)
    assert client.name == "web"
    assert client.confidential is True
    assert secret  # plaintext returned to caller
    assert client.secret != secret  # stored hashed


def test_public_client_has_no_secret(clients):
    client, secret = clients.register(name="spa", redirect_uris=["https://spa/cb"], confidential=False)
    assert secret is None
    assert client.secret is None


def test_authenticate_confidential_client(clients):
    client, secret = clients.register(name="web", redirect_uris=[], confidential=True)
    assert clients.authenticate(client.id, secret) is not None
    assert clients.authenticate(client.id, "wrong-secret") is None


def test_authenticate_public_client_without_secret(clients):
    client, _ = clients.register(name="spa", redirect_uris=[], confidential=False)
    assert clients.authenticate(client.id, None) is not None


def test_find_and_delete(clients):
    client, _ = clients.register(name="web", redirect_uris=[], confidential=True)
    assert clients.find(client.id) is client
    assert clients.delete(client.id) is True
    assert clients.find(client.id) is None


def test_redirect_uri_validation(clients):
    client, _ = clients.register(name="web", redirect_uris=["https://app/cb"], confidential=False)
    assert client.allows_redirect("https://app/cb") is True
    assert client.allows_redirect("https://evil/cb") is False


def test_grant_restriction(clients):
    client, _ = clients.register(name="web", redirect_uris=[], confidential=True, grant_types=["client_credentials"])
    assert client.allows_grant("client_credentials") is True
    assert client.allows_grant("password") is False


def test_grants_default_to_all_when_unrestricted(clients):
    client, _ = clients.register(name="web", redirect_uris=[], confidential=True)
    assert client.allows_grant("authorization_code") is True
