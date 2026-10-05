import pytest

from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.clients.repository import InMemoryClientRepository


@pytest.fixture
def clients():
    return InMemoryClientRepository(hasher=BcryptHasher(rounds=4))


async def test_register_confidential_client_returns_plaintext_secret_once(clients):
    client, secret = await clients.register(name="web", redirect_uris=["https://app/cb"], confidential=True)
    assert client.name == "web"
    assert client.confidential is True
    assert secret  # plaintext returned to caller
    assert client.secret != secret  # stored hashed


async def test_public_client_has_no_secret(clients):
    client, secret = await clients.register(name="spa", redirect_uris=["https://spa/cb"], confidential=False)
    assert secret is None
    assert client.secret is None


async def test_authenticate_confidential_client(clients):
    client, secret = await clients.register(name="web", redirect_uris=[], confidential=True)
    assert await clients.authenticate(client.id, secret) is not None
    assert await clients.authenticate(client.id, "wrong-secret") is None


async def test_authenticate_public_client_without_secret(clients):
    client, _ = await clients.register(name="spa", redirect_uris=[], confidential=False)
    assert await clients.authenticate(client.id, None) is not None


async def test_find_and_delete(clients):
    client, _ = await clients.register(name="web", redirect_uris=[], confidential=True)
    assert await clients.find(client.id) is client
    assert await clients.delete(client.id) is True
    assert await clients.find(client.id) is None


async def test_redirect_uri_validation(clients):
    client, _ = await clients.register(name="web", redirect_uris=["https://app/cb"], confidential=False)
    assert client.allows_redirect("https://app/cb") is True
    assert client.allows_redirect("https://evil/cb") is False


async def test_grant_restriction(clients):
    client, _ = await clients.register(name="web", redirect_uris=[], confidential=True, grant_types=["client_credentials"])
    assert client.allows_grant("client_credentials") is True
    assert client.allows_grant("password") is False


async def test_grants_default_to_all_when_unrestricted(clients):
    client, _ = await clients.register(name="web", redirect_uris=[], confidential=True)
    assert client.allows_grant("authorization_code") is True
