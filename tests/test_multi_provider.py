"""Owner re-checks resolve the provider that issued a token or code.

Both providers hold a user with id 1, so a check against the wrong provider
would silently pass or fail on the other provider's row.
"""

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_startkit_auth import AuthConfig
from fastapi_startkit_auth.grants import (
    AsyncAuthorizationCodeGrant,
    AsyncRefreshTokenGrant,
    AuthorizationCodeGrant,
    RefreshTokenGrant,
)
from fastapi_startkit_auth.security.hashing import BcryptHasher

from conftest import PASSWORD_GRANTS, VERIFIER, oauth2_config, register_auth, s256_challenge

HASHER = BcryptHasher(rounds=4)
KEY = "multi-provider-secret-key-32-bytes-minimum!"
CHALLENGE = s256_challenge(VERIFIER)


def model(name):
    class Model:
        rows: dict = {}

        def __init__(self, **attributes):
            self.__dict__.update(attributes)

        @classmethod
        async def find(cls, identifier):
            return cls.rows.get(identifier)

        @classmethod
        def where(cls, field, value):
            class Query:
                async def first(self):
                    return next((row for row in cls.rows.values() if getattr(row, field) == value), None)

            return Query()

    Model.__name__ = name
    return Model


Customer = model("Customer")
Staff = model("Staff")


@pytest.fixture(autouse=True)
def rows():
    Customer.rows = {1: Customer(id=1, email="ada@example.com", password=HASHER.make("secret"), active=True)}
    Staff.rows = {1: Staff(id=1, email="root@example.com", password=HASHER.make("secret"), active=True)}


def make_config(providers):
    class Config(AuthConfig):
        bcrypt_rounds = 4
        default = {"guard": "api"}
        guards = {
            "api": {"driver": "passport", "provider": "users"},
            "staff": {"driver": "passport", "provider": "staff"},
        }

    Config.providers = providers
    return Config


def install(api, providers, connection=None):
    stores = {"store": "database", "connection": connection} if connection is not None else {"store": "memory"}
    oauth2 = oauth2_config(key=KEY, grant_types=list(PASSWORD_GRANTS), tokens=stores)
    return register_auth(api, make_config(providers), oauth2=oauth2)


ASYNC_PROVIDERS = {
    "users": {"driver": "async_model", "model": Customer, "is_active": "active"},
    "staff": {"driver": "async_model", "model": Staff, "is_active": "active"},
}


async def build(connection):
    api = FastAPI()
    manager = install(api, ASYNC_PROVIDERS, connection)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=api), base_url="https://testserver")
    return client, manager


def register(manager, provider, **kwargs):
    return manager.client_repository.register(name=provider or "default", provider=provider, **kwargs)


async def staff_tokens(client, manager):
    staff_client, secret = register(manager, "staff")
    issued = await client.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "root@example.com", "password": "secret"},
        auth=(staff_client.id, secret),
    )
    assert issued.status_code == 200, issued.text
    return issued.json(), (staff_client.id, secret)


async def test_password_grant_uses_the_clients_provider(orm_database):
    client, manager = await build(orm_database)
    async with client:
        _, auth = await staff_tokens(client, manager)
        wrong_provider = {"grant_type": "password", "username": "ada@example.com", "password": "secret"}
        assert (await client.post("/oauth/token", data=wrong_provider, auth=auth)).json()["error"] == "invalid_grant"


async def test_refresh_rechecks_the_issuing_provider(orm_database):
    client, manager = await build(orm_database)
    assert isinstance(manager.refresh_grant(), AsyncRefreshTokenGrant)
    async with client:
        tokens, auth = await staff_tokens(client, manager)
        Customer.rows[1].active = False
        refresh = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}
        refreshed = await client.post("/oauth/token", data=refresh, auth=auth)
        assert refreshed.status_code == 200, refreshed.text

        Customer.rows[1].active = True
        Staff.rows[1].active = False
        refresh["refresh_token"] = refreshed.json()["refresh_token"]
        assert (await client.post("/oauth/token", data=refresh, auth=auth)).json()["error"] == "invalid_grant"


async def test_introspect_rechecks_the_issuing_provider(orm_database):
    client, manager = await build(orm_database)
    async with client:
        tokens, auth = await staff_tokens(client, manager)
        introspect = {"token": tokens["access_token"]}
        Customer.rows[1].active = False
        assert (await client.post("/oauth/introspect", data=introspect, auth=auth)).json()["active"] is True
        Staff.rows[1].active = False
        assert (await client.post("/oauth/introspect", data=introspect, auth=auth)).json() == {"active": False}


async def test_authorization_code_rechecks_the_clients_provider(orm_database):
    _, manager = await build(orm_database)
    grant = manager.authorization_code_grant()
    assert isinstance(grant, AsyncAuthorizationCodeGrant)
    spa, _ = register(manager, "staff", redirect_uris=["https://app/cb"], confidential=False)
    exchange = {"client": spa, "redirect_uri": "https://app/cb", "code_verifier": VERIFIER}
    issue = {"client": spa, "user_id": 1, "scopes": [], "redirect_uri": "https://app/cb", "code_challenge": CHALLENGE}

    Customer.rows[1].active = False
    code = await grant.issue_code(**issue, code_challenge_method="S256")
    assert (await grant.handle(code=code, **exchange)).access_token

    Customer.rows[1].active = True
    Staff.rows[1].active = False
    code = await grant.issue_code(**issue, code_challenge_method="S256")
    with pytest.raises(Exception, match="no longer exists or is not active"):
        await grant.handle(code=code, **exchange)


async def test_authorize_rejects_a_client_of_another_provider():
    client, manager = await build(None)
    async with client:
        spa, _ = register(manager, "staff", redirect_uris=["https://app/cb"], confidential=False)
        login = {"grant_type": "password", "username": "ada@example.com", "password": "secret"}
        user_token = (await client.post("/oauth/token", data=login)).json()["access_token"]
        authorized = await client.post(
            "/oauth/authorize",
            json={
                "client_id": spa.id,
                "redirect_uri": "https://app/cb",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "approved": True,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert authorized.json()["error"] == "unauthorized_client"


def sync_app():
    def memory(email):
        return {
            "driver": "memory",
            "is_active": "active",
            "users": [{"id": 1, "email": email, "password": HASHER.make("secret"), "active": True}],
        }

    api = FastAPI()
    manager = install(api, {"users": memory("ada@example.com"), "staff": memory("root@example.com")})
    return TestClient(api), manager


def test_sync_refresh_rechecks_the_issuing_provider():
    client, manager = sync_app()
    assert isinstance(manager.refresh_grant(), RefreshTokenGrant)
    staff_client, secret = register(manager, "staff")
    auth = (staff_client.id, secret)
    login = {"grant_type": "password", "username": "root@example.com", "password": "secret"}
    tokens = client.post("/oauth/token", data=login, auth=auth).json()

    manager.provider("users").retrieve_by_id(1)["active"] = False
    refresh = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}
    refreshed = client.post("/oauth/token", data=refresh, auth=auth)
    assert refreshed.status_code == 200, refreshed.text

    manager.provider("users").retrieve_by_id(1)["active"] = True
    manager.provider("staff").retrieve_by_id(1)["active"] = False
    refresh["refresh_token"] = refreshed.json()["refresh_token"]
    assert client.post("/oauth/token", data=refresh, auth=auth).json()["error"] == "invalid_grant"


def test_sync_authorization_code_rechecks_the_clients_provider():
    _, manager = sync_app()
    grant = manager.authorization_code_grant()
    assert isinstance(grant, AuthorizationCodeGrant)
    spa, _ = register(manager, "staff", redirect_uris=["https://app/cb"], confidential=False)
    exchange = {"client": spa, "redirect_uri": "https://app/cb", "code_verifier": VERIFIER}
    issue = {"client": spa, "user_id": 1, "scopes": [], "redirect_uri": "https://app/cb", "code_challenge": CHALLENGE}

    manager.provider("users").retrieve_by_id(1)["active"] = False
    code = grant.issue_code(**issue, code_challenge_method="S256")
    assert grant.handle(code=code, **exchange).access_token

    manager.provider("users").retrieve_by_id(1)["active"] = True
    manager.provider("staff").retrieve_by_id(1)["active"] = False
    code = grant.issue_code(**issue, code_challenge_method="S256")
    with pytest.raises(Exception, match="no longer exists or is not active"):
        grant.handle(code=code, **exchange)


def test_client_without_provider_falls_back_to_the_default_guard():
    _, manager = sync_app()
    plain, _ = register(manager, None)
    assert manager.owner_provider(plain.id) is manager.guard().provider
    assert manager.owner_provider(None) is manager.guard().provider
    assert manager.owner_provider("unknown") is manager.guard().provider
