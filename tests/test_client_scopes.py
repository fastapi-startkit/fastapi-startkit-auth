import asyncio
import shutil
import time
import uuid

import pytest
from fastapi import FastAPI

from fastapi_startkit_auth import AsyncAuth
from fastapi_startkit_auth.clients.models import Client
from fastapi_startkit_auth.clients.repository import InMemoryClientRepository
from fastapi_startkit_auth.exceptions import InvalidScope
from fastapi_startkit_auth.grants.client_credentials import AsyncClientCredentialsGrant
from fastapi_startkit_auth.grants.password import AsyncPasswordGrant
from fastapi_startkit_auth.policy import GrantPolicy
from fastapi_startkit_auth.security.hashing import BcryptHasher

from conftest import MIGRATIONS_DIR, PASSWORD_GRANTS, VERIFIER, make_auth_client, oauth2_config, register_auth
from conftest import BrowserTestClient as TestClient
from conftest import s256_challenge
from test_session_auth import session_config

REDIRECT = "https://client.example/callback"
CATALOG = {"read": "Read", "write": "Write", "*": "Everything"}


def _oauth2(**overrides):
    overrides.setdefault("scopes", CATALOG)
    overrides.setdefault("grant_types", list(PASSWORD_GRANTS))
    return oauth2_config(**overrides)


def _token(client, registered, secret, **data):
    return client.post("/oauth/token", data=data, auth=(registered.id, secret))


# --- model and policy ---------------------------------------------------------


def test_empty_allow_list_permits_any_scope():
    client = Client(id="c", name="c")
    assert client.allows_scopes(["read", "write", "*"])
    GrantPolicy().check_client_scopes(client, ["anything"])


def test_allow_list_limits_requested_scopes():
    client = Client(id="c", name="c", scopes=["read", "write"])
    assert client.allows_scopes([])
    assert client.allows_scopes(["read"])
    assert client.allows_scopes(["read", "write"])
    assert not client.allows_scopes(["read", "admin"])
    with pytest.raises(InvalidScope):
        GrantPolicy().check_client_scopes(client, ["admin"])


def test_star_is_not_a_wildcard_in_the_allow_list():
    restricted = Client(id="c", name="c", scopes=["read"])
    with pytest.raises(InvalidScope):
        GrantPolicy().check_client_scopes(restricted, ["*"])
    assert not Client(id="s", name="s", scopes=["*"]).allows_scopes(["read"])


# --- repositories -------------------------------------------------------------


def test_in_memory_repository_stores_scopes_and_revokes():
    repo = InMemoryClientRepository(hasher=BcryptHasher(rounds=4))
    client, secret = repo.register(name="svc", scopes=["read"])
    assert repo.find(client.id).scopes == ["read"]
    assert repo.authenticate(client.id, secret) is client

    assert repo.revoke(client.id) is True
    assert repo.authenticate(client.id, secret) is None
    assert repo.revoke("missing") is False


async def test_orm_repository_round_trips_scopes(orm_database):
    from fastapi_startkit_auth.clients.orm import OrmClientRepository

    repo = OrmClientRepository(orm_database, hasher=BcryptHasher(rounds=4))
    restricted, secret = await repo.register(name="svc", scopes=["read", "write"])
    open_client, _ = await repo.register(name="spa", confidential=False)

    assert (await repo.find(restricted.id)).scopes == ["read", "write"]
    assert (await repo.authenticate(restricted.id, secret)).scopes == ["read", "write"]
    assert (await repo.find(open_client.id)).scopes == []


async def test_legacy_client_row_without_scopes_is_unrestricted(orm_database, tmp_path, monkeypatch):
    from fastapi_startkit.masoniteorm import Migrator

    from fastapi_startkit_auth import orm
    from fastapi_startkit_auth.clients.orm import OrmClientRepository

    scopes_migration = "2026_10_05_000001_add_scopes_to_oauth_clients_table.py"
    # The Migrator imports migrations by module path, so the copy must be importable.
    directory = tmp_path / f"pre_scopes_migrations_{uuid.uuid4().hex}"
    directory.mkdir()
    monkeypatch.syspath_prepend(str(tmp_path))
    for path in MIGRATIONS_DIR.glob("*.py"):
        if path.name != scopes_migration:
            shutil.copy(path, directory / path.name)
    await Migrator(migration_directory=str(MIGRATIONS_DIR), connection=orm_database).reset()
    migrator = Migrator(migration_directory=str(directory), connection=orm_database)
    await migrator.migrate()

    await orm.query(orm.AuthOAuthClient, orm_database).insert(
        {
            "id": "legacy",
            "name": "legacy",
            "secret": None,
            "redirect_uris": "[]",
            "confidential": False,
            "grant_types": "[]",
            "revoked": False,
            "provider": None,
            "created_at": time.time(),
        }
    )
    shutil.copy(MIGRATIONS_DIR / scopes_migration, directory / scopes_migration)
    await migrator.migrate()

    legacy = await OrmClientRepository(orm_database).find("legacy")
    assert legacy.scopes == []
    assert legacy.allows_scopes(["read", "write"])


# --- client_credentials -------------------------------------------------------


def test_client_credentials_rejects_scopes_outside_the_allow_list():
    client, _ = make_auth_client(oauth2=_oauth2())
    manager = client.app.state.auth_manager
    registered, secret = manager.client_repository.register(name="svc", scopes=["read"])

    allowed = _token(client, registered, secret, grant_type="client_credentials", scope="read")
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["scope"] == "read"

    for scope in ("write", "read write", "*"):
        refused = _token(client, registered, secret, grant_type="client_credentials", scope=scope)
        assert refused.status_code == 400
        assert refused.json()["error"] == "invalid_scope"


def test_default_scopes_outside_the_allow_list_fail_closed():
    client, _ = make_auth_client(oauth2=_oauth2(default_scopes=["write"]))
    manager = client.app.state.auth_manager
    registered, secret = manager.client_repository.register(name="svc", scopes=["read"])

    response = _token(client, registered, secret, grant_type="client_credentials")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def test_unrestricted_client_may_request_any_catalog_scope():
    client, _ = make_auth_client(oauth2=_oauth2())
    manager = client.app.state.auth_manager
    registered, secret = manager.client_repository.register(name="svc")

    response = _token(client, registered, secret, grant_type="client_credentials", scope="read write *")
    assert response.status_code == 200, response.text


async def test_async_client_credentials_grant_enforces_the_allow_list():
    class Tokens:
        async def issue(self, **kwargs):
            raise AssertionError("no token may be issued")

    grant = AsyncClientCredentialsGrant(Tokens())
    with pytest.raises(InvalidScope):
        await grant.handle(client=Client(id="svc", name="svc", scopes=["read"]), scopes=["write"])


# --- password -----------------------------------------------------------------


def _password(client, **data):
    return client.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "ada@example.com", "password": "secret", **data},
    )


def test_password_route_enforces_client_scopes():
    client, _ = make_auth_client(oauth2=_oauth2())
    manager = client.app.state.auth_manager
    registered, secret = manager.client_repository.register(name="cli", grant_types=["password"], scopes=["read"])

    refused = _password(client, scope="write", client_id=registered.id, client_secret=secret)
    assert refused.status_code == 400
    assert refused.json()["error"] == "invalid_scope"

    allowed = _password(client, scope="read", client_id=registered.id, client_secret=secret)
    assert allowed.status_code == 200, allowed.text


def test_password_route_without_a_client_is_unrestricted():
    client, _ = make_auth_client(oauth2=_oauth2())
    assert _password(client, scope="write").status_code == 200


def test_programmatic_password_grant_enforces_client_scopes():
    client, _ = make_auth_client(oauth2=_oauth2())
    manager = client.app.state.auth_manager
    restricted = Client(id="cli", name="cli", scopes=["read"])
    grant = manager.password_grant(client=restricted)

    with pytest.raises(InvalidScope):
        grant.handle(username="ada@example.com", password="secret", scopes=["write"], client_id=restricted.id)
    issued = grant.handle(username="ada@example.com", password="secret", scopes=["read"], client_id=restricted.id)
    assert issued.scopes == ["read"]


async def test_async_password_grant_checks_client_scopes_before_credentials():
    class Users:
        async def retrieve_by_credentials(self, credentials):
            raise AssertionError("credentials must not be checked")

    grant = AsyncPasswordGrant(None, Users(), client=Client(id="cli", name="cli", scopes=["read"]))
    with pytest.raises(InvalidScope):
        await grant.handle(username="ada", password="secret", scopes=["write"], client_id="cli")


# --- scopes must be a list ----------------------------------------------------


def test_string_scopes_are_rejected():
    with pytest.raises(TypeError):
        Client(id="c", name="c", scopes="read")
    with pytest.raises(TypeError):
        InMemoryClientRepository(hasher=BcryptHasher(rounds=4)).register(name="svc", scopes="read")


async def test_orm_register_rejects_string_scopes(orm_database):
    from fastapi_startkit_auth import orm
    from fastapi_startkit_auth.clients.orm import OrmClientRepository

    with pytest.raises(TypeError):
        await OrmClientRepository(orm_database, hasher=BcryptHasher(rounds=4)).register(name="svc", scopes="read")
    assert await orm.query(orm.AuthOAuthClient, orm_database).get() == []


# --- authorization code -------------------------------------------------------


@pytest.fixture
def server():
    api = FastAPI()
    manager = register_auth(api, session_config(), session={}, oauth2=_oauth2(default_scopes=["write"]))

    @api.post("/login")
    async def login():
        await AsyncAuth.login(1)
        return {"authenticated": True}

    client = TestClient(api, base_url="https://server.example")
    client.post("/login")
    return client, manager


def _authorize(client, client_id, **overrides):
    return client.post(
        "/oauth/authorize",
        json={
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "code_challenge": s256_challenge(VERIFIER),
            "code_challenge_method": "S256",
            "approved": True,
            **overrides,
        },
    )


def _public_client(manager, scopes):
    registered = manager.client_repository.register(
        name="spa",
        confidential=False,
        redirect_uris=[REDIRECT],
        grant_types=["authorization_code", "refresh_token"],
        scopes=scopes,
    )
    return asyncio.run(registered)[0] if asyncio.iscoroutine(registered) else registered[0]


def test_authorization_code_enforces_client_scopes(server):
    client, manager = server
    spa = _public_client(manager, ["read"])

    code = _authorize(client, spa.id, scope="read").json()["code"]
    issued = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": spa.id,
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": REDIRECT,
        },
    )
    assert issued.status_code == 200, issued.text
    assert issued.json()["scope"] == "read"

    for scope in ("read write", "*"):
        refused = _authorize(client, spa.id, scope=scope)
        assert refused.status_code == 400
        assert refused.json()["error"] == "invalid_scope"


def test_authorization_code_default_scopes_outside_the_allow_list_fail_closed(server):
    client, manager = server
    spa = _public_client(manager, ["read"])

    refused = _authorize(client, spa.id)
    assert refused.status_code == 400
    assert refused.json()["error"] == "invalid_scope"


def test_authorization_code_with_an_empty_allow_list_accepts_any_scope(server):
    client, manager = server
    spa = _public_client(manager, [])

    assert _authorize(client, spa.id, scope="read write *").status_code == 200
