import asyncio
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_startkit_auth import AuthConfig, AuthManager, AuthOAuth2Provider, AuthProvider
from fastapi_startkit_auth.config import OAuth2Config, OAuthClientsConfig

from conftest import MIGRATIONS_DIR, ORM_CONNECTION

pytest.importorskip("fastapi_startkit.masoniteorm.models")
from cleo.testers.command_tester import CommandTester  # noqa: E402

from fastapi_startkit_auth.commands.oauth2_client import OAuth2ClientCommand  # noqa: E402


@pytest.fixture
def client_database(tmp_path):
    from fastapi_startkit.application import Application as StartkitApplication
    from fastapi_startkit.masoniteorm import Migrator, Model
    from fastapi_startkit.masoniteorm.connections.factory import ConnectionFactory
    from fastapi_startkit.masoniteorm.connections.manager import DatabaseManager

    StartkitApplication(env="testing")
    connection = {"driver": "sqlite", "database": str(tmp_path / "auth.db")}
    manager = DatabaseManager(ConnectionFactory(), {"default": ORM_CONNECTION, "connections": {ORM_CONNECTION: connection}})
    Model.db_manager = manager
    Migrator.db_manager = manager

    async def migrate():
        migrator = Migrator(migration_directory=str(MIGRATIONS_DIR), connection=ORM_CONNECTION)
        await migrator.create_table_if_not_exists()
        await migrator.fresh(ignore_fk=True)

    asyncio.run(migrate())
    yield manager
    asyncio.run(manager.clear())


OAUTH2 = OAuth2Config(
    key="command-test-key-with-at-least-32-bytes",
    clients=OAuthClientsConfig(store="database", connection=ORM_CONNECTION),
)


class Config(AuthConfig):
    bcrypt_rounds = 4
    guards = {}


def create_command():
    manager = AuthManager(Config).use_oauth2(OAUTH2)
    command = OAuth2ClientCommand()
    command.set_container(SimpleNamespace(make=lambda name: manager))
    return CommandTester(command), manager


def test_public_client_persists_without_secret(client_database):
    tester, manager = create_command()
    assert tester.execute('--public --name="Browser app" --redirect-uri=https://app.example/callback') == 0
    client = asyncio.run(manager.client_repository.all())[0]
    assert not client.confidential
    assert client.secret is None
    assert client.grant_types == ["authorization_code", "refresh_token"]
    restored = AuthManager(Config).use_oauth2(OAUTH2)
    assert asyncio.run(restored.client_repository.find(client.id)) == client
    assert "Client secret:" not in tester.io.fetch_output()


def test_first_party_secret_is_hashed_and_existing_clients_preserved(client_database):
    tester, manager = create_command()
    assert tester.execute("--name=Server --redirect-uri=https://server.example/callback") == 0
    secret = tester.io.fetch_output().split("Client secret: ")[1].splitlines()[0]
    client = asyncio.run(manager.client_repository.all())[0]
    assert client.confidential
    assert client.secret != secret
    assert asyncio.run(manager.client_repository.authenticate(client.id, secret)) == client
    tester, second = create_command()
    assert tester.execute("--public --name=Browser --redirect-uri=https://browser.example/callback") == 0
    assert len(asyncio.run(second.client_repository.all())) == 2
    assert asyncio.run(second.client_repository.authenticate(client.id, secret)) == client
    assert asyncio.run(second.client_repository.authenticate(client.id, "wrong")) is None


def test_invalid_redirect_creates_no_client(client_database):
    tester, manager = create_command()
    assert tester.execute("--public --name=Browser --redirect-uri=https://browser.example/callback#fragment") == 1
    assert asyncio.run(manager.client_repository.all()) == []


def test_oauth_routes_use_database_clients_and_observe_deletion(client_database):
    _, manager = create_command()
    client, secret = asyncio.run(
        manager.client_repository.register(name="Service", redirect_uris=[], grant_types=["client_credentials"])
    )
    app = FastAPI()
    AuthProvider(Config).register(app)
    AuthOAuth2Provider(OAUTH2).register(app)
    http = TestClient(app)
    response = http.post("/oauth/token", data={"grant_type": "client_credentials"}, auth=(client.id, secret))
    assert response.status_code == 200
    assert response.json()["access_token"]
    assert asyncio.run(manager.client_repository.delete(client.id))
    denied = http.post("/oauth/token", data={"grant_type": "client_credentials"}, auth=(client.id, secret))
    assert denied.status_code == 401
    assert denied.headers["www-authenticate"] == "Basic"


def test_scopes_option_restricts_the_client(client_database):
    tester, manager = create_command()
    command = "--public --name=Agent --redirect-uri=https://agent.example/cb --scopes='read write' --scopes=read"
    assert tester.execute(command) == 0
    client = asyncio.run(manager.client_repository.all())[0]
    assert client.scopes == ["read", "write"]
    assert "Allowed scopes: read write" in tester.io.fetch_output()


def test_star_scope_is_refused(client_database):
    tester, manager = create_command()
    assert tester.execute("--public --name=Agent --redirect-uri=https://agent.example/cb --scopes='read *'") == 1
    assert "* grants every ability; list explicit scopes." in tester.io.fetch_error()
    assert asyncio.run(manager.client_repository.all()) == []


def test_omitting_scopes_leaves_the_client_unrestricted(client_database):
    tester, manager = create_command()
    assert tester.execute("--public --name=Agent --redirect-uri=https://agent.example/cb") == 0
    assert asyncio.run(manager.client_repository.all())[0].scopes == []
    assert "Allowed scopes: any" in tester.io.fetch_output()


def test_scopes_outside_the_catalog_create_no_client(client_database):
    manager = AuthManager(Config).use_oauth2(
        OAuth2Config(
            key="command-test-key-with-at-least-32-bytes",
            scopes={"read": "Read"},
            clients=OAuthClientsConfig(store="database", connection=ORM_CONNECTION),
        )
    )
    command = OAuth2ClientCommand()
    command.set_container(SimpleNamespace(make=lambda name: manager))
    tester = CommandTester(command)
    assert tester.execute("--public --name=Agent --redirect-uri=https://agent.example/cb --scopes=admin") == 1
    assert asyncio.run(manager.client_repository.all()) == []
