"""Feature providers under a Startkit application: publishes, commands, boot.

The Startkit side is exercised with the framework's real ``Provider`` base
against a minimal application double (container, published resources, command
list, FastAPI app); the standalone test proves the package never imports the
framework when it is absent.
"""
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_startkit_auth import (
    AuthApiTokenProvider,
    AuthOAuth2Provider,
    AuthProvider,
    AuthSessionProvider,
)
from fastapi_startkit_auth.provider import OAUTH2_MIGRATIONS

pytest.importorskip("fastapi_startkit.support")

PUBLISHABLE = Path(__file__).resolve().parents[1] / "src" / "fastapi_startkit_auth" / "publishable"
CORS_STUB = PUBLISHABLE / "cors.py"
MIGRATIONS = PUBLISHABLE / "migrations"
SECRET = "framework-test-secret-with-32-bytes-min!"
MEMORY_CLIENTS = {"store": "memory"}


class FakeConfig:
    def __init__(self):
        self.merged = []

    def merge_with(self, key, source):
        self.merged.append((source, key))


class FakeApplication:
    def __init__(self):
        self.published_resources = {}
        self.bindings = {"config": FakeConfig()}
        self.fastapi = FastAPI()
        self.commands = []

    def bind(self, name, value):
        self.bindings[name] = value

    def make(self, name):
        return self.bindings[name]

    def has(self, name):
        return name in self.bindings

    def add_commands(self, commands):
        self.commands.extend(commands)


def oauth2_settings():
    return {"key": SECRET, "clients": MEMORY_CLIENTS}


def register_all(app, **configs):
    providers = [
        AuthProvider(app, config=configs.get("auth")),
        AuthSessionProvider(app, config=configs.get("session")),
        AuthOAuth2Provider(app, config=configs.get("oauth2", oauth2_settings())),
        AuthApiTokenProvider(app, config=configs.get("api_tokens")),
    ]
    for provider in providers:
        provider.register()
    return providers


def published_migrations(app, key):
    return sorted(Path(source).name for source in app.published_resources[key] if Path(source).parent == MIGRATIONS)


def test_each_provider_publishes_only_its_own_resources():
    app = FakeApplication()
    register_all(app)

    assert "auth" not in app.published_resources
    assert published_migrations(app, "auth-session") == ["2026_09_30_000001_create_sessions_table.py"]
    assert published_migrations(app, "auth-api-token") == ["2026_09_30_000002_create_personal_api_tokens_table.py"]
    assert published_migrations(app, "auth-oauth2") == [
        "2026_09_30_000003_create_oauth_access_tokens_table.py",
        "2026_09_30_000004_create_oauth_refresh_tokens_table.py",
        "2026_09_30_000005_create_oauth_auth_codes_table.py",
        "2026_10_02_000001_add_resource_to_oauth_tables.py",
        "2026_10_04_000001_create_oauth_clients_table.py",
        "2026_10_04_000002_add_family_id_to_oauth_refresh_tokens_table.py",
    ]
    assert app.published_resources["auth-api-token"][str(CORS_STUB)] == "config/cors.py"
    for resources in app.published_resources.values():
        for source, target in resources.items():
            assert Path(source).is_file()
            assert target in ("config/cors.py", f"databases/migrations/{Path(source).name}")


def test_every_shipped_migration_is_published_by_some_provider():
    app = FakeApplication()
    register_all(app)
    published = {name for key in app.published_resources for name in published_migrations(app, key)}
    assert published == {path.name for path in MIGRATIONS.glob("*.py")}
    assert len(OAUTH2_MIGRATIONS) == 6


def test_only_the_oauth2_provider_registers_the_client_command():
    from fastapi_startkit_auth.commands.oauth2_client import OAuth2ClientCommand

    app = FakeApplication()
    AuthProvider(app).register()
    AuthSessionProvider(app).register()
    AuthApiTokenProvider(app).register()
    assert app.commands == []

    AuthOAuth2Provider(app, config=oauth2_settings()).register()
    assert app.commands == [OAuth2ClientCommand]


def test_api_token_provider_merges_cors_defaults_under_a_non_reserved_key():
    app = FakeApplication()
    AuthProvider(app).register()
    AuthApiTokenProvider(app).register()
    assert app.make("config").merged == [(str(CORS_STUB), "cors")]


def test_feature_provider_listed_before_the_core_provider_fails_clearly():
    with pytest.raises(RuntimeError, match="List AuthProvider before AuthSessionProvider"):
        AuthSessionProvider(FakeApplication()).register()


def test_feature_providers_enable_their_feature_on_the_shared_manager():
    app = FakeApplication()
    core, *_ = register_all(app)

    assert app.make("auth_manager") is core.manager
    assert core.manager.sessions_enabled
    assert core.manager.oauth2_enabled
    assert core.manager.api_tokens_enabled


def test_boot_mounts_the_routes_on_the_framework_app():
    app = FakeApplication()
    providers = register_all(app, auth={"guards": {}})
    for provider in providers:
        provider.boot()

    assert app.fastapi.state.auth_manager is providers[0].manager
    response = TestClient(app.fastapi).post("/oauth/token", data={"grant_type": "unsupported"})
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_cors_stub_enables_credentials_and_refuses_wildcard_origins():
    config = runpy.run_path(str(CORS_STUB))
    assert config["ALLOW_CREDENTIALS"] is True
    assert config["ALLOW_ORIGINS"] and "*" not in config["ALLOW_ORIGINS"]
    assert "X-XSRF-TOKEN" in config["ALLOW_HEADERS"]


def test_providers_run_without_the_optional_framework():
    code = """
import importlib.abc
import sys

class BlockStartkit(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "fastapi_startkit" or fullname.startswith("fastapi_startkit."):
            raise ModuleNotFoundError(f"No module named {fullname!r}", name="fastapi_startkit")

sys.meta_path.insert(0, BlockStartkit())

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_startkit_auth import AuthConfig, AuthOAuth2Provider, AuthProvider, OAuth2Config, OAuthClientsConfig

class Config(AuthConfig):
    guards = {}

app = FastAPI()
AuthProvider(Config).register(app)
AuthOAuth2Provider(OAuth2Config(key="standalone-test-key-with-32-bytes-min!", clients=OAuthClientsConfig(store="memory"))).register(app)
assert TestClient(app).post("/oauth/token", data={"grant_type": "unsupported"}).status_code == 400
assert "fastapi_startkit" not in sys.modules
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
