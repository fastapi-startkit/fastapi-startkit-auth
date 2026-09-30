"""AuthServiceProvider: framework-native publish integration + standalone gating.

The `fastapi-startkit` framework is an optional extra and is NOT installed in
this test environment. The publish contract is exercised against a stub that
mirrors the framework's ``Provider`` surface (``provider_key``, ``publishes``,
``merge_config_from``); the standalone tests assert the package never
requires the framework.
"""
import importlib
import runpy
import sys
import types
from pathlib import Path

import pytest

FRAMEWORK_INSTALLED = importlib.util.find_spec("fastapi_startkit") is not None

CORS_STUB = (
    Path(__file__).resolve().parents[1]
    / "src" / "fastapi_startkit_auth" / "publishable" / "cors.py"
)


class FakeApplication:
    def __init__(self):
        self.published_resources = {}
        self.merged_configs = []


class StubProvider:
    """Mirror of fastapi_startkit.support.Provider (framework 0.51.0)."""

    provider_key = None

    def __init__(self, application):
        self.app = application

    def register(self):
        pass

    def boot(self):
        pass

    def publishes(self, resources, tag=None):
        self.app.published_resources.setdefault(self.provider_key, {}).update(resources)

    def merge_config_from(self, source, provider_key):
        self.app.merged_configs.append((source, provider_key))


@pytest.fixture
def startkit_module(monkeypatch):
    """Import fastapi_startkit_auth.startkit against a stubbed framework."""
    framework = types.ModuleType("fastapi_startkit")
    support = types.ModuleType("fastapi_startkit.support")
    support.Provider = StubProvider
    framework.support = support
    monkeypatch.setitem(sys.modules, "fastapi_startkit", framework)
    monkeypatch.setitem(sys.modules, "fastapi_startkit.support", support)
    sys.modules.pop("fastapi_startkit_auth.startkit", None)
    module = importlib.import_module("fastapi_startkit_auth.startkit")
    yield module
    # Do not leak the stub-bound module into other tests.
    sys.modules.pop("fastapi_startkit_auth.startkit", None)


# --- publish contract ---------------------------------------------------


def test_provider_publishes_cors_stub_under_the_auth_key(startkit_module):
    app = FakeApplication()
    provider = startkit_module.AuthServiceProvider(app)
    provider.register()

    assert provider.provider_key == "auth"  # `provider:publish -p auth`
    migrations = sorted((CORS_STUB.parent / "migrations").glob("*.py"))
    assert len(migrations) == 5
    assert app.published_resources == {
        "auth": {
            str(CORS_STUB): "config/cors.py",
            **{str(stub): f"databases/migrations/{stub.name}" for stub in migrations},
        }
    }
    published_source = next(iter(app.published_resources["auth"]))
    assert Path(published_source).is_file()


def test_provider_merges_cors_defaults_under_a_non_reserved_key(startkit_module):
    app = FakeApplication()
    startkit_module.AuthServiceProvider(app).register()
    assert app.merged_configs == [(str(CORS_STUB), "cors")]


def test_provider_is_exported_from_the_package_root(startkit_module):
    import fastapi_startkit_auth

    assert fastapi_startkit_auth.AuthServiceProvider is startkit_module.AuthServiceProvider


# --- the published stub -------------------------------------------------


def test_cors_stub_enables_credentials_and_refuses_wildcard_origins():
    config = runpy.run_path(str(CORS_STUB))
    assert config["ALLOW_CREDENTIALS"] is True
    assert config["ALLOW_ORIGINS"] and "*" not in config["ALLOW_ORIGINS"]
    assert "X-XSRF-TOKEN" in config["ALLOW_HEADERS"]


# --- standalone (no extra installed) ------------------------------------


@pytest.mark.skipif(FRAMEWORK_INSTALLED, reason="fastapi-startkit is installed")
def test_accessing_the_provider_without_the_extra_raises_a_helpful_error():
    sys.modules.pop("fastapi_startkit_auth.startkit", None)
    import fastapi_startkit_auth

    with pytest.raises(ImportError, match=r"fastapi-startkit-auth\[startkit\]"):
        fastapi_startkit_auth.AuthServiceProvider


@pytest.mark.skipif(FRAMEWORK_INSTALLED, reason="fastapi-startkit is installed")
def test_package_and_spa_mode_run_standalone_without_the_framework():
    # The whole SPA feature set must work on plain FastAPI: importing the
    # package and running the app never touches the optional dependency.
    from test_spa_csrf import make_client

    client = make_client()
    assert client.get("/__auth__/csrf-cookie").status_code == 204
    assert "fastapi_startkit" not in sys.modules
