"""AuthProvider + AuthServiceProvider exercised through a real framework Application.

Per https://fastapi-startkit.github.io/docs/testing/fastapi the framework's
``HttpTestCase`` spins up the actual application and sends real HTTP requests
through it. ``make_testing_application()`` builds a singleton startkit Application
composing the auth providers exactly like a consuming app's
``bootstrap/application.py``, so the register/boot lifecycle, the publish
contract and the mounted routes are all verified against the real framework.
"""
import runpy
from pathlib import Path

from fastapi_startkit import Application
from fastapi_startkit.fastapi import FastAPIConfig, FastAPIProvider
from fastapi_startkit.fastapi.testing import HttpTestCase
from fastapi_startkit.support import Provider

from fastapi_startkit_auth import AuthConfig, AuthProvider, AuthServiceProvider
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

CORS_STUB = (
    Path(__file__).resolve().parents[1]
    / "src" / "fastapi_startkit_auth" / "publishable" / "cors.py"
)


def seeded_users() -> InMemoryUserProvider:
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    provider.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})
    return provider


class Config(AuthConfig):
    key = "startkit-provider-test-key-32-bytes-min!!"
    bcrypt_rounds = 4
    providers = {"users": {"driver": "instance", "instance": seeded_users()}}


_TESTING_APP = None


def make_testing_application() -> Application:
    """Singleton test Application, composed like a consuming app's bootstrap."""
    global _TESTING_APP
    if _TESTING_APP is None:
        _TESTING_APP = Application(
            base_path=Path(__file__).resolve().parent,
            providers=[
                (FastAPIProvider, FastAPIConfig),
                (AuthProvider, Config),
                AuthServiceProvider,
            ],
        )
    return _TESTING_APP


class TestAuthProviderThroughTheFramework(HttpTestCase):
    def get_application(self):
        return make_testing_application()

    async def test_password_grant_issues_a_token_through_the_real_app(self):
        response = await self.post(
            "/oauth/token",
            data={"grant_type": "password", "username": "ada@example.com", "password": "secret"},
        )
        response.assert_ok()
        assert response.json()["access_token"]

    async def test_auth_error_handler_renders_oauth_errors(self):
        response = await self.post(
            "/oauth/token",
            data={"grant_type": "password", "username": "ada@example.com", "password": "nope"},
        )
        response.assert_status(400)
        assert response.json()["error"] == "invalid_grant"


def test_auth_provider_extends_the_framework_provider():
    assert issubclass(AuthProvider, Provider)
    assert issubclass(AuthServiceProvider, Provider)


def test_register_exposes_the_manager_on_the_wired_fastapi_app():
    app = make_testing_application()
    provider = next(p for p in app.providers if isinstance(p, AuthProvider))
    assert provider.provider_key == "auth"
    assert app.fastapi.state.auth_manager is provider.manager


def test_service_provider_publishes_cors_stub_under_the_auth_key():
    app = make_testing_application()
    assert app.published_resources["auth"] == {str(CORS_STUB): "config/cors.py"}
    assert Path(next(iter(app.published_resources["auth"]))).is_file()


def test_service_provider_merges_cors_defaults_into_the_config_repository():
    config = make_testing_application().make("config")
    assert config.get("cors.allow_credentials") is True
    assert "X-XSRF-TOKEN" in config.get("cors.allow_headers")


def test_providers_are_exported_from_the_package_root():
    import fastapi_startkit_auth
    from fastapi_startkit_auth.provider import AuthProvider as provider_cls
    from fastapi_startkit_auth.startkit import AuthServiceProvider as service_cls

    assert fastapi_startkit_auth.AuthProvider is provider_cls
    assert fastapi_startkit_auth.AuthServiceProvider is service_cls


def test_cors_stub_enables_credentials_and_refuses_wildcard_origins():
    config = runpy.run_path(str(CORS_STUB))
    assert config["ALLOW_CREDENTIALS"] is True
    assert config["ALLOW_ORIGINS"] and "*" not in config["ALLOW_ORIGINS"]
    assert "X-XSRF-TOKEN" in config["ALLOW_HEADERS"]
