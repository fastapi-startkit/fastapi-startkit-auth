import pytest

from fastapi_startkit_auth import (
    ApiTokenConfig,
    AuthConfig,
    AuthManager,
    FeatureNotRegistered,
    OAuth2Config,
    SessionConfig,
)
from fastapi_startkit_auth.config import OAuth2Guard, OAuthClientsConfig, SessionGuard, resolve_config
from fastapi_startkit_auth.guards.guard import PassportGuard
from fastapi_startkit_auth.guards.session import SessionGuard as RuntimeSessionGuard
from fastapi_startkit_auth.security.jwt import JWTEncoder

from conftest import oauth2_config


class Config(AuthConfig):
    default = {"guard": "web", "passwords": "users"}
    providers = {"users": {"driver": "memory"}}
    guards = {
        "web": SessionGuard(provider="users"),
        "api": OAuth2Guard(provider="users"),
    }


def test_class_guards_build_once_their_features_are_enabled():
    manager = AuthManager(Config).use_sessions(SessionConfig(cookie="my_session")).use_oauth2(oauth2_config())

    assert isinstance(manager.guard(), RuntimeSessionGuard)
    assert isinstance(manager.guard("api"), PassportGuard)
    assert manager.session_config.cookie == "my_session"
    assert manager._resolve_broker_provider(None) is manager.guard().provider


def test_guard_without_its_feature_names_the_missing_provider():
    manager = AuthManager(Config).use_oauth2(oauth2_config())

    with pytest.raises(FeatureNotRegistered, match="AuthSessionProvider"):
        manager.guard("web")


def test_dictionary_guards_remain_supported():
    class DictConfig(AuthConfig):
        default = {"guard": "api", "passwords": "users"}
        providers = {"users": {"driver": "memory"}}
        guards = {"api": {"driver": "passport", "provider": "users"}}

    assert isinstance(AuthManager(DictConfig).use_oauth2(oauth2_config()).guard(), PassportGuard)


def test_dictionary_auth_config_is_accepted():
    manager = AuthManager({"providers": {"users": {"driver": "memory"}}, "guards": {}})
    assert manager.provider("users") is not None


def test_feature_configs_are_read_back_from_the_manager():
    manager = (
        AuthManager(Config)
        .use_sessions(SessionConfig(cookie="configured_session", ttl=1800))
        .use_api_tokens(ApiTokenConfig(header="X-API-Token", ttl=600, stateful_origins=["https://app.example"]))
    )

    assert manager.session_config.cookie == "configured_session"
    assert manager.session_config.ttl == 1800
    assert manager.spa_enabled
    assert manager.stateful_origins == ["https://app.example"]
    assert manager.api_token_config.header == "X-API-Token"
    assert manager.api_token_config.ttl == 600


def test_disabled_features_raise_with_the_provider_to_register():
    manager = AuthManager(Config)

    assert not manager.sessions_enabled
    assert not manager.oauth2_enabled
    assert not manager.api_tokens_enabled
    with pytest.raises(FeatureNotRegistered, match="AuthOAuth2Provider"):
        manager.oauth2_config
    with pytest.raises(FeatureNotRegistered, match="AuthApiTokenProvider"):
        manager.api_token_config


def test_spa_mode_requires_sessions():
    class TokenConfig(AuthConfig):
        providers = {"users": {"driver": "memory"}}
        guards = {}

    manager = AuthManager(TokenConfig).use_api_tokens(ApiTokenConfig(stateful_origins=["https://app.example"]))

    with pytest.raises(FeatureNotRegistered, match="AuthSessionProvider"):
        manager.validate()


@pytest.mark.parametrize(
    "value",
    [None, SessionConfig(cookie="c"), {"cookie": "c"}, type("Custom", (SessionConfig,), {})],
)
def test_resolve_config_accepts_instances_dicts_subclasses_and_none(value):
    assert isinstance(resolve_config(value, SessionConfig), SessionConfig)


def test_resolve_config_rejects_other_values():
    with pytest.raises(TypeError):
        resolve_config(42, SessionConfig)


def test_oauth_settings_configure_signing_and_token_lifetimes():
    manager = AuthManager(Config).use_oauth2(
        OAuth2Config(
            key="nested-oauth-signing-key",
            access_token_ttl=120,
            authorization_code_ttl=30,
            clients=OAuthClientsConfig(store="memory"),
        )
    )

    assert manager.oauth2_config.access_token_ttl == 120
    assert manager.token_service.access_ttl == 120
    assert manager.authorization_code_grant()._code_ttl == 30
    token = manager.encoder.encode({"sub": "123"}, ttl_seconds=120)
    assert JWTEncoder("nested-oauth-signing-key").decode(token)["sub"] == "123"


def test_missing_oauth_key_warns_and_generates_an_ephemeral_key():
    with pytest.warns(UserWarning, match="OAuth2Config.key is not set"):
        AuthManager(Config).use_oauth2(OAuth2Config(clients=OAuthClientsConfig(store="memory")))
