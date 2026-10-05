import warnings

import pytest

from fastapi_startkit_auth import AuthConfig, AuthManager
from fastapi_startkit_auth.config import (
    ApiTokenConfig,
    OAuthClientsConfig,
    OAuthTokensConfig,
    SessionConfig,
)

from conftest import oauth2_config

STORE_CONFIGS = [SessionConfig, ApiTokenConfig, OAuthClientsConfig, OAuthTokensConfig]


class Config(AuthConfig):
    guards = {}


def test_oauth_clients_default_to_the_database_store():
    assert OAuthClientsConfig().store == "database"


def test_the_database_default_resolves_to_the_orm_client_store():
    pytest.importorskip("fastapi_startkit.masoniteorm.models")
    from fastapi_startkit_auth.clients.orm import OrmClientRepository

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        manager = AuthManager(Config).use_oauth2(oauth2_config(clients=OAuthClientsConfig()))
    assert isinstance(manager.client_repository, OrmClientRepository)


@pytest.mark.parametrize("config_type", STORE_CONFIGS)
def test_orm_is_a_deprecated_alias_of_database(config_type):
    with pytest.warns(DeprecationWarning, match=f'{config_type.__name__}\\(store="orm"\\) is deprecated'):
        config = config_type(store="orm")
    assert config.store == "database"


def test_the_deprecated_alias_still_resolves_to_the_orm_client_store():
    pytest.importorskip("fastapi_startkit.masoniteorm.models")
    from fastapi_startkit_auth.clients.orm import OrmClientRepository

    with pytest.warns(DeprecationWarning):
        manager = AuthManager(Config).use_oauth2(oauth2_config(clients={"store": "orm"}))
    assert isinstance(manager.client_repository, OrmClientRepository)
