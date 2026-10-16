import warnings

import pytest

from fastapi_startkit_auth import OAuth2Config, OAuthClientConfig, OAuthClientsConfig, OAuthTokenConfig, OAuthTokensConfig


def test_singular_names_do_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        OAuthTokenConfig(store="memory")
        OAuthClientConfig(store="memory")


@pytest.mark.parametrize(
    ("old", "new"),
    [(OAuthTokensConfig, OAuthTokenConfig), (OAuthClientsConfig, OAuthClientConfig)],
)
def test_plural_alias_warns_and_builds_the_singular_config(old, new):
    with pytest.warns(DeprecationWarning, match=old.__name__):
        config = old(store="memory")
    assert isinstance(config, new)
    assert config.store == "memory"


def test_oauth2_config_accepts_plural_alias_as_field_value():
    with pytest.warns(DeprecationWarning):
        oauth2 = OAuth2Config(tokens=OAuthTokensConfig(store="memory"))
    assert oauth2.tokens.store == "memory"
