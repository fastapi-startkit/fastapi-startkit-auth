import shutil
import time
import uuid
from inspect import isawaitable

import pytest

from fastapi_startkit_auth import AuthConfig, AuthManager
from fastapi_startkit_auth.config import DEFAULT_GRANT_TYPES
from fastapi_startkit_auth.exceptions import InvalidGrant, InvalidToken
from fastapi_startkit_auth.security.jwt import JWTEncoder
from fastapi_startkit_auth.tokens.service import AsyncTokenService, TokenService

from conftest import (
    MIGRATIONS_DIR,
    PASSWORD_GRANTS,
    TEST_OAUTH_KEY,
    make_auth_client,
    oauth2_config,
    register_client,
)

SECRET = "hardening-test-secret-with-32-bytes-min!"
V06_MIGRATIONS = [
    "2026_09_30_000001_create_sessions_table.py",
    "2026_09_30_000002_create_personal_api_tokens_table.py",
    "2026_09_30_000003_create_oauth_access_tokens_table.py",
    "2026_09_30_000004_create_oauth_refresh_tokens_table.py",
    "2026_09_30_000005_create_oauth_auth_codes_table.py",
    "2026_10_02_000001_add_resource_to_oauth_tables.py",
]
NEW_MIGRATIONS = [
    "2026_10_04_000001_create_oauth_clients_table.py",
    "2026_10_04_000002_add_family_id_to_oauth_refresh_tokens_table.py",
]


# --- refresh family reuse detection -----------------------------------------


def test_replaying_a_rotated_refresh_token_revokes_every_descendant():
    service = TokenService(encoder=JWTEncoder(secret=SECRET))
    first = service.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    second = service.refresh(first.refresh_token)
    third = service.refresh(second.refresh_token)

    with pytest.raises(InvalidGrant):
        service.refresh(first.refresh_token)
    with pytest.raises(InvalidGrant):
        service.refresh(third.refresh_token)
    with pytest.raises(InvalidToken):
        service.authenticate(third.access_token)


async def test_orm_replay_revokes_the_family(orm_database):
    from fastapi_startkit_auth.tokens.orm import OrmTokenRepository

    service = AsyncTokenService(encoder=JWTEncoder(secret=SECRET), repository=OrmTokenRepository(orm_database))
    first = await service.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    second = await service.refresh(first.refresh_token)
    third = await service.refresh(second.refresh_token)

    with pytest.raises(InvalidGrant):
        await service.refresh(second.refresh_token)
    with pytest.raises(InvalidGrant):
        await service.refresh(third.refresh_token)
    with pytest.raises(InvalidToken):
        await service.authenticate(third.access_token)


def test_cross_client_replay_of_a_used_refresh_token_revokes_the_family():
    http, _ = make_auth_client()
    owner = register_client(http, name="Owner", grant_types=["client_credentials", "refresh_token"])
    other = register_client(http, name="Other", grant_types=["client_credentials", "refresh_token"])
    owner_auth = (owner["id"], owner["secret"])
    service = http.app.state.auth_manager.token_service
    first = service.issue(user_id=1, client_id=owner["id"], scopes=[], with_refresh=True)
    rotated = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first.refresh_token}, auth=owner_auth)
    assert rotated.status_code == 200, rotated.text
    tokens = rotated.json()

    replay = http.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": first.refresh_token},
        auth=(other["id"], other["secret"]),
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    with pytest.raises(InvalidToken):
        service.authenticate(tokens["access_token"])
    after = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, auth=owner_auth)
    assert after.status_code == 400


def test_cross_client_presentation_of_an_unused_refresh_token_leaves_the_family_intact():
    http, _ = make_auth_client()
    owner = register_client(http, name="Owner", grant_types=["client_credentials", "refresh_token"])
    other = register_client(http, name="Other", grant_types=["client_credentials", "refresh_token"])
    service = http.app.state.auth_manager.token_service
    issued = service.issue(user_id=1, client_id=owner["id"], scopes=[], with_refresh=True)

    response = http.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": issued.refresh_token},
        auth=(other["id"], other["secret"]),
    )
    assert response.status_code == 400
    assert service.authenticate(issued.access_token)["sub"] == "1"


async def test_async_cross_client_replay_revokes_the_family(orm_database):
    from fastapi_startkit_auth.tokens.orm import OrmTokenRepository

    service = AsyncTokenService(encoder=JWTEncoder(secret=SECRET), repository=OrmTokenRepository(orm_database))
    first = await service.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    second = await service.refresh(first.refresh_token, client_id="c1")

    with pytest.raises(InvalidGrant):
        await service.refresh(first.refresh_token, client_id="c2")
    with pytest.raises(InvalidGrant):
        await service.refresh(second.refresh_token, client_id="c1")
    with pytest.raises(InvalidToken):
        await service.authenticate(second.access_token)


# --- unbound (password grant) refresh tokens --------------------------------


def _unbound_refresh_token(http):
    issued = http.app.state.auth_manager.token_service.issue(
        user_id=1, client_id=None, scopes=[], with_refresh=True
    )
    assert not isawaitable(issued)
    return issued.refresh_token


def test_unbound_refresh_token_is_accepted_when_the_password_grant_is_enabled():
    http, _ = make_auth_client()
    response = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": _unbound_refresh_token(http)})
    assert response.status_code == 200, response.text
    assert response.json()["refresh_token"]


def test_unbound_refresh_token_is_refused_without_the_password_grant():
    http, _ = make_auth_client(oauth2=oauth2_config())
    response = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": _unbound_refresh_token(http)})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_unbound_refresh_token_is_refused_when_a_client_presents_it():
    http, _ = make_auth_client()
    client = register_client(http, name="Service", grant_types=["client_credentials", "refresh_token"])
    response = http.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": _unbound_refresh_token(http)},
        auth=(client["id"], client["secret"]),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def _rotated_unbound_pair(http):
    """An unbound refresh token that has already been rotated, plus the live pair it rotated into."""
    used = _unbound_refresh_token(http)
    rotated = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": used})
    assert rotated.status_code == 200, rotated.text
    return used, rotated.json()


def _assert_family_revoked(http, tokens):
    with pytest.raises(InvalidToken):
        http.app.state.auth_manager.token_service.authenticate(tokens["access_token"])
    after = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]})
    assert after.status_code == 400
    assert after.json()["error"] == "invalid_grant"


def test_replaying_a_used_unbound_refresh_token_revokes_its_family():
    http, _ = make_auth_client()
    used, tokens = _rotated_unbound_pair(http)

    replay = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": used})
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    _assert_family_revoked(http, tokens)


def test_a_client_replaying_a_used_unbound_refresh_token_revokes_its_family():
    http, _ = make_auth_client()
    client = register_client(http, name="Service", grant_types=["client_credentials", "refresh_token"])
    used, tokens = _rotated_unbound_pair(http)

    replay = http.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": used},
        auth=(client["id"], client["secret"]),
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    _assert_family_revoked(http, tokens)


def test_an_unknown_client_cannot_trigger_unbound_reuse_revocation():
    http, _ = make_auth_client()
    used, tokens = _rotated_unbound_pair(http)

    replay = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": used}, auth=("unknown", "nope"))
    assert replay.status_code == 401
    assert replay.json()["error"] == "invalid_client"
    assert http.app.state.auth_manager.token_service.authenticate(tokens["access_token"])["sub"] == "1"


def test_a_client_presenting_an_unused_unbound_refresh_token_leaves_the_family_intact():
    http, _ = make_auth_client()
    client = register_client(http, name="Service", grant_types=["client_credentials", "refresh_token"])
    service = http.app.state.auth_manager.token_service
    issued = service.issue(user_id=1, client_id=None, scopes=[], with_refresh=True)

    response = http.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": issued.refresh_token},
        auth=(client["id"], client["secret"]),
    )
    assert response.status_code == 400
    assert service.authenticate(issued.access_token)["sub"] == "1"


async def test_async_replay_of_a_used_unbound_refresh_token_revokes_the_family(orm_database):
    from fastapi_startkit_auth.tokens.orm import OrmTokenRepository

    service = AsyncTokenService(encoder=JWTEncoder(secret=SECRET), repository=OrmTokenRepository(orm_database))
    first = await service.issue(user_id=1, client_id=None, scopes=[], with_refresh=True)
    second = await service.refresh(first.refresh_token)

    with pytest.raises(InvalidGrant):
        await service.refresh(first.refresh_token, client_id="c1")
    with pytest.raises(InvalidGrant):
        await service.refresh(second.refresh_token)
    with pytest.raises(InvalidToken):
        await service.authenticate(second.access_token)


# --- chain revocation through /oauth/revoke ---------------------------------


def test_revoking_an_access_token_revokes_its_refresh_chain():
    http, _ = make_auth_client()
    client = register_client(http, name="Service", grant_types=["client_credentials", "refresh_token"])
    auth = (client["id"], client["secret"])
    service = http.app.state.auth_manager.token_service
    first = service.issue(user_id=1, client_id=client["id"], scopes=[], with_refresh=True)
    rotated = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first.refresh_token}, auth=auth)
    assert rotated.status_code == 200, rotated.text
    tokens = rotated.json()

    assert http.post("/oauth/revoke", data={"token": tokens["access_token"]}, auth=auth).status_code == 200

    with pytest.raises(InvalidToken):
        service.authenticate(tokens["access_token"])
    replay = http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, auth=auth)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


def test_a_client_cannot_revoke_another_clients_chain():
    http, _ = make_auth_client()
    owner = register_client(http, name="Owner", grant_types=["client_credentials", "refresh_token"])
    other = register_client(http, name="Other", grant_types=["client_credentials"])
    service = http.app.state.auth_manager.token_service
    issued = service.issue(user_id=1, client_id=owner["id"], scopes=[], with_refresh=True)

    response = http.post("/oauth/revoke", data={"token": issued.refresh_token}, auth=(other["id"], other["secret"]))
    assert response.status_code == 200
    assert service.authenticate(issued.access_token)["sub"] == "1"


# --- migrations: the 2026_10_04 pair on top of a v0.6 schema ----------------


async def test_new_migrations_apply_on_top_of_a_v06_schema(orm_database, tmp_path, monkeypatch):
    from fastapi_startkit.masoniteorm import Migrator

    from fastapi_startkit_auth import orm
    from fastapi_startkit_auth.clients.orm import OrmClientRepository
    from fastapi_startkit_auth.security.hashing import BcryptHasher
    from fastapi_startkit_auth.tokens.orm import OrmTokenRepository, _digest

    # The Migrator imports migrations by module path, so the copy must be importable.
    directory = tmp_path / f"v06_migrations_{uuid.uuid4().hex}"
    directory.mkdir()
    monkeypatch.syspath_prepend(str(tmp_path))
    for name in V06_MIGRATIONS:
        shutil.copy(MIGRATIONS_DIR / name, directory / name)
    # Start from an empty database, then lay down only the v0.6 schema.
    await Migrator(migration_directory=str(MIGRATIONS_DIR), connection=orm_database).reset()
    migrator = Migrator(migration_directory=str(directory), connection=orm_database)
    await migrator.migrate()
    assert await migrator.get_unran_migrations() == []

    legacy = "legacy-refresh-token"
    jti = uuid.uuid4().hex
    repository = OrmTokenRepository(orm_database)
    await repository.store_access_token(jti=jti, user_id=1, client_id="c1", scopes=[], expires_at=time.time() + 60)
    await orm.query(orm.AuthRefreshToken, orm_database).insert(
        {
            "token_hash": _digest(legacy),
            "access_jti": jti,
            "user_id": "1",
            "client_id": "c1",
            "scopes": "[]",
            "expires_at": time.time() + 60,
            "revoked": False,
            "created_at": time.time(),
            "resource": None,
        }
    )

    for name in NEW_MIGRATIONS:
        shutil.copy(MIGRATIONS_DIR / name, directory / name)
    await migrator.migrate()

    ran = {row["migration_file"] for row in await migrator.get_ran_migrations()}
    assert ran == {name.removesuffix(".py") for name in V06_MIGRATIONS + NEW_MIGRATIONS}
    record = await repository.find_refresh_token(legacy)
    assert record.family_id == _digest(legacy)

    service = AsyncTokenService(encoder=JWTEncoder(secret=SECRET), repository=repository)
    rotated = await service.refresh(legacy)
    with pytest.raises(InvalidGrant):
        await service.refresh(legacy)
    with pytest.raises(InvalidGrant):
        await service.refresh(rotated.refresh_token)

    clients = OrmClientRepository(orm_database, hasher=BcryptHasher(rounds=4))
    client, secret = await clients.register(name="Service", redirect_uris=[], grant_types=["client_credentials"])
    assert await clients.authenticate(client.id, secret) == client


# --- deprecated AuthConfig attributes ---------------------------------------


class LegacyConfig(AuthConfig):
    guards = {}
    access_token_ttl = 120
    issuer = "https://legacy.example"


def test_deprecated_auth_config_attribute_warns_and_applies():
    with pytest.warns(DeprecationWarning, match="AuthConfig.access_token_ttl is deprecated"):
        manager = AuthManager(LegacyConfig).use_oauth2(oauth2_config())
    assert manager.oauth2_config.access_token_ttl == 120
    assert manager.oauth2_config.issuer == "https://legacy.example"


def test_explicit_oauth2_config_value_wins_over_the_deprecated_attribute():
    with pytest.warns(DeprecationWarning):
        manager = AuthManager(LegacyConfig).use_oauth2(oauth2_config(access_token_ttl=900))
    assert manager.oauth2_config.access_token_ttl == 900
    assert manager.oauth2_config.issuer == "https://legacy.example"


def test_deprecated_key_is_still_honoured():
    class KeyConfig(AuthConfig):
        guards = {}
        key = TEST_OAUTH_KEY

    with pytest.warns(DeprecationWarning, match="AuthConfig.key"):
        manager = AuthManager(KeyConfig).use_oauth2({"clients": {"store": "memory"}})
    assert manager.oauth2_config.key == TEST_OAUTH_KEY


# --- discovery and error responses ------------------------------------------


def test_discovery_lists_only_enabled_grant_types():
    http, _ = make_auth_client(oauth2=oauth2_config())
    assert http.get("/.well-known/oauth-authorization-server").json()["grant_types_supported"] == list(DEFAULT_GRANT_TYPES)
    http, _ = make_auth_client(oauth2=oauth2_config(grant_types=list(PASSWORD_GRANTS)))
    assert "password" in http.get("/.well-known/oauth-authorization-server").json()["grant_types_supported"]


def test_invalid_client_challenges_with_basic():
    http, _ = make_auth_client()
    response = http.post("/oauth/token", data={"grant_type": "client_credentials"}, auth=("unknown", "nope"))
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert response.headers["www-authenticate"] == "Basic"


@pytest.mark.parametrize(
    "data",
    [
        {"grant_type": "unsupported"},
        {"grant_type": "refresh_token", "refresh_token": "unknown"},
        {"grant_type": "client_credentials"},
    ],
)
def test_token_error_responses_are_not_cached(data):
    http, _ = make_auth_client()
    response = http.post("/oauth/token", data=data)
    assert response.status_code >= 400
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
