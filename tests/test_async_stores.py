import asyncio
import time

import pytest

pytest.importorskip("fastapi_startkit.masoniteorm.models")

from fastapi_startkit_auth import orm
from fastapi_startkit_auth.apitokens.orm import OrmApiTokenRepository
from fastapi_startkit_auth.clients.orm import OrmClientRepository
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.sessions.orm import OrmSessionStore
from fastapi_startkit_auth.tokens.orm import OrmTokenRepository


async def session_store(connection, **kwargs):
    return OrmSessionStore(connection, **kwargs)


async def api_token_repo(connection):
    return OrmApiTokenRepository(connection)


async def token_repo(connection):
    return OrmTokenRepository(connection)


# --- connection selection ------------------------------------------------


async def test_stores_use_the_default_connection_when_none_is_named(orm_database):
    store = OrmSessionStore()
    record = await store.create(user_id=1, guard="web", ttl=60)
    assert (await store.find(record.id)).user_id == 1


# --- sessions ------------------------------------------------------------


async def test_session_round_trip(orm_database):
    store = await session_store(orm_database)
    record = await store.create(user_id={"tenant": 1, "id": 7}, guard="web", ttl=60)
    found = await store.find(record.id)
    assert found.user_id == {"tenant": 1, "id": 7}
    assert found.guard == "web"
    assert found.csrf_token == record.csrf_token


async def test_session_touch_regenerate_and_invalidate(orm_database):
    store = await session_store(orm_database)
    record = await store.create(user_id=1, guard="web", ttl=None)
    await store.touch(record.id)
    old_id = record.id
    regenerated = await store.regenerate_id(old_id)
    assert regenerated.id != old_id
    assert await store.find(old_id) is None
    assert await store.invalidate(regenerated.id) is True
    assert await store.invalidate(regenerated.id) is False
    assert await store.find(regenerated.id) is None


async def test_expired_session_is_not_returned(orm_database):
    store = await session_store(orm_database)
    record = await store.create(user_id=1, guard="web", ttl=-1)
    assert await store.find(record.id) is None


async def test_idle_session_is_purged(orm_database):
    store = await session_store(orm_database, idle_ttl=0.01)
    record = await store.create(user_id=1, guard="web", ttl=None)
    await asyncio.sleep(0.05)
    await store.purge_expired()
    assert await store.find(record.id) is None


# --- personal API tokens -------------------------------------------------


async def test_api_token_round_trip(orm_database):
    repo = await api_token_repo(orm_database)
    record = await repo.create(user_id=3, token_hash="hash", name="cli", abilities=["read"], expires_at=None)
    found = await repo.find(record.id)
    assert (found.user_id, found.name, found.abilities) == (3, "cli", ["read"])
    await repo.touch(record.id)
    assert (await repo.find(record.id)).last_used_at is not None


async def test_api_token_listing_and_revocation(orm_database):
    repo = await api_token_repo(orm_database)
    first = await repo.create(user_id=3, token_hash="a", name="a", abilities=[], expires_at=None)
    await repo.create(user_id=3, token_hash="b", name="b", abilities=[], expires_at=None)
    await repo.create(user_id=4, token_hash="c", name="c", abilities=[], expires_at=None)
    assert [r.name for r in await repo.list_for_user(3)] == ["a", "b"]
    assert await repo.revoke(first.id) is True
    assert await repo.revoke(first.id) is False
    assert await repo.revoke_all_for_user(3) == 1
    assert await repo.list_for_user(3) == []


async def test_expired_api_token_is_dropped(orm_database):
    repo = await api_token_repo(orm_database)
    record = await repo.create(user_id=3, token_hash="h", name=None, abilities=[], expires_at=time.time() - 1)
    assert await repo.list_for_user(3) == []
    assert await repo.find(record.id) is None


# --- OAuth tokens --------------------------------------------------------


async def test_access_token_round_trip(orm_database):
    repo = await token_repo(orm_database)
    await repo.store_access_token(
        jti="j1", user_id=1, client_id="c", scopes=["read"], expires_at=None, name="pat", personal_access=True
    )
    await repo.store_access_token(jti="j2", user_id=1, client_id="c", scopes=[], expires_at=None)
    found = await repo.find_access_token("j1")
    assert (found.user_id, found.scopes, found.personal_access, found.revoked) == (1, ["read"], True, False)
    assert [r.jti for r in await repo.list_access_tokens(1, personal_access=True)] == ["j1"]
    assert len(await repo.list_access_tokens(1)) == 2
    assert await repo.revoke_access_token("j1") is True
    assert (await repo.find_access_token("j1")).revoked is True
    assert await repo.find_access_token("missing") is None


async def test_refresh_token_is_hashed_and_revoked_once(orm_database):
    repo = await token_repo(orm_database)
    await repo.store_refresh_token(
        token_id="secret-refresh", access_jti="j1", user_id=1, client_id=None, scopes=["read"], expires_at=None
    )
    stored = await orm.query(orm.AuthRefreshToken, orm_database).get()
    assert [row.token_hash for row in stored] != ["secret-refresh"]
    assert (await repo.find_refresh_token("secret-refresh")).scopes == ["read"]
    results = await asyncio.gather(*(repo.revoke_refresh_token("secret-refresh") for _ in range(8)))
    assert results.count(True) == 1
    assert (await repo.find_refresh_token("secret-refresh")).revoked is True


async def test_auth_code_can_be_pulled_once(orm_database):
    repo = await token_repo(orm_database)
    await repo.store_auth_code(
        code="the-code",
        client_id="client",
        user_id=1,
        scopes=["read"],
        redirect_uri="https://app/cb",
        code_challenge="challenge",
        code_challenge_method="S256",
        expires_at=time.time() + 60,
    )
    pulled = await asyncio.gather(*(repo.pull_auth_code("the-code") for _ in range(3)))
    winners = [code for code in pulled if code is not None]
    assert len(winners) == 1
    assert (winners[0].client_id, winners[0].redirect_uri, winners[0].code_challenge) == (
        "client",
        "https://app/cb",
        "challenge",
    )


async def test_resource_round_trips_on_codes_and_refresh_tokens(orm_database):
    repo = await token_repo(orm_database)
    await repo.store_auth_code(
        code="bound-code",
        client_id="client",
        user_id=1,
        scopes=["read"],
        redirect_uri=None,
        code_challenge=None,
        code_challenge_method=None,
        expires_at=time.time() + 60,
        resource="https://api/mcp",
    )
    await repo.store_refresh_token(
        token_id="bound-refresh",
        access_jti="j1",
        user_id=1,
        client_id="client",
        scopes=["read"],
        expires_at=None,
        resource="https://api/mcp",
    )
    assert (await repo.pull_auth_code("bound-code")).resource == "https://api/mcp"
    assert (await repo.find_refresh_token("bound-refresh")).resource == "https://api/mcp"


async def test_token_purge_removes_expired_rows(orm_database):
    repo = await token_repo(orm_database)
    past = time.time() - 10
    await repo.store_access_token(jti="old", user_id=1, client_id=None, scopes=[], expires_at=past)
    await repo.store_access_token(jti="live", user_id=1, client_id=None, scopes=[], expires_at=None)
    await repo.store_auth_code(
        code="c",
        client_id="x",
        user_id=1,
        scopes=[],
        redirect_uri=None,
        code_challenge=None,
        code_challenge_method=None,
        expires_at=past,
    )
    await repo.purge_expired()
    assert await repo.find_access_token("old") is None
    assert await repo.find_access_token("live") is not None
    assert await repo.pull_auth_code("c") is None


async def test_create_opportunistically_purges_expired_sessions(orm_database):
    store = await session_store(orm_database, purge_interval=0)
    await store.create(user_id=1, guard="web", ttl=-1)
    await store.create(user_id=2, guard="web", ttl=-1)
    alive = await store.create(user_id=3, guard="web", ttl=3600)
    assert len(await orm.query(orm.AuthSession, orm_database).get()) == 1
    assert await store.find(alive.id) is not None


async def test_purge_on_create_respects_the_interval(orm_database):
    store = await session_store(orm_database, purge_interval=3600)
    await store.create(user_id=1, guard="web", ttl=-1)
    await store.create(user_id=2, guard="web", ttl=3600)
    assert len(await orm.query(orm.AuthSession, orm_database).get()) == 2


async def test_client_round_trip_with_hashed_secret(orm_database):
    repo = OrmClientRepository(orm_database, hasher=BcryptHasher(rounds=4))
    client, secret = await repo.register(
        name="claude",
        redirect_uris=["http://localhost:3334/cb"],
        grant_types=["authorization_code", "refresh_token"],
        scopes=["content:write"],
        owner_id=7,
    )
    stored = await orm.query(orm.AuthClient, orm_database).where("id", client.id).first()
    assert stored.secret != secret

    found = await repo.find(client.id)
    assert (found.redirect_uris, found.scopes, found.owner_id, found.confidential) == (
        ["http://localhost:3334/cb"],
        ["content:write"],
        7,
        True,
    )
    assert (await repo.authenticate(client.id, secret)).id == client.id
    assert await repo.authenticate(client.id, "wrong") is None
    assert [c.id for c in await repo.all()] == [client.id]

    assert await repo.revoke(client.id) is True
    assert await repo.authenticate(client.id, secret) is None
    assert await repo.delete(client.id) is True
    assert await repo.find(client.id) is None


async def test_public_client_has_no_secret(orm_database):
    repo = OrmClientRepository(orm_database, hasher=BcryptHasher(rounds=4))
    client, secret = await repo.register(name="spa", confidential=False)
    assert secret is None
    assert (await repo.authenticate(client.id, None)).id == client.id


async def test_rollback_drops_every_table(orm_database):
    from fastapi_startkit.masoniteorm import Migrator

    from conftest import MIGRATIONS_DIR

    await Migrator(migration_directory=str(MIGRATIONS_DIR), connection=orm_database).rollback()
    with pytest.raises(Exception):
        await orm.query(orm.AuthSession, orm_database).get()
