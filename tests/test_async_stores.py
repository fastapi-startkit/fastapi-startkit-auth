import asyncio
import time

import pytest

from fastapi_startkit_auth.apitokens.async_sql import AsyncSqlApiTokenRepository
from fastapi_startkit_auth.database import AiosqliteDatabase, AsyncpgDatabase, LazyAsyncDatabase, async_database
from fastapi_startkit_auth.sessions.async_sql import AsyncSqlSessionStore
from fastapi_startkit_auth.tokens.async_sql import AsyncSqlTokenRepository


async def session_store(connection, **kwargs):
    store = AsyncSqlSessionStore(connection, **kwargs)
    await store.create_table()
    return store


async def api_token_repo(connection):
    repo = AsyncSqlApiTokenRepository(connection)
    await repo.create_table()
    return repo


async def token_repo(connection):
    repo = AsyncSqlTokenRepository(connection)
    await repo.create_table()
    return repo


# --- adapter selection ---------------------------------------------------


async def test_async_database_wraps_each_driver(async_connection):
    expected = AiosqliteDatabase if hasattr(async_connection, "commit") else AsyncpgDatabase
    assert isinstance(async_database(async_connection), expected)


async def test_zero_arg_factory_is_resolved_lazily_once():
    import aiosqlite

    calls = []

    async def factory():
        calls.append(1)
        return await aiosqlite.connect(":memory:")

    database = async_database(factory)
    assert isinstance(database, LazyAsyncDatabase)
    assert calls == []
    store = AsyncSqlSessionStore(factory)
    await store.create_table()
    record = await store.create(user_id=1, guard="web", ttl=60)
    assert (await store.find(record.id)).user_id == 1
    assert calls == [1]


def test_unsupported_connection_is_rejected():
    with pytest.raises(TypeError):
        async_database(object())


# --- sessions ------------------------------------------------------------


async def test_session_round_trip(async_connection):
    store = await session_store(async_connection)
    record = await store.create(user_id={"tenant": 1, "id": 7}, guard="web", ttl=60)
    found = await store.find(record.id)
    assert found.user_id == {"tenant": 1, "id": 7}
    assert found.guard == "web"
    assert found.csrf_token == record.csrf_token


async def test_session_touch_regenerate_and_invalidate(async_connection):
    store = await session_store(async_connection)
    record = await store.create(user_id=1, guard="web", ttl=None)
    await store.touch(record.id)
    old_id = record.id
    regenerated = await store.regenerate_id(old_id)
    assert regenerated.id != old_id
    assert await store.find(old_id) is None
    assert await store.invalidate(regenerated.id) is True
    assert await store.invalidate(regenerated.id) is False
    assert await store.find(regenerated.id) is None


async def test_expired_session_is_not_returned(async_connection):
    store = await session_store(async_connection)
    record = await store.create(user_id=1, guard="web", ttl=-1)
    assert await store.find(record.id) is None


async def test_idle_session_is_purged(async_connection):
    store = await session_store(async_connection, idle_ttl=0.01)
    record = await store.create(user_id=1, guard="web", ttl=None)
    await asyncio.sleep(0.05)
    await store.purge_expired()
    assert await store.find(record.id) is None


# --- personal API tokens -------------------------------------------------


async def test_api_token_round_trip(async_connection):
    repo = await api_token_repo(async_connection)
    record = await repo.create(user_id=3, token_hash="hash", name="cli", abilities=["read"], expires_at=None)
    found = await repo.find(record.id)
    assert (found.user_id, found.name, found.abilities) == (3, "cli", ["read"])
    await repo.touch(record.id)
    assert (await repo.find(record.id)).last_used_at is not None


async def test_api_token_listing_and_revocation(async_connection):
    repo = await api_token_repo(async_connection)
    first = await repo.create(user_id=3, token_hash="a", name="a", abilities=[], expires_at=None)
    await repo.create(user_id=3, token_hash="b", name="b", abilities=[], expires_at=None)
    await repo.create(user_id=4, token_hash="c", name="c", abilities=[], expires_at=None)
    assert [r.name for r in await repo.list_for_user(3)] == ["a", "b"]
    assert await repo.revoke(first.id) is True
    assert await repo.revoke(first.id) is False
    assert await repo.revoke_all_for_user(3) == 1
    assert await repo.list_for_user(3) == []


async def test_expired_api_token_is_dropped(async_connection):
    repo = await api_token_repo(async_connection)
    record = await repo.create(user_id=3, token_hash="h", name=None, abilities=[], expires_at=time.time() - 1)
    assert await repo.list_for_user(3) == []
    assert await repo.find(record.id) is None


# --- OAuth tokens --------------------------------------------------------


async def test_access_token_round_trip(async_connection):
    repo = await token_repo(async_connection)
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


async def test_refresh_token_is_hashed_and_revoked_once(async_connection):
    repo = await token_repo(async_connection)
    await repo.store_refresh_token(
        token_id="secret-refresh", access_jti="j1", user_id=1, client_id=None, scopes=["read"], expires_at=None
    )
    database = async_database(async_connection)
    stored = await database.fetch_all("SELECT token_hash FROM oauth_refresh_tokens")
    assert [row[0] for row in stored] != ["secret-refresh"]
    assert (await repo.find_refresh_token("secret-refresh")).scopes == ["read"]
    results = await asyncio.gather(*(repo.revoke_refresh_token("secret-refresh") for _ in range(5)))
    assert results.count(True) == 1
    assert (await repo.find_refresh_token("secret-refresh")).revoked is True


async def test_auth_code_can_be_pulled_once(async_connection):
    repo = await token_repo(async_connection)
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


async def test_token_purge_removes_expired_rows(async_connection):
    repo = await token_repo(async_connection)
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
