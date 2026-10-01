import asyncio
import os
from uuid import UUID

import asyncpg
import pytest

from fastapi_startkit_auth.providers.model import AsyncModelUserProvider, ModelUserProvider

POSTGRES_DSN = os.environ.get("TEST_ASYNCPG_DSN")


@pytest.fixture
async def postgres_users():
    if not POSTGRES_DSN:
        pytest.skip("TEST_ASYNCPG_DSN is not set")
    connection = await asyncpg.connect(POSTGRES_DSN)
    await connection.execute("DROP TABLE IF EXISTS auth_provider_int_users, auth_provider_uuid_users")
    await connection.execute("CREATE TABLE auth_provider_int_users (id integer PRIMARY KEY)")
    await connection.execute("INSERT INTO auth_provider_int_users (id) VALUES (7)")
    await connection.execute("CREATE TABLE auth_provider_uuid_users (id uuid PRIMARY KEY)")
    await connection.execute("INSERT INTO auth_provider_uuid_users (id) VALUES ($1)", UUID("d8ea1aa2-47e5-4fef-a3e8-dcd5fd68d217"))

    class IntegerUser:
        id: int

        @classmethod
        async def find(cls, identifier):
            return await connection.fetchrow("SELECT id FROM auth_provider_int_users WHERE id = $1", identifier)

    class UUIDUser:
        id: UUID

        @classmethod
        async def find(cls, identifier):
            return await connection.fetchrow("SELECT id FROM auth_provider_uuid_users WHERE id = $1", identifier)

    yield connection, IntegerUser, UUIDUser
    await connection.execute("DROP TABLE auth_provider_int_users, auth_provider_uuid_users")
    await connection.close()


@pytest.mark.asyncio
async def test_async_provider_coerces_numeric_subject_for_integer_key(postgres_users):
    _, integer_user, _ = postgres_users
    user = await AsyncModelUserProvider(integer_user).retrieve_by_id("7")
    assert user["id"] == 7


def test_sync_provider_coerces_numeric_subject_for_integer_key(postgres_users):
    class SyncIntegerUser:
        id: int

        @classmethod
        def find(cls, identifier):
            async def fetch():
                connection = await asyncpg.connect(POSTGRES_DSN)
                try:
                    return await connection.fetchrow("SELECT id FROM auth_provider_int_users WHERE id = $1", identifier)
                finally:
                    await connection.close()

            return asyncio.run(fetch())

    user = ModelUserProvider(SyncIntegerUser()).retrieve_by_id("7")
    assert user["id"] == 7


@pytest.mark.asyncio
async def test_async_provider_preserves_uuid_subject(postgres_users):
    _, _, uuid_user = postgres_users
    identifier = "d8ea1aa2-47e5-4fef-a3e8-dcd5fd68d217"
    user = await AsyncModelUserProvider(uuid_user).retrieve_by_id(identifier)
    assert user["id"] == UUID(identifier)
