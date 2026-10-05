import pytest

from fastapi_startkit_auth.exceptions import InvalidGrant, InvalidToken
from fastapi_startkit_auth.security.jwt import JWTEncoder
from fastapi_startkit_auth.tokens.service import AsyncTokenService

SECRET = "async-refresh-race-secret-with-32-bytes!"


def _service(orm_database, *, before_consume=None, after_consume=None):
    from fastapi_startkit_auth.tokens.orm import OrmTokenRepository

    class InterleavingRepository(OrmTokenRepository):
        """Runs a competing request once, at a chosen point inside the first consume."""

        async def consume_refresh_token(self, token_id):
            hook, self.hook = self.hook, None
            if hook and hook[0] == "before":
                await hook[1]()
            consumed = await super().consume_refresh_token(token_id)
            if hook and hook[0] == "after":
                await hook[1]()
            return consumed

    repository = InterleavingRepository(orm_database)
    repository.hook = None
    service = AsyncTokenService(encoder=JWTEncoder(secret=SECRET), repository=repository)
    return service, repository


async def test_replay_landing_after_the_winning_consume_revokes_the_new_pair(orm_database):
    service, repository = _service(orm_database)
    first = await service.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)

    async def replay():
        with pytest.raises(InvalidGrant):
            await service.refresh(first.refresh_token, client_id="c1")

    repository.hook = ("after", replay)
    winner = await service.refresh(first.refresh_token, client_id="c1")

    with pytest.raises(InvalidToken):
        await service.authenticate(winner.access_token)
    with pytest.raises(InvalidGrant):
        await service.refresh(winner.refresh_token, client_id="c1")


async def test_losing_a_rotation_race_revokes_every_pair_minted_from_the_token(orm_database):
    from fastapi_startkit_auth import orm

    service, repository = _service(orm_database)
    first = await service.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    rival = {}

    async def concurrent_refresh():
        rival["issued"] = await service.refresh(first.refresh_token, client_id="c1")

    repository.hook = ("before", concurrent_refresh)
    with pytest.raises(InvalidGrant):
        await service.refresh(first.refresh_token, client_id="c1")

    with pytest.raises(InvalidToken):
        await service.authenticate(rival["issued"].access_token)
    # The losing request minted its own pair before consuming; nothing may stay live.
    assert await orm.query(orm.AuthRefreshToken, orm_database).where("revoked", False).get() == []
    assert await orm.query(orm.AuthAccessToken, orm_database).where("revoked", False).get() == []


async def test_sequential_refreshes_keep_working(orm_database):
    service, _ = _service(orm_database)
    issued = await service.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    for _ in range(3):
        previous = issued
        issued = await service.refresh(issued.refresh_token, client_id="c1")
        with pytest.raises(InvalidToken):
            await service.authenticate(previous.access_token)
    assert (await service.authenticate(issued.access_token))["sub"] == "1"
