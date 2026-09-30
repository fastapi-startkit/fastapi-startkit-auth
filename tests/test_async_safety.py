import asyncio
import base64
import hashlib
import sqlite3
import warnings
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Body, Depends
from fastapi.testclient import TestClient

from fastapi_startkit_auth import (
    Application,
    AsyncAuth,
    AsyncPassportGuard,
    Auth,
    AuthConfig,
    AuthProvider,
    SessionGuard,
    SqlSessionStore,
    current_user,
)
from fastapi_startkit_auth.concurrency import AsyncMisconfiguration
from fastapi_startkit_auth.grants import AsyncPasswordGrant, PasswordGrant, RefreshTokenGrant
from fastapi_startkit_auth.providers.base import user_is_active
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.providers.model import ModelUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.security.jwt import JWTEncoder
from fastapi_startkit_auth.sessions.store import InMemorySessionStore
from fastapi_startkit_auth.tokens.repository import InMemoryTokenRepository
from fastapi_startkit_auth.tokens.service import TokenService

HASHER = BcryptHasher(rounds=4)
KEY = "async-safety-secret-key-32-bytes-minimum!"
LOOP_CALLS: list = []


def record_thread():
    try:
        asyncio.get_running_loop()
        LOOP_CALLS.append(True)
    except RuntimeError:
        LOOP_CALLS.append(False)


class Account:
    rows: dict = {}

    def __init__(self, **attributes):
        self.__dict__.update(attributes)

    @classmethod
    async def find(cls, identifier):
        return cls.rows.get(identifier)

    @classmethod
    def where(cls, field, value):
        class Query:
            async def first(self):
                return next((u for u in cls.rows.values() if getattr(u, field) == value), None)

        return Query()

    async def save(self):
        pass


async def account_is_active(user):
    await asyncio.sleep(0)
    return user.active


@pytest.fixture(autouse=True)
def accounts():
    Account.rows = {
        1: Account(id=1, email="ada@example.com", password=HASHER.make("secret"), active=True),
        2: Account(id=2, email="off@example.com", password=HASHER.make("secret"), active=False),
    }
    LOOP_CALLS.clear()
    return Account.rows


ASYNC_PROVIDER = {"driver": "async_model", "model": Account, "is_active": account_is_active}


def make_config(connection=None, *, default_guard="api", provider=None, session=None):
    stores = {"store": "async_sql", "connection": connection} if connection is not None else {"store": "memory"}

    class Config(AuthConfig):
        key = KEY
        bcrypt_rounds = 4
        default = {"guard": default_guard}
        guards = {
            "api": {"driver": "passport", "provider": "users"},
            "web": {"driver": "session", "provider": "users"},
            "tokens": {"driver": "token", "provider": "users"},
        }
        providers = {"users": provider or ASYNC_PROVIDER}

    Config.session = session or stores
    Config.api_tokens = stores
    Config.tokens = stores
    return Config


async def build(connection=None, **kwargs):
    application = Application([(AuthProvider, make_config(connection, **kwargs))])

    @application.api.get("/me")
    async def me(user=Depends(current_user)):
        return {"id": user["id"] if isinstance(user, dict) else user.id}

    @application.api.post("/login")
    async def login(payload: dict = Body(...), auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        return {"ok": await auth.attempt(payload, guard="web")}

    manager = application.auth
    for store in (manager.session_store, manager.api_tokens.repository, manager.token_repository):
        create_table = getattr(store, "create_table", None)
        if create_table is not None and asyncio.iscoroutinefunction(create_table):
            await create_table()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=application.api), base_url="https://testserver")
    return client, manager


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def password_token(client, email="ada@example.com", password="secret"):
    return await client.post("/oauth/token", data={"grant_type": "password", "username": email, "password": password})


def remove_owner(accounts, how):
    if how == "deactivated":
        accounts[1].active = False
    else:
        del accounts[1]


# --- async is_active hook ------------------------------------------------


async def test_async_is_active_hook_denies_password_grant(async_connection):
    client, _ = await build(async_connection)
    async with client:
        assert (await password_token(client, email="off@example.com")).json()["error"] == "invalid_grant"
        assert (await password_token(client)).status_code == 200


async def test_async_is_active_hook_denies_passport_guard(async_connection, accounts):
    client, _ = await build(async_connection)
    async with client:
        token = (await password_token(client)).json()["access_token"]
        assert (await client.get("/me", headers=bearer(token))).status_code == 200
        accounts[1].active = False
        assert (await client.get("/me", headers=bearer(token))).status_code == 401


async def test_async_is_active_hook_denies_token_guard(async_connection, accounts):
    client, manager = await build(async_connection, default_guard="tokens")
    async with client:
        issued = await manager.api_tokens.create(1, name="cli")
        assert (await client.get("/me", headers=bearer(issued.plain_text))).status_code == 200
        accounts[1].active = False
        assert (await client.get("/me", headers=bearer(issued.plain_text))).status_code == 401


async def test_async_is_active_hook_denies_attempt_and_session_guard(async_connection, accounts):
    client, _ = await build(async_connection, default_guard="web")
    async with client:
        denied = await client.post("/login", json={"email": "off@example.com", "password": "secret"})
        assert denied.json() == {"ok": False}
        assert (await client.post("/login", json={"email": "ada@example.com", "password": "secret"})).json() == {
            "ok": True
        }
        assert (await client.get("/me")).status_code == 200
        accounts[1].active = False
        assert (await client.get("/me")).status_code == 401


@pytest.mark.parametrize("provider_class", [InMemoryUserProvider, lambda **kw: ModelUserProvider(Account, **kw)])
def test_sync_providers_reject_async_is_active_hook(provider_class):
    with pytest.raises(TypeError, match="async provider"):
        provider_class(hasher=HASHER, is_active=account_is_active)


def test_sync_is_active_check_fails_closed_on_awaitable():
    provider = SimpleNamespace(is_active=lambda user: account_is_active(user))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(AsyncMisconfiguration):
            user_is_active(provider, Account.rows[2])


# --- providers with only some async methods --------------------------------


class AsyncValidateProvider(InMemoryUserProvider):
    async def validate_credentials(self, user, credentials):
        return await asyncio.to_thread(super().validate_credentials, user, credentials)


def mixed_provider():
    provider = AsyncValidateProvider(hasher=HASHER)
    provider.create(id=1, email="ada@example.com", password="secret")
    return provider


async def test_async_validate_credentials_selects_async_grant_and_denies_wrong_password():
    client, manager = await build(provider={"driver": "instance", "instance": mixed_provider()})
    async with client:
        assert isinstance(manager.password_grant(), AsyncPasswordGrant)
        assert isinstance(manager.guard("api"), AsyncPassportGuard)
        assert (await password_token(client, password="wrong")).json()["error"] == "invalid_grant"
        token = (await password_token(client)).json()["access_token"]
        assert (await client.get("/me", headers=bearer(token))).json() == {"id": 1}


def test_sync_grant_and_attempt_fail_closed_on_async_validate():
    provider = mixed_provider()
    tokens = TokenService(encoder=JWTEncoder(secret=KEY), repository=InMemoryTokenRepository())
    with pytest.raises(AsyncMisconfiguration):
        PasswordGrant(tokens, provider).handle(username="ada@example.com", password="wrong", scopes=[], client_id=None)

    guard = SessionGuard(name="web", store=InMemorySessionStore(), provider=provider, ttl=None)
    manager = SimpleNamespace(guard=lambda name=None: guard)
    request = SimpleNamespace(state=SimpleNamespace())
    with pytest.raises(AsyncMisconfiguration):
        Auth(manager, request).attempt({"email": "ada@example.com", "password": "wrong"})


# --- owner re-checks on refresh, code exchange and introspection -----------


@pytest.mark.parametrize("how", ["deactivated", "deleted"])
async def test_refresh_grant_denied_when_owner_is_gone(async_connection, accounts, how):
    client, _ = await build(async_connection)
    async with client:
        refresh_token = (await password_token(client)).json()["refresh_token"]
        remove_owner(accounts, how)
        denied = await client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token})
        assert denied.json()["error"] == "invalid_grant"


async def test_refresh_denied_for_inactive_owner_does_not_consume_the_token(async_connection, accounts):
    client, _ = await build(async_connection)
    async with client:
        refresh_token = (await password_token(client)).json()["refresh_token"]
        accounts[1].active = False
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        assert (await client.post("/oauth/token", data=data)).status_code == 400
        accounts[1].active = True
        assert (await client.post("/oauth/token", data=data)).status_code == 200


@pytest.mark.parametrize("how", ["deactivated", "deleted"])
async def test_authorization_code_denied_when_owner_is_gone(async_connection, accounts, how):
    client, manager = await build(async_connection)
    async with client:
        spa, _ = manager.client_repository.register(
            name="spa", redirect_uris=["https://app/cb"], confidential=False, grant_types=["authorization_code"]
        )
        verifier = "v" * 64
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        user_token = (await password_token(client)).json()["access_token"]
        authorized = await client.post(
            "/oauth/authorize",
            json={"client_id": spa.id, "redirect_uri": "https://app/cb", "code_challenge": challenge},
            headers=bearer(user_token),
        )
        remove_owner(accounts, how)
        exchange = {
            "grant_type": "authorization_code",
            "code": authorized.json()["code"],
            "client_id": spa.id,
            "redirect_uri": "https://app/cb",
            "code_verifier": verifier,
        }
        assert (await client.post("/oauth/token", data=exchange)).json()["error"] == "invalid_grant"


@pytest.mark.parametrize("how", ["deactivated", "deleted"])
async def test_introspect_reports_gone_owner_as_inactive(async_connection, accounts, how):
    client, manager = await build(async_connection)
    async with client:
        server, secret = manager.client_repository.register(name="rs", grant_types=["client_credentials"])
        token = (await password_token(client)).json()["access_token"]
        introspect = {"token": token}
        assert (await client.post("/oauth/introspect", data=introspect, auth=(server.id, secret))).json()["active"]
        remove_owner(accounts, how)
        result = await client.post("/oauth/introspect", data=introspect, auth=(server.id, secret))
        assert result.json() == {"active": False}


@pytest.mark.parametrize("how", ["deactivated", "deleted"])
def test_sync_refresh_grant_denied_when_owner_is_gone(how):
    users = [{"id": 1, "email": "ada@example.com", "password": HASHER.make("secret"), "active": True}]
    provider = {"driver": "memory", "users": users, "is_active": "active"}
    application = Application([(AuthProvider, make_config(provider=provider))])
    manager = application.auth
    assert isinstance(manager.refresh_grant(), RefreshTokenGrant)
    client = TestClient(application.api)
    issued = client.post(
        "/oauth/token", data={"grant_type": "password", "username": "ada@example.com", "password": "secret"}
    )
    stored = manager.guard().provider.retrieve_by_id(1)
    if how == "deactivated":
        stored["active"] = False
    else:
        manager.guard().provider._users.clear()
    denied = client.post(
        "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": issued.json()["refresh_token"]}
    )
    assert denied.json()["error"] == "invalid_grant"


# --- sync collaborators in an async configuration stay off the event loop ---


class RecordingHasher(BcryptHasher):
    def make(self, plain):
        record_thread()
        return super().make(plain)

    def verify(self, plain, hashed):
        record_thread()
        return super().verify(plain, hashed)


class SyncAccount:
    rows: dict = {}

    def __init__(self, **attributes):
        self.__dict__.update(attributes)

    @classmethod
    def find(cls, identifier):
        record_thread()
        return cls.rows.get(identifier)

    @classmethod
    def where(cls, field, value):
        class Query:
            def first(self):
                record_thread()
                return next((u for u in cls.rows.values() if getattr(u, field) == value), None)

        return Query()


class RecordingSessionStore(SqlSessionStore):
    def create(self, **kwargs):
        record_thread()
        return super().create(**kwargs)

    def find(self, session_id):
        record_thread()
        return super().find(session_id)

    def touch(self, session_id):
        record_thread()
        return super().touch(session_id)


def sync_is_active(user):
    record_thread()
    return True


async def test_sync_provider_and_session_store_never_run_on_the_loop(async_connection):
    SyncAccount.rows = {1: SyncAccount(id=1, email="ada@example.com", password=HASHER.make("secret"))}
    provider = ModelUserProvider(SyncAccount, hasher=RecordingHasher(rounds=4), is_active=sync_is_active)
    sessions = RecordingSessionStore(sqlite3.connect(":memory:", check_same_thread=False))
    client, _ = await build(
        async_connection,
        provider={"driver": "instance", "instance": provider},
        session={"store": "instance", "instance": sessions},
    )
    async with client:
        LOOP_CALLS.clear()
        assert (await password_token(client, password="wrong")).json()["error"] == "invalid_grant"
        token = (await password_token(client)).json()["access_token"]
        assert (await client.get("/me", headers=bearer(token))).json() == {"id": 1}
        assert (await client.post("/login", json={"email": "ada@example.com", "password": "secret"})).json() == {
            "ok": True
        }
        assert (await client.get("/me", headers=bearer(token))).status_code == 200
        assert (await client.get("/oauth/personal-access-tokens", headers=bearer(token))).status_code == 200
    assert len(LOOP_CALLS) > 10
    assert not any(LOOP_CALLS)
