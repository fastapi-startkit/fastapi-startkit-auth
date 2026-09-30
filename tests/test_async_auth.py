import base64
import hashlib

import httpx
import pytest
from fastapi import Body, Depends

from fastapi_startkit_auth import (
    Application,
    AsyncAuth,
    AsyncPassportGuard,
    AsyncPasswordBroker,
    AsyncSessionGuard,
    AsyncTokenGuard,
    AsyncTokenService,
    Auth,
    AuthConfig,
    AuthProvider,
    InvalidSession,
    current_user,
    optional_user,
)
from fastapi_startkit_auth.grants import (
    AsyncAuthorizationCodeGrant,
    AsyncClientCredentialsGrant,
    AsyncPasswordGrant,
    AsyncRefreshTokenGrant,
)
from fastapi_startkit_auth.providers.model import AsyncModelUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

HASHER = BcryptHasher(rounds=4)


class AsyncUser:

    rows: dict = {}
    saves: list = []

    def __init__(self, **attributes):
        self.__dict__.update(attributes)

    @classmethod
    def seed(cls, *users):
        cls.rows = {user.id: user for user in users}
        cls.saves = []

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
        type(self).saves.append(self.id)


@pytest.fixture(autouse=True)
def users():
    AsyncUser.seed(
        AsyncUser(id=1, email="ada@example.com", hashed_password=HASHER.make("secret"), is_active=True),
        AsyncUser(id=2, email="off@example.com", hashed_password=HASHER.make("secret"), is_active=False),
    )
    return AsyncUser.rows


USER_PROVIDER = {
    "driver": "async_model",
    "model": AsyncUser,
    "password_field": "hashed_password",
    "password_key": "password",
    "is_active": "is_active",
}


def make_config(connection, *, default_guard="api", sent=None):
    class Config(AuthConfig):
        key = "async-tests-secret-key-32-bytes-minimum!!"
        bcrypt_rounds = 4
        default = {"guard": default_guard, "passwords": "users"}
        guards = {
            "api": {"driver": "passport", "provider": "users"},
            "web": {"driver": "session", "provider": "users"},
            "tokens": {"driver": "token", "provider": "users"},
        }
        providers = {"users": USER_PROVIDER}
        passwords = {"users": {"provider": "users", "table": "password_reset_tokens", "expire": 60, "throttle": 0}}
        session = {"store": "orm", "connection": connection}
        api_tokens = {"store": "orm", "connection": connection}
        tokens = {"store": "orm", "connection": connection}
        spa = {"enabled": True}
        password_reset_notifier = staticmethod(lambda email, token: sent.append((email, token))) if sent is not None else None

    return Config


def user_json(user):
    return None if user is None else {"id": user.id, "email": user.email}


def wire_routes(api):
    @api.get("/me")
    async def me(user=Depends(current_user)):
        return user_json(user)

    @api.get("/whoami")
    async def whoami(user=Depends(optional_user)):
        return user_json(user)

    @api.post("/login")
    async def login(payload: dict = Body(...), auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        if not await auth.attempt(payload):
            raise InvalidSession("Invalid credentials.")
        return {"ok": True}

    @api.post("/login-as/{user_id}")
    async def login_as(user_id: int, auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        record = await auth.login(user_id)
        return {"session_id": record.id}

    @api.post("/logout")
    async def logout(auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        await auth.logout()
        return {"ok": True}

    @api.get("/status")
    async def status(auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        return {"check": await auth.check(), "id": await auth.id(), "user": user_json(await auth.user())}

    @api.get("/sync-facade")
    def sync_facade(auth: Auth = Depends(Auth.scoped)):
        auth.logout()


async def build(connection, **kwargs):
    application = Application([(AuthProvider, make_config(connection, **kwargs))])
    wire_routes(application.api)
    manager = application.auth
    transport = httpx.ASGITransport(app=application.api)
    client = httpx.AsyncClient(transport=transport, base_url="https://testserver")
    return client, manager


@pytest.fixture
async def app(orm_database):
    client, manager = await build(orm_database)
    async with client:
        yield client, manager


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def password_token(client, email="ada@example.com", password="secret", scope=""):
    return await client.post(
        "/oauth/token", data={"grant_type": "password", "username": email, "password": password, "scope": scope}
    )


# --- wiring --------------------------------------------------------------


async def test_manager_selects_async_variants(app):
    _, manager = app
    assert isinstance(manager.guard("api").provider, AsyncModelUserProvider)
    assert isinstance(manager.guard("api"), AsyncPassportGuard)
    assert isinstance(manager.guard("web"), AsyncSessionGuard)
    assert isinstance(manager.guard("tokens"), AsyncTokenGuard)
    assert isinstance(manager.token_service, AsyncTokenService)
    assert isinstance(manager.password_grant(), AsyncPasswordGrant)
    assert isinstance(manager.refresh_grant(), AsyncRefreshTokenGrant)
    assert isinstance(manager.client_credentials_grant(), AsyncClientCredentialsGrant)
    assert isinstance(manager.authorization_code_grant(), AsyncAuthorizationCodeGrant)
    assert isinstance(manager.broker(), AsyncPasswordBroker)
    assert manager.session_guard_name() == "web"


@pytest.mark.parametrize("section", ["session", "api_tokens", "tokens"])
@pytest.mark.parametrize("removed", ["sql", "async_sql"])
def test_removed_sql_stores_point_to_the_orm_store(section, removed):
    from fastapi_startkit_auth.manager import AuthManager

    class Config(AuthConfig):
        key = "async-tests-secret-key-32-bytes-minimum!!"
        providers = {"users": {"driver": "memory", "users": []}}

    setattr(Config, section, {"store": removed})
    attribute = {"session": "session_store", "api_tokens": "api_tokens", "tokens": "token_repository"}[section]
    with pytest.raises(ValueError, match='"orm"'):
        getattr(AuthManager(Config), attribute)


# --- async model provider ------------------------------------------------


async def test_provider_reads_hashed_password_column_with_password_key():
    provider = AsyncModelUserProvider(
        AsyncUser, hasher=HASHER, password_field="hashed_password", password_key="password"
    )
    user = await provider.retrieve_by_credentials({"email": "ada@example.com"})
    assert user.id == 1
    assert await provider.validate_credentials(user, {"password": "secret"}) is True
    assert await provider.validate_credentials(user, {"password": "wrong"}) is False
    assert await provider.validate_credentials(user, {"hashed_password": "secret"}) is False
    assert await provider.retrieve_by_id(1) is user
    assert await provider.retrieve_by_credentials({}) is None
    await provider.dummy_verify()


async def test_provider_is_active_accepts_attribute_or_callable():
    by_attribute = AsyncModelUserProvider(AsyncUser, hasher=HASHER, is_active="is_active")
    by_callable = AsyncModelUserProvider(AsyncUser, hasher=HASHER, is_active=lambda user: user.id == 2)
    default = AsyncModelUserProvider(AsyncUser, hasher=HASHER)
    active, inactive = AsyncUser.rows[1], AsyncUser.rows[2]
    async def by_coroutine_check(user):
        return user.id == 1

    by_coroutine = AsyncModelUserProvider(AsyncUser, hasher=HASHER, is_active=by_coroutine_check)
    assert (await by_attribute.is_active(active), await by_attribute.is_active(inactive)) == (True, False)
    assert (await by_callable.is_active(active), await by_callable.is_active(inactive)) == (False, True)
    assert (await by_coroutine.is_active(active), await by_coroutine.is_active(inactive)) == (True, False)
    assert await default.is_active(inactive) is True


async def test_provider_update_password_awaits_save():
    provider = AsyncModelUserProvider(AsyncUser, hasher=HASHER, password_field="hashed_password")
    user = AsyncUser.rows[1]
    await provider.update_password(user, "new-secret")
    assert AsyncUser.saves == [1]
    assert HASHER.verify("new-secret", user.hashed_password)


# --- passport guard + grants over HTTP -----------------------------------


async def test_password_grant_then_current_user(app):
    client, _ = app
    issued = await password_token(client)
    assert issued.status_code == 200, issued.text
    me = await client.get("/me", headers=bearer(issued.json()["access_token"]))
    assert me.json() == {"id": 1, "email": "ada@example.com"}
    assert (await client.get("/whoami")).json() is None


async def test_password_grant_rejects_bad_password_and_inactive_user(app):
    client, _ = app
    assert (await password_token(client, password="nope")).json()["error"] == "invalid_grant"
    assert (await password_token(client, email="missing@example.com")).json()["error"] == "invalid_grant"
    inactive = await password_token(client, email="off@example.com")
    assert inactive.status_code == 400
    assert inactive.json()["error"] == "invalid_grant"


async def test_deactivated_user_token_stops_working(app, users):
    client, _ = app
    token = (await password_token(client)).json()["access_token"]
    users[1].is_active = False
    me = await client.get("/me", headers=bearer(token))
    assert me.status_code == 401
    assert (await client.get("/whoami", headers=bearer(token))).json() is None


async def test_refresh_rotates_and_rejects_reuse(app):
    client, _ = app
    first = (await password_token(client, scope="read")).json()
    refreshed = await client.post(
        "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["scope"] == "read"
    assert (await client.get("/me", headers=bearer(first["access_token"]))).status_code == 401
    assert (await client.get("/me", headers=bearer(refreshed.json()["access_token"]))).status_code == 200
    replay = await client.post(
        "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}
    )
    assert replay.json()["error"] == "invalid_grant"


async def test_introspect_and_revoke(app):
    client, manager = app
    confidential, secret = manager.client_repository.register(name="rs", grant_types=["client_credentials"])
    auth = (confidential.id, secret)
    token = (await password_token(client)).json()["access_token"]
    active = await client.post("/oauth/introspect", data={"token": token}, auth=auth)
    assert active.json()["active"] is True
    assert (await client.post("/oauth/revoke", data={"token": token}, auth=auth)).json() == {"revoked": True}
    assert (await client.post("/oauth/introspect", data={"token": token}, auth=auth)).json()["active"] is False
    assert (await client.get("/me", headers=bearer(token))).status_code == 401


async def test_client_credentials_grant(app):
    client, manager = app
    machine, secret = manager.client_repository.register(name="svc", grant_types=["client_credentials"])
    issued = await client.post(
        "/oauth/token", data={"grant_type": "client_credentials", "scope": "jobs"}, auth=(machine.id, secret)
    )
    assert issued.status_code == 200, issued.text
    assert issued.json()["scope"] == "jobs"
    assert "refresh_token" not in issued.json()


async def test_authorization_code_with_pkce_is_single_use(app):
    client, manager = app
    spa, _ = manager.client_repository.register(
        name="spa", redirect_uris=["https://app/cb"], confidential=False, grant_types=["authorization_code"]
    )
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    user_token = (await password_token(client)).json()["access_token"]
    authorized = await client.post(
        "/oauth/authorize",
        json={"client_id": spa.id, "redirect_uri": "https://app/cb", "scope": "read", "code_challenge": challenge},
        headers=bearer(user_token),
    )
    code = authorized.json()["code"]
    exchange = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": spa.id,
        "redirect_uri": "https://app/cb",
        "code_verifier": verifier,
    }
    issued = await client.post("/oauth/token", data=exchange)
    assert issued.status_code == 200, issued.text
    me = await client.get("/me", headers=bearer(issued.json()["access_token"]))
    assert me.json()["id"] == 1
    assert (await client.post("/oauth/token", data=exchange)).json()["error"] == "invalid_grant"


async def test_personal_access_tokens(app):
    client, _ = app
    headers = bearer((await password_token(client)).json()["access_token"])
    created = await client.post("/oauth/personal-access-tokens", json={"name": "cli", "scopes": ["read"]}, headers=headers)
    assert created.status_code == 201
    jti = created.json()["jti"]
    listed = await client.get("/oauth/personal-access-tokens", headers=headers)
    assert [row["jti"] for row in listed.json()] == [jti]
    assert (await client.get("/me", headers=bearer(created.json()["access_token"]))).status_code == 200
    assert (await client.delete(f"/oauth/personal-access-tokens/{jti}", headers=headers)).status_code == 204
    assert (await client.get("/oauth/personal-access-tokens", headers=headers)).json() == []


# --- session guard + AsyncAuth facade --------------------------------------


@pytest.fixture
async def session_app(orm_database):
    client, manager = await build(orm_database, default_guard="web")
    async with client:
        yield client, manager


def csrf_headers(client):
    return {"X-XSRF-TOKEN": client.cookies.get("XSRF-TOKEN", "")}


async def prime(client):
    assert (await client.get("/__auth__/csrf-cookie")).status_code == 204


async def test_session_attempt_login_status_and_logout(session_app):
    client, _ = session_app
    await prime(client)
    assert (await client.get("/me")).status_code == 401
    failed = await client.post("/login", json={"email": "ada@example.com", "password": "bad"}, headers=csrf_headers(client))
    assert failed.status_code == 401
    ok = await client.post("/login", json={"email": "ada@example.com", "password": "secret"}, headers=csrf_headers(client))
    assert ok.status_code == 200, ok.text
    assert (await client.get("/me")).json() == {"id": 1, "email": "ada@example.com"}
    assert (await client.get("/status")).json() == {
        "check": True,
        "id": 1,
        "user": {"id": 1, "email": "ada@example.com"},
    }
    assert (await client.post("/logout", headers=csrf_headers(client))).status_code == 200
    assert (await client.get("/status")).json()["check"] is False
    assert (await client.get("/me")).status_code == 401


async def test_session_login_by_id_and_inactive_user(session_app, users):
    client, _ = session_app
    await prime(client)
    inactive = await client.post(
        "/login", json={"email": "off@example.com", "password": "secret"}, headers=csrf_headers(client)
    )
    assert inactive.status_code == 401
    assert (await client.post("/login-as/1", headers=csrf_headers(client))).status_code == 200
    assert (await client.get("/whoami")).json()["id"] == 1
    users[1].is_active = False
    assert (await client.get("/me")).status_code == 401


async def test_sync_facade_refuses_async_session_guard(session_app):
    client, _ = session_app
    with pytest.raises(RuntimeError, match="use AsyncAuth"):
        await client.get("/sync-facade")


# --- token guard (personal API tokens) -----------------------------------


async def test_token_guard_with_async_api_tokens(orm_database):
    client, manager = await build(orm_database, default_guard="tokens")
    async with client:
        issued = await manager.api_tokens.create(1, name="cli", abilities=["read"])
        assert (await client.get("/me", headers=bearer(issued.plain_text))).json()["id"] == 1
        record_id = issued.record.id
        assert [r.id for r in await manager.api_tokens.tokens_for(1)] == [record_id]
        assert (await client.get("/me", headers=bearer(f"{record_id}|wrong"))).status_code == 401
        AsyncUser.rows[1].is_active = False
        assert (await client.get("/me", headers=bearer(issued.plain_text))).status_code == 401
        assert await manager.api_tokens.revoke(record_id) is True


# --- password broker -----------------------------------------------------


async def test_password_reset_with_async_provider(orm_database):
    sent = []
    client, _ = await build(orm_database, sent=sent)
    async with client:
        generic = await client.post("/password/email", json={"email": "ada@example.com"})
        assert generic.status_code == 200
        unknown = await client.post("/password/email", json={"email": "missing@example.com"})
        assert unknown.json() == generic.json()
        [(email, token)] = sent
        assert email == "ada@example.com"
        reset = await client.post(
            "/password/reset", json={"email": email, "token": token, "password": "brand-new"}
        )
        assert reset.status_code == 200, reset.text
        assert AsyncUser.saves == [1]
        assert (await password_token(client, password="secret")).status_code == 400
        assert (await password_token(client, password="brand-new")).status_code == 200
        replay = await client.post("/password/reset", json={"email": email, "token": token, "password": "x"})
        assert replay.json()["error"] == "invalid_grant"
