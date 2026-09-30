import asyncio
import inspect

import pytest
from fastapi import Body, Depends
from fastapi.testclient import TestClient

from fastapi_startkit_auth import (
    ApiTokenManager,
    Application,
    Auth,
    AuthConfig,
    AuthProvider,
    InvalidSession,
    PassportGuard,
    PasswordBroker,
    SessionGuard,
    InMemoryApiTokenRepository,
    InMemorySessionStore,
    TokenGuard,
    TokenService,
    current_user,
    optional_user,
)
from fastapi_startkit_auth.dependencies import current_context
from fastapi_startkit_auth.grants import (
    AuthorizationCodeGrant,
    ClientCredentialsGrant,
    PasswordGrant,
    RefreshTokenGrant,
)
from fastapi_startkit_auth.providers.model import ModelUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.tokens.repository import InMemoryTokenRepository

HASHER = BcryptHasher(rounds=4)


class SyncUser:
    rows: dict = {}
    loop_calls: list = []

    def __init__(self, **attributes):
        self.__dict__.update(attributes)

    @classmethod
    def _record_thread(cls):
        try:
            asyncio.get_running_loop()
            cls.loop_calls.append(True)
        except RuntimeError:
            cls.loop_calls.append(False)

    @classmethod
    def find(cls, identifier):
        cls._record_thread()
        return cls.rows.get(identifier)

    @classmethod
    def where(cls, field, value):
        class Query:
            def first(self):
                return next((u for u in cls.rows.values() if getattr(u, field) == value), None)

        return Query()

    def save(self):
        pass


@pytest.fixture(autouse=True)
def users():
    SyncUser.rows = {1: SyncUser(id=1, email="ada@example.com", password=HASHER.make("secret"))}
    SyncUser.loop_calls = []
    return SyncUser.rows


def sync_config(default_guard="api", sent=None):
    class Config(AuthConfig):
        key = "sync-regression-secret-key-32-bytes!!"
        bcrypt_rounds = 4
        default = {"guard": default_guard, "passwords": "users"}
        guards = {
            "api": {"driver": "passport", "provider": "users"},
            "web": {"driver": "session", "provider": "users"},
            "tokens": {"driver": "token", "provider": "users"},
        }
        providers = {"users": {"driver": "model", "model": SyncUser}}
        passwords = {"users": {"provider": "users", "table": "password_reset_tokens", "expire": 60, "throttle": 0}}
        password_reset_notifier = staticmethod(lambda email, token: sent.append((email, token))) if sent is not None else None

    return Config


def build(default_guard="api", sent=None):
    application = Application([(AuthProvider, sync_config(default_guard, sent))])

    @application.api.get("/me")
    def me(user=Depends(current_user)):
        return {"id": user.id}

    @application.api.get("/whoami")
    def whoami(user=Depends(optional_user)):
        return {"id": user.id if user else None}

    @application.api.post("/login")
    def login(payload: dict = Body(...), auth: Auth = Depends(Auth.scoped)):
        if not auth.attempt(payload):
            raise InvalidSession("Invalid credentials.")
        return {"ok": True}

    @application.api.post("/logout")
    def logout(auth: Auth = Depends(Auth.scoped)):
        auth.logout()
        return {"ok": True}

    client = TestClient(application.api, base_url="https://testserver")
    return client, application.auth


def test_manager_builds_the_sync_classes():
    _, manager = build()
    assert type(manager.guard("api").provider) is ModelUserProvider
    assert type(manager.guard("api")) is PassportGuard
    assert type(manager.guard("web")) is SessionGuard
    assert type(manager.guard("tokens")) is TokenGuard
    assert type(manager.token_service) is TokenService
    assert type(manager.token_repository) is InMemoryTokenRepository
    assert type(manager.session_store) is InMemorySessionStore
    assert type(manager.api_tokens) is ApiTokenManager
    assert type(manager.api_tokens.repository) is InMemoryApiTokenRepository
    assert type(manager.password_grant()) is PasswordGrant
    assert type(manager.refresh_grant()) is RefreshTokenGrant
    assert type(manager.client_credentials_grant()) is ClientCredentialsGrant
    assert type(manager.authorization_code_grant()) is AuthorizationCodeGrant
    assert type(manager.broker()) is PasswordBroker


def test_sync_grants_and_services_return_plain_values():
    _, manager = build()
    issued = manager.password_grant().handle(username="ada@example.com", password="secret", scopes=[], client_id=None)
    assert not inspect.isawaitable(issued)
    context = manager.guard().user_from_token(issued.access_token)
    assert context.user.id == 1


def test_public_dependencies_are_now_coroutines():
    assert inspect.iscoroutinefunction(current_context)
    assert inspect.iscoroutinefunction(optional_user)


def test_sync_guard_runs_in_threadpool_not_on_the_event_loop():
    client, _ = build()
    token = client.post("/oauth/token", data={"grant_type": "password", "username": "ada@example.com", "password": "secret"})
    SyncUser.loop_calls = []
    assert client.get("/me", headers={"Authorization": f"Bearer {token.json()['access_token']}"}).json() == {"id": 1}
    assert client.get("/whoami", headers={"Authorization": f"Bearer {token.json()['access_token']}"}).json() == {"id": 1}
    assert SyncUser.loop_calls and not any(SyncUser.loop_calls)


def test_passport_flow_is_unchanged():
    client, _ = build()
    bad = client.post("/oauth/token", data={"grant_type": "password", "username": "ada@example.com", "password": "x"})
    assert (bad.status_code, bad.json()["error"]) == (400, "invalid_grant")
    issued = client.post("/oauth/token", data={"grant_type": "password", "username": "ada@example.com", "password": "secret"})
    assert issued.status_code == 200
    body = issued.json()
    assert client.get("/me").status_code == 401
    assert client.get("/whoami").json() == {"id": None}
    refreshed = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"]})
    assert refreshed.status_code == 200
    assert client.get("/me", headers={"Authorization": f"Bearer {body['access_token']}"}).status_code == 401
    replay = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"]})
    assert replay.json()["error"] == "invalid_grant"


def test_session_flow_with_sync_store_is_unchanged():
    client, _ = build(default_guard="web")
    assert client.get("/me").status_code == 401
    assert client.post("/login", json={"email": "ada@example.com", "password": "bad"}).status_code == 401
    assert client.post("/login", json={"email": "ada@example.com", "password": "secret"}).status_code == 200
    assert client.get("/me").json() == {"id": 1}
    assert client.post("/logout").status_code == 200
    assert client.get("/me").status_code == 401


def test_token_guard_with_sync_repository_is_unchanged():
    client, manager = build(default_guard="tokens")
    issued = manager.api_tokens.create(1, name="cli")
    assert client.get("/me", headers={"Authorization": f"Bearer {issued.plain_text}"}).json() == {"id": 1}
    assert manager.api_tokens.revoke(issued.record.id) is True
    assert client.get("/me", headers={"Authorization": f"Bearer {issued.plain_text}"}).status_code == 401


def test_password_reset_with_sync_provider_is_unchanged():
    sent = []
    client, _ = build(sent=sent)
    assert client.post("/password/email", json={"email": "ada@example.com"}).status_code == 200
    [(email, token)] = sent
    assert client.post("/password/reset", json={"email": email, "token": token, "password": "new-one"}).status_code == 200
    ok = client.post("/oauth/token", data={"grant_type": "password", "username": email, "password": "new-one"})
    assert ok.status_code == 200
