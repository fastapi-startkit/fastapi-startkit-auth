"""Phase 1 cookie/session authentication: guard, facade, middleware, security.

The integration tests run over HTTPS (TestClient base_url) so Secure cookies
round-trip, and are parametrized over BOTH session stores. The package ships no
login/logout routes — the app-style routes wired here are the consuming app's
responsibility, exactly as documented.
"""
import warnings

import pytest
from fastapi import Body, Depends, FastAPI, Request

from fastapi_startkit_auth import (
    Auth,
    AuthConfig,
    InvalidSession,
    current_user,
    optional_user,
)
from fastapi_startkit_auth.guards import Guard, PassportGuard, SessionGuard
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth import AuthMiddleware
from fastapi_startkit_auth.sessions import InMemorySessionStore

from conftest import BrowserTestClient, auth_manager, oauth2_config, register_auth

COOKIE = "startkit_session"

USERS = (
    {"id": 1, "email": "ada@example.com", "password": "secret"},
    {"id": 2, "email": "grace@example.com", "password": "hopper"},
)


def seeded_provider(users=USERS):
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    for user in users:
        row = dict(user)
        row["password"] = hasher.make(row["password"])
        provider.add(row)
    return provider


def session_config(guards=None, default_guard="web"):
    provider = seeded_provider()

    class Config(AuthConfig):
        bcrypt_rounds = 4
        default = {"guard": default_guard, "passwords": "users"}
        providers = {"users": {"driver": "instance", "instance": provider}}

    Config.guards = guards or {"web": {"driver": "session", "provider": "users"}}
    return Config


def wire_routes(api):
    @api.post("/login")
    def login(payload: dict = Body(...), auth: Auth = Depends(Auth.scoped)):
        if not auth.attempt(payload):
            raise InvalidSession("Invalid credentials.")
        return {"ok": True}

    @api.post("/login-as/{user_id}")
    def login_as(user_id: int, auth: Auth = Depends(Auth.scoped)):
        record = auth.login(user_id)
        return {"session_id": record.id}

    @api.post("/logout")
    def logout(auth: Auth = Depends(Auth.scoped)):
        auth.logout()
        return {"ok": True}

    @api.get("/me")
    def me(user=Depends(current_user)):
        return user

    @api.get("/whoami")
    def whoami(user=Depends(optional_user)):
        return {"id": user["id"] if user else None}

    @api.get("/status")
    def status(auth: Auth = Depends(Auth.scoped)):
        return {"check": auth.check(), "id": auth.id()}


def make_client(session=None, guards=None):
    api = FastAPI()
    register_auth(api, session_config(guards=guards), session=session or {}, oauth2=oauth2_config())
    wire_routes(api)
    return BrowserTestClient(api, base_url="https://testserver")


@pytest.fixture
def client():
    return make_client()


def set_cookie_header(response, name=COOKIE):
    return next((header for header in response.headers.get_list("set-cookie") if header.startswith(f"{name}=")), "")


# --- login / logout round trip (both stores) --------------------------


def test_unauthenticated_request_is_rejected(client):
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_session"


def test_attempt_logs_in_and_cookie_authenticates(client):
    response = client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    assert response.status_code == 200
    assert client.cookies.get(COOKIE)

    me = client.get("/me")
    assert me.status_code == 200
    assert me.json()["id"] == 1


def test_attempt_failure_is_generic_and_sets_no_cookie(client):
    wrong_password = client.post("/login", json={"email": "ada@example.com", "password": "nope"})
    unknown_user = client.post("/login", json={"email": "ghost@example.com", "password": "nope"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    # Same body for wrong password and unknown user: no user enumeration.
    assert wrong_password.json() == unknown_user.json()
    assert COOKIE not in wrong_password.headers.get("set-cookie", "")
    assert client.cookies.get(COOKIE) is None


def test_login_by_id(client):
    client.post("/login-as/2")
    assert client.get("/me").json()["id"] == 2


def test_logout_invalidates_server_side_session(client):
    client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    session_id = client.cookies.get(COOKIE)

    logout = client.post("/logout")
    assert "Max-Age=0" in set_cookie_header(logout) or "max-age=0" in set_cookie_header(logout)
    assert client.get("/me").status_code == 401

    # Replaying the pre-logout cookie must fail: the record is gone server-side.
    replay = client.get("/me", headers={"cookie": f"{COOKIE}={session_id}"})
    assert replay.status_code == 401


def test_optional_user_and_facade_accessors(client):
    assert client.get("/whoami").json() == {"id": None}
    assert client.get("/status").json() == {"check": False, "id": None}

    client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    assert client.get("/whoami").json() == {"id": 1}
    assert client.get("/status").json() == {"check": True, "id": 1}


# --- session fixation -------------------------------------------------


def test_login_ignores_and_replaces_a_fixed_cookie(client):
    client.cookies.set(COOKIE, "attacker-fixed-session-id", domain="testserver.local")
    client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    new_id = client.cookies.get(COOKIE)
    assert new_id != "attacker-fixed-session-id"
    assert client.get("/me").status_code == 200


def test_relogin_regenerates_id_and_kills_the_old_session(client):
    client.post("/login-as/1")
    first_id = client.cookies.get(COOKIE)
    client.post("/login-as/2")
    second_id = client.cookies.get(COOKIE)

    assert first_id != second_id
    assert client.get("/me").json()["id"] == 2
    replay = client.get("/me", headers={"cookie": f"{COOKIE}={first_id}"})
    assert replay.status_code == 401


def test_stale_cookie_is_deleted_on_response():
    client = make_client()
    response = client.get("/me", headers={"cookie": f"{COOKIE}=long-gone-session"})
    assert response.status_code == 401
    header = set_cookie_header(response)
    assert COOKIE in header and ("Max-Age=0" in header or "max-age=0" in header)


# --- cookie flags -----------------------------------------------------


def test_default_cookie_flags():
    client = make_client()
    response = client.post("/login-as/1")
    header = set_cookie_header(response).lower()
    assert "httponly" in header
    assert "samesite=lax" in header
    assert "secure" in header
    assert "path=/" in header
    assert "max-age=7200" in header


def test_cookie_flags_are_configurable():
    with pytest.warns(UserWarning, match="secure"):
        client = make_client(
            session={"secure": False, "same_site": "strict", "cookie": "sid", "ttl": 60}
        )
    response = client.post("/login-as/1")
    header = set_cookie_header(response, "sid").lower()
    assert header
    assert "secure" not in header
    assert "samesite=strict" in header
    assert "max-age=60" in header


def test_no_cookie_issued_without_session_activity(client):
    response = client.get("/whoami")
    assert "set-cookie" not in response.headers


# --- guard resolution -------------------------------------------------


def _manager(session=None, guards=None, default_guard="web"):
    return auth_manager(
        session_config(guards=guards, default_guard=default_guard), session=session or {}, oauth2=oauth2_config()
    )


def test_session_driver_resolves_through_registry():
    guard = _manager().guard("web")
    assert isinstance(guard, SessionGuard)
    assert isinstance(guard, Guard)
    assert guard.name == "web"


def test_session_guard_resolves_user_from_session_id():
    manager = _manager()
    guard = manager.guard("web")
    record = manager.session_store.create(user_id=1, guard="web", ttl=60)
    context = guard.user_from_token(record.id)
    assert context.user["id"] == 1
    assert context.scopes == ["*"]
    with pytest.raises(InvalidSession):
        guard.user_from_token("unknown-session-id")


def test_session_and_passport_guards_coexist():
    manager = _manager(
        guards={
            "api": {"driver": "passport", "provider": "users"},
            "web": {"driver": "session", "provider": "users"},
        },
        default_guard="api",
    )
    assert isinstance(manager.guard("api"), PassportGuard)
    assert isinstance(manager.guard("web"), SessionGuard)
    assert manager.has_session_guard()


def test_manager_without_session_guard_adds_only_the_auth_middleware():
    provider = seeded_provider()

    class Config(AuthConfig):
        bcrypt_rounds = 4
        default = {"guard": "api", "passwords": "users"}
        guards = {"api": {"driver": "passport", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": provider}}

    api = FastAPI()
    manager = register_auth(api, Config, oauth2=oauth2_config())
    assert not manager.has_session_guard()
    assert [middleware.cls for middleware in api.user_middleware] == [AuthMiddleware]


def test_session_store_config_selects_implementation():
    assert isinstance(_manager().session_store, InMemorySessionStore)
    custom = InMemorySessionStore()
    manager = _manager(session={"store": "instance", "instance": custom})
    assert manager.session_store is custom
    with pytest.raises(ValueError, match="Unknown session store"):
        _manager(session={"store": "redis"}).session_store
    with pytest.raises(ValueError, match='"database"'):
        _manager(session={"store": "sql"}).session_store


# --- facade unit behaviour --------------------------------------------


def make_request():
    return Request({"type": "http", "headers": [], "query_string": b"", "state": {}})


@pytest.fixture
def auth():
    manager = _manager()
    return Auth(manager, make_request()), manager


def test_facade_login_and_logout_manage_the_store(auth):
    facade, manager = auth
    record = facade.login(1)
    assert manager.session_store.find(record.id) is not None
    assert facade.check() is True
    assert facade.id() == 1
    assert facade.user()["email"] == "ada@example.com"

    facade.logout()
    assert manager.session_store.find(record.id) is None
    assert facade.check() is False
    assert facade.user() is None


def test_facade_login_regenerates_session_id(auth):
    facade, manager = auth
    first = facade.login(1)
    first_id = first.id
    second = facade.login(1)
    assert second.id != first_id
    assert manager.session_store.find(first_id) is None
    assert manager.session_store.find(second.id) is not None


def test_facade_attempt_validates_credentials(auth):
    facade, _ = auth
    assert facade.attempt({"email": "ada@example.com", "password": "wrong"}) is False
    assert facade.check() is False
    assert facade.attempt({"email": "ada@example.com", "password": "secret"}) is True
    assert facade.id() == 1


def test_facade_login_rejects_unknown_user_id(auth):
    facade, _ = auth
    with pytest.raises(ValueError, match="No user with id 999"):
        facade.login(999)


def test_facade_login_requires_a_session_guard():
    manager = _manager(
        guards={"api": {"driver": "passport", "provider": "users"}}, default_guard="api"
    )
    facade = Auth(manager, make_request())
    with pytest.raises(RuntimeError, match="not a session guard"):
        facade.login(1)


def test_secure_default_emits_no_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        _manager()
