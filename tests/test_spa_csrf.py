"""Phase 2 SPA authentication: csrf-cookie endpoint + double-submit middleware.

Runs the axios-shaped flow over HTTPS (Secure cookies) against both session
stores. The SPA mode is opt-in (``AuthConfig.spa["enabled"]``): the plain
Phase 1 cookie flow must keep working untouched when it is off.
"""
import sqlite3

import pytest
from fastapi import Body, Depends
from fastapi.testclient import TestClient

from fastapi_startkit_auth import (
    Application,
    Auth,
    AuthConfig,
    AuthProvider,
    InvalidSession,
    current_user,
)
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

SESSION_COOKIE = "startkit_session"
CSRF_COOKIE = "XSRF-TOKEN"
CSRF_HEADER = "X-XSRF-TOKEN"

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


def spa_config(spa=None, session=None):
    provider = seeded_provider()

    class Config(AuthConfig):
        key = "spa-tests-secret-key-32-bytes-minimum!!"
        bcrypt_rounds = 4
        default = {"guard": "web", "passwords": "users"}
        guards = {"web": {"driver": "session", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": provider}}

    Config.session = session or {}
    Config.spa = {"enabled": True, **(spa or {})}
    return Config


def wire_routes(api):
    @api.post("/login")
    def login(payload: dict = Body(...), auth: Auth = Depends(Auth.scoped)):
        if not auth.attempt(payload):
            raise InvalidSession("Invalid credentials.")
        return {"ok": True}

    @api.post("/logout")
    def logout(auth: Auth = Depends(Auth.scoped)):
        auth.logout()
        return {"ok": True}

    @api.get("/me")
    def me(user=Depends(current_user)):
        return user

    @api.api_route("/mutate", methods=["POST", "PUT", "PATCH", "DELETE"])
    def mutate():
        return {"ok": True}

    @api.post("/webhook")
    def webhook():
        return {"ok": True}

    @api.post("/hooks/github")
    def github_hook():
        return {"ok": True}


def make_client(spa=None, session=None):
    application = Application([(AuthProvider, spa_config(spa=spa, session=session))])
    wire_routes(application.api)
    return TestClient(application.api, base_url="https://testserver")


SQL_SESSION = {
    "store": "sql",
    "connection": lambda: sqlite3.connect(":memory:", check_same_thread=False),
}


@pytest.fixture(params=["memory", "sql"])
def client(request):
    return make_client(session=SQL_SESSION if request.param == "sql" else None)


def csrf_headers(client):
    return {CSRF_HEADER: client.cookies.get(CSRF_COOKIE)}


def set_cookie_headers(response):
    return response.headers.get_list("set-cookie")


# --- /__auth__/csrf-cookie endpoint -----------------------------------


def test_csrf_cookie_endpoint_sets_both_cookies(client):
    response = client.get("/__auth__/csrf-cookie")
    assert response.status_code == 204

    headers = set_cookie_headers(response)
    session_header = next(h for h in headers if h.startswith(f"{SESSION_COOKIE}="))
    csrf_header = next(h for h in headers if h.startswith(f"{CSRF_COOKIE}="))
    assert "httponly" in session_header.lower()
    # The CSRF cookie must stay readable by the SPA's JS.
    assert "httponly" not in csrf_header.lower()
    assert "secure" in csrf_header.lower()
    assert "samesite=lax" in csrf_header.lower()
    assert client.cookies.get(CSRF_COOKIE)


def test_csrf_cookie_endpoint_reuses_the_live_session(client):
    client.get("/__auth__/csrf-cookie")
    session_id = client.cookies.get(SESSION_COOKIE)
    token = client.cookies.get(CSRF_COOKIE)

    again = client.get("/__auth__/csrf-cookie")
    assert again.status_code == 204
    assert set_cookie_headers(again) == []
    assert client.cookies.get(SESSION_COOKIE) == session_id
    assert client.cookies.get(CSRF_COOKIE) == token


def test_guest_session_is_not_authenticated_but_survives_401(client):
    client.get("/__auth__/csrf-cookie")
    assert client.get("/me").status_code == 401
    # The guest session must not be invalidated by the 401: the login that
    # follows still has its CSRF token.
    login = client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers=csrf_headers(client),
    )
    assert login.status_code == 200


# --- the axios flow ----------------------------------------------------


def test_full_spa_flow_with_rotation(client):
    client.get("/__auth__/csrf-cookie")
    pre_login_token = client.cookies.get(CSRF_COOKIE)

    no_header = client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    assert no_header.status_code == 403
    assert no_header.json()["error"] == "csrf_token_mismatch"

    ok = client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers={CSRF_HEADER: pre_login_token},
    )
    assert ok.status_code == 200
    assert client.get("/me").json()["id"] == 1

    # Login rotates the session and its CSRF token; the response re-set the
    # cookie and the stale pre-login token must be rejected.
    post_login_token = client.cookies.get(CSRF_COOKIE)
    assert post_login_token != pre_login_token
    stale = client.post("/logout", headers={CSRF_HEADER: pre_login_token})
    assert stale.status_code == 403

    out = client.post("/logout", headers={CSRF_HEADER: post_login_token})
    assert out.status_code == 200
    assert client.get("/me").status_code == 401


def test_logout_deletes_the_csrf_cookie(client):
    client.get("/__auth__/csrf-cookie")
    client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers=csrf_headers(client),
    )
    out = client.post("/logout", headers=csrf_headers(client))
    deletions = [h for h in set_cookie_headers(out) if h.startswith(f"{CSRF_COOKIE}=")]
    assert deletions and "max-age=0" in deletions[0].lower()


# --- enforcement and exemptions ----------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_unsafe_methods_require_the_token(client, method):
    client.get("/__auth__/csrf-cookie")
    client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers=csrf_headers(client),
    )
    missing = client.request(method, "/mutate")
    assert missing.status_code == 403
    wrong = client.request(method, "/mutate", headers={CSRF_HEADER: "not-the-token"})
    assert wrong.status_code == 403
    ok = client.request(method, "/mutate", headers=csrf_headers(client))
    assert ok.status_code == 200


def test_safe_methods_are_exempt(client):
    client.get("/__auth__/csrf-cookie")
    client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers=csrf_headers(client),
    )
    assert client.get("/me", headers={CSRF_HEADER: ""}).status_code == 200
    assert client.get("/me").status_code == 200


def test_requests_without_a_session_are_exempt(client):
    # Bearer/token clients carry no session cookie — no ambient credential, no
    # CSRF check. This also keeps the plain Phase 1 login flow working.
    assert client.post("/mutate").status_code == 200
    login = client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    assert login.status_code == 200


def test_exempt_paths_skip_the_token_check():
    client = make_client(spa={"csrf_exempt_paths": ["/webhook", "/hooks/*"]})
    client.get("/__auth__/csrf-cookie")
    client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers=csrf_headers(client),
    )
    assert client.post("/webhook").status_code == 200
    assert client.post("/hooks/github").status_code == 200
    assert client.post("/mutate").status_code == 403


def test_configurable_cookie_and_header_names():
    client = make_client(spa={"csrf_cookie": "MY-CSRF", "csrf_header": "X-MY-CSRF"})
    client.get("/__auth__/csrf-cookie")
    token = client.cookies.get("MY-CSRF")
    assert token
    login = {"email": "ada@example.com", "password": "secret"}
    assert client.post("/login", json=login).status_code == 403
    assert client.post("/login", json=login, headers={"X-MY-CSRF": token}).status_code == 200


# --- stateful origins (defense in depth) --------------------------------


def test_foreign_origin_is_rejected_even_with_a_valid_token():
    client = make_client(spa={"stateful_origins": ["https://app.example.com"]})
    client.get("/__auth__/csrf-cookie")
    login = {"email": "ada@example.com", "password": "secret"}

    foreign = client.post(
        "/login",
        json=login,
        headers={**csrf_headers(client), "Origin": "https://evil.example.com"},
    )
    assert foreign.status_code == 403

    allowed = client.post(
        "/login",
        json=login,
        headers={**csrf_headers(client), "Origin": "https://app.example.com"},
    )
    assert allowed.status_code == 200

    # The Origin gate does not replace the token check.
    bad_token = client.post(
        "/mutate",
        headers={CSRF_HEADER: "nope", "Origin": "https://app.example.com"},
    )
    assert bad_token.status_code == 403


def test_origin_check_disabled_when_no_stateful_origins(client):
    client.get("/__auth__/csrf-cookie")
    response = client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers={**csrf_headers(client), "Origin": "https://anywhere.example.com"},
    )
    assert response.status_code == 200


# --- opt-in gating ------------------------------------------------------


def test_spa_mode_is_off_by_default():
    provider = seeded_provider()

    class Config(AuthConfig):
        key = "spa-tests-secret-key-32-bytes-minimum!!"
        bcrypt_rounds = 4
        default = {"guard": "web", "passwords": "users"}
        guards = {"web": {"driver": "session", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": provider}}
        session = {}

    application = Application([(AuthProvider, Config)])
    wire_routes(application.api)
    client = TestClient(application.api, base_url="https://testserver")

    assert client.get("/__auth__/csrf-cookie").status_code == 404
    # Phase 1 behavior untouched: session-cookie requests need no CSRF header.
    client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    assert client.post("/mutate").status_code == 200
    assert client.post("/logout").status_code == 200
