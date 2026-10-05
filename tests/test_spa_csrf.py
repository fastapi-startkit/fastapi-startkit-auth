import pytest
from fastapi import Body, Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_startkit_auth import (
    ApiToken,
    AsyncAuth,
    AuthConfig,
    InvalidSession,
    current_user,
)
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

from conftest import register_auth

SPA_ORIGIN = "https://app.example.com"
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


def spa_config(default_guard="web"):
    provider = seeded_provider()

    class Config(AuthConfig):
        bcrypt_rounds = 4
        default = {"guard": default_guard, "passwords": "users"}
        guards = {
            "web": {"driver": "session", "provider": "users"},
            "api": {"driver": "token", "provider": "users"},
        }
        providers = {"users": {"driver": "instance", "instance": provider}}

    return Config


def wire_routes(api):
    @api.post("/login")
    async def login(payload: dict = Body(...), auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        if not await auth.attempt(payload):
            raise InvalidSession("Invalid credentials.")
        return {"ok": True}

    @api.post("/logout")
    async def logout(auth: AsyncAuth = Depends(AsyncAuth.scoped)):
        await auth.logout()
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

    @api.post("/form")
    async def form(request: Request):
        return {"name": (await request.form()).get("name")}

    @api.post("/tokens")
    async def issue_token(user=Depends(current_user)):
        return {"token": (await ApiToken.create(user, name="cli")).plain_text}


def make_client(session=None, stateful_origins=(SPA_ORIGIN,), default_guard="web"):
    api = FastAPI()
    api_tokens = {"stateful_origins": list(stateful_origins or [])}
    register_auth(api, spa_config(default_guard), session=session or {}, api_tokens=api_tokens)
    wire_routes(api)
    return TestClient(api, base_url="https://testserver")


@pytest.fixture
def client():
    return make_client()


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


def test_csrf_cookie_endpoint_is_never_cached(client):
    response = client.get("/__auth__/csrf-cookie")
    assert response.headers.get("cache-control") == "no-store"


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
    client = make_client(session={"csrf_exempt_paths": ["/webhook", "/hooks/*"]})
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
    client = make_client(session={"csrf_cookie": "MY-CSRF", "csrf_header": "X-MY-CSRF"})
    client.get("/__auth__/csrf-cookie")
    token = client.cookies.get("MY-CSRF")
    assert token
    login = {"email": "ada@example.com", "password": "secret"}
    assert client.post("/login", json=login).status_code == 403
    assert client.post("/login", json=login, headers={"X-MY-CSRF": token}).status_code == 200


# --- stateful origins (defense in depth) --------------------------------


def test_foreign_origin_is_rejected_even_with_a_valid_token():
    client = make_client()
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


def test_requests_without_an_origin_header_rely_on_the_token(client):
    client.get("/__auth__/csrf-cookie")
    response = client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200


# --- Sanctum-style stateful token guard ----------------------------------


def test_token_guard_accepts_the_spa_session_and_bearer_tokens():
    client = make_client(default_guard="api")
    client.get("/__auth__/csrf-cookie")
    client.post(
        "/login",
        json={"email": "ada@example.com", "password": "secret"},
        headers=csrf_headers(client),
    )
    assert client.get("/me").json()["id"] == 1

    token = client.post("/tokens", headers=csrf_headers(client)).json()["token"]
    mobile = TestClient(client.app, base_url="https://testserver")
    assert mobile.get("/me", headers={"Authorization": f"Bearer {token}"}).json()["id"] == 1
    assert mobile.get("/me").status_code == 401


def test_token_guard_without_stateful_origins_ignores_the_session():
    client = make_client(stateful_origins=None, default_guard="api")
    client.post("/login", json={"email": "ada@example.com", "password": "secret"}, headers={})
    assert client.cookies.get(SESSION_COOKIE)
    assert client.get("/me").status_code == 401


# --- sessions without SPA mode (Jinja / Inertia) -----------------------------


def test_session_only_apps_have_no_csrf_cookie_route_but_enforce_csrf():
    client = make_client(stateful_origins=None)

    assert client.get("/__auth__/csrf-cookie").status_code == 404
    client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    assert client.cookies.get(CSRF_COOKIE)
    assert client.post("/mutate").status_code == 403
    assert client.post("/mutate", headers=csrf_headers(client)).status_code == 200


def test_form_posts_may_send_the_token_as_a_field(client):
    client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    token = client.cookies.get(CSRF_COOKIE)

    assert client.post("/form", data={"name": "ada"}).status_code == 403
    assert client.post("/form", data={"name": "ada", "_token": "wrong"}).status_code == 403
    accepted = client.post("/form", data={"name": "ada", "_token": token})
    assert accepted.status_code == 200
    assert accepted.json() == {"name": "ada"}


def test_multipart_posts_may_send_the_token_as_a_field(client):
    client.post("/login", json={"email": "ada@example.com", "password": "secret"})
    token = client.cookies.get(CSRF_COOKIE)

    response = client.post("/form", data={"name": "grace", "_token": token}, files={"upload": ("a.txt", b"hi")})
    assert response.status_code == 200
    assert response.json() == {"name": "grace"}


def test_spa_mode_requires_the_session_provider():
    from fastapi_startkit_auth import FeatureNotRegistered

    class Config(AuthConfig):
        guards = {"api": {"driver": "token", "provider": "users"}}
        default = {"guard": "api", "passwords": "users"}
        providers = {"users": {"driver": "instance", "instance": seeded_provider()}}

    with pytest.raises(FeatureNotRegistered, match="AuthSessionProvider"):
        register_auth(FastAPI(), Config, api_tokens={"stateful_origins": [SPA_ORIGIN]})
