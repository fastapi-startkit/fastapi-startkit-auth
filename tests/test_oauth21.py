import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI

from fastapi_startkit_auth import AsyncAuth

from conftest import BrowserTestClient as TestClient
from conftest import oauth2_config, register_auth
from test_session_auth import session_config

VERIFIER = "oauth21-verifier-" + "a" * 48
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
REDIRECT = "https://client.example/callback?application=demo"


@pytest.fixture
def server():
    api = FastAPI()
    manager = register_auth(
        api,
        session_config(),
        session={},
        oauth2=oauth2_config(scopes={"read": "Read resources", "write": "Update resources"}, default_scopes=["read"]),
    )

    @api.post("/login")
    async def login():
        await AsyncAuth.login(1)
        return {"authenticated": True}

    client = TestClient(api, base_url="https://server.example")
    client.post("/login")
    return client, manager


def register(manager, confidential=False, grants=None):
    return manager.client_repository.register(
        name="demo",
        confidential=confidential,
        redirect_uris=[REDIRECT],
        grant_types=grants or ["authorization_code", "refresh_token", "client_credentials"],
    )


def authorization(client_id, **overrides):
    return {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "state": "csrf-state",
        "approved": True,
        **overrides,
    }


def exchange(client, registration, **overrides):
    application, secret = registration
    body = client.post("/oauth/authorize", json=authorization(application.id)).json()
    data = {
        "grant_type": "authorization_code",
        "client_id": application.id,
        "code": body["code"],
        "code_verifier": VERIFIER,
        "redirect_uri": REDIRECT,
    }
    if secret is not None:
        data["client_secret"] = secret
    return client.post("/oauth/token", data={**data, **overrides})


@pytest.mark.parametrize("confidential", [False, True])
def test_authorization_code_pkce_and_refresh(server, confidential):
    client, manager = server
    registration = register(manager, confidential=confidential)
    application, secret = registration
    request = authorization(application.id)
    preview = client.get("/oauth/authorize", params={key: value for key, value in request.items() if key != "approved"})
    assert preview.status_code == 200
    assert preview.json()["requires_approval"] is True
    assert preview.json()["scope"] == "read"
    assert "code" not in preview.json()
    approved = client.post("/oauth/authorize", json=request).json()
    redirect = urlsplit(approved["redirect_to"])
    assert parse_qs(redirect.query) == {
        "application": ["demo"],
        "code": [approved["code"]],
        "state": ["csrf-state"],
        "iss": ["https://server.example"],
    }
    data = {
        "grant_type": "authorization_code",
        "client_id": application.id,
        "code": approved["code"],
        "code_verifier": VERIFIER,
        "redirect_uri": REDIRECT,
    }
    if secret:
        data["client_secret"] = secret
    issued = client.post("/oauth/token", data=data)
    assert issued.status_code == 200
    assert issued.headers["cache-control"] == "no-store"
    assert issued.headers["pragma"] == "no-cache"
    assert issued.json()["scope"] == "read"
    claims = manager.token_service.authenticate(issued.json()["access_token"])
    assert claims["sub"] == "1"
    assert claims["client_id"] == application.id
    assert client.post("/oauth/token", data=data).json()["error"] == "invalid_grant"
    refresh = {
        "grant_type": "refresh_token",
        "client_id": application.id,
        "refresh_token": issued.json()["refresh_token"],
    }
    if secret:
        refresh["client_secret"] = secret
    rotated = client.post("/oauth/token", data=refresh)
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != issued.json()["refresh_token"]
    assert client.post("/oauth/token", data=refresh).json()["error"] == "invalid_grant"
    descendant = {**refresh, "refresh_token": rotated.json()["refresh_token"]}
    assert client.post("/oauth/token", data=descendant).json()["error"] == "invalid_grant"
    assert manager.token_service.introspect(rotated.json()["access_token"]) == {"active": False}


@pytest.mark.parametrize("confidential", [False, True])
@pytest.mark.parametrize(
    "overrides",
    [
        {"code_challenge": None},
        {"code_challenge_method": "plain"},
        {"code_challenge": "short"},
        {"redirect_uri": None},
        {"redirect_uri": "https://attacker.example/callback"},
    ],
)
def test_invalid_authorization_requests_are_rejected(server, confidential, overrides):
    client, manager = server
    application, _ = register(manager, confidential=confidential)
    response = client.post("/oauth/authorize", json=authorization(application.id, **overrides))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_authorization_requires_approval(server):
    client, manager = server
    application, _ = register(manager)
    response = client.post("/oauth/authorize", json=authorization(application.id, approved=False))
    assert response.json()["error"] == "access_denied"
    assert manager.token_repository._codes == {}


@pytest.mark.parametrize("verifier", [None, "short", "wrong" * 12, "!" * 64])
def test_exchange_requires_valid_pkce(server, verifier):
    client, manager = server
    response = exchange(client, register(manager), code_verifier=verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_confidential_client_must_authenticate(server):
    client, manager = server
    response = exchange(client, register(manager, confidential=True), client_secret="wrong")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_public_client_cannot_use_client_credentials(server):
    client, manager = server
    application, _ = register(manager)
    response = client.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": application.id})
    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"


def test_client_credentials_supports_basic_auth_and_default_scopes(server):
    client, manager = server
    application, secret = register(manager, confidential=True)
    response = client.post("/oauth/token", data={"grant_type": "client_credentials"}, auth=(application.id, secret))
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "read"
    assert "refresh_token" not in body
    assert manager.token_service.authenticate(body["access_token"])["sub"] is None


def test_refresh_is_bound_to_the_issuing_client(server):
    client, manager = server
    first = register(manager)
    second, _ = register(manager)
    issued = exchange(client, first).json()
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": second.id,
            "refresh_token": issued["refresh_token"],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    legitimate = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": first[0].id,
            "refresh_token": issued["refresh_token"],
        },
    )
    assert legitimate.status_code == 200


def test_refresh_requires_client_identification(server):
    client, manager = server
    issued = exchange(client, register(manager)).json()
    response = client.post(
        "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": issued["refresh_token"]}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_refresh_can_narrow_but_cannot_expand_scopes(server):
    client, manager = server
    application, _ = register(manager)
    code = client.post("/oauth/authorize", json=authorization(application.id, scope="read write")).json()["code"]
    issued = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": application.id,
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": REDIRECT,
        },
    ).json()
    refresh = {"grant_type": "refresh_token", "client_id": application.id, "refresh_token": issued["refresh_token"]}
    narrowed = client.post("/oauth/token", data={**refresh, "scope": "read"}).json()
    assert narrowed["scope"] == "read"
    refresh["refresh_token"] = narrowed["refresh_token"]
    expanded = client.post("/oauth/token", data={**refresh, "scope": "read write"})
    assert expanded.json()["error"] == "invalid_grant"
    assert client.post("/oauth/token", data=refresh).status_code == 200


def test_grant_permissions_apply_to_public_clients(server):
    client, manager = server
    application, _ = register(manager, grants=["client_credentials"])
    response = client.post("/oauth/authorize", json=authorization(application.id))
    assert response.json()["error"] == "unauthorized_client"


def test_unknown_scopes_are_rejected(server):
    client, manager = server
    application, secret = register(manager, confidential=True)
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "scope": "admin",
        },
        auth=(application.id, secret),
    )
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.parametrize("grant", ["password", "implicit", "made_up"])
def test_removed_and_unknown_grants_are_rejected(server, grant):
    client, _ = server
    response = client.post("/oauth/token", data={"grant_type": grant})
    assert response.json()["error"] == "unsupported_grant_type"


def test_implicit_response_type_is_rejected(server):
    client, manager = server
    application, _ = register(manager)
    response = client.post("/oauth/authorize", json=authorization(application.id, response_type="token"))
    assert response.json()["error"] == "unsupported_response_type"


def test_discovery_reports_oauth21_capabilities(server):
    client, _ = server
    response = client.get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    body = response.json()
    assert body["issuer"] == "https://server.example"
    assert body["token_endpoint"] == "https://server.example/oauth/token"
    assert body["grant_types_supported"] == ["authorization_code", "client_credentials", "refresh_token"]
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["authorization_response_iss_parameter_supported"] is True
    assert body["scopes_supported"] == ["read", "write"]


def test_pkce_method_must_be_explicit(server):
    client, manager = server
    application, _ = register(manager)
    request = authorization(application.id)
    request.pop("code_challenge_method")
    response = client.post("/oauth/authorize", json=request)
    assert response.json()["error"] == "invalid_request"


def test_revoked_client_cannot_exchange_existing_code(server):
    client, manager = server
    application, _ = register(manager)
    code = client.post("/oauth/authorize", json=authorization(application.id)).json()["code"]
    application.revoked = True
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": application.id,
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": REDIRECT,
        },
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_code_exchange_rechecks_grant_permissions(server):
    client, manager = server
    application, _ = register(manager)
    code = client.post("/oauth/authorize", json=authorization(application.id)).json()["code"]
    application.grant_types = ["refresh_token"]
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": application.id,
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": REDIRECT,
        },
    )
    assert response.json()["error"] == "unauthorized_client"


def test_confidential_refresh_rejects_missing_secret(server):
    client, manager = server
    registration = register(manager, confidential=True)
    issued = exchange(client, registration).json()
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": registration[0].id,
            "refresh_token": issued["refresh_token"],
        },
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Basic"


@pytest.mark.parametrize("header", ["Basic ***", "Basic bm9jb2xvbg=="])
def test_malformed_basic_authentication_is_rejected(server, header):
    client, _ = server
    response = client.post("/oauth/token", data={"grant_type": "client_credentials"}, headers={"Authorization": header})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_concurrent_refresh_cannot_issue_two_valid_token_chains(server):
    from concurrent.futures import ThreadPoolExecutor
    from fastapi_startkit_auth.exceptions import InvalidGrant

    _, manager = server
    original = manager.token_service.issue(user_id=1, client_id="concurrent", scopes=["read"], with_refresh=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = [pool.submit(manager.token_service.refresh, original.refresh_token) for _ in range(2)]
    issued = [attempt.result() for attempt in attempts if attempt.exception() is None]
    errors = [attempt.exception() for attempt in attempts if attempt.exception() is not None]
    assert len(issued) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], InvalidGrant)
    assert manager.token_service.introspect(issued[0].access_token) == {"active": False}


def test_user_token_listing_does_not_expose_secrets_or_other_users(server):
    client, manager = server
    registration = register(manager)
    issued = exchange(client, registration).json()
    own_jti = manager.token_service.authenticate(issued["access_token"])["jti"]
    manager.token_service.issue(user_id=2, client_id=registration[0].id, scopes=["read"], with_refresh=True)
    manager.token_service.create_personal_access_token(user_id=1, name="personal", scopes=["read"])
    response = client.get("/oauth/tokens")
    assert response.status_code == 200
    assert [record["jti"] for record in response.json()] == [own_jti]
    record = response.json()[0]
    assert record["client_id"] == registration[0].id
    assert record["active"] is True
    assert record["expires_at"] > record["created_at"]
    assert issued["access_token"] not in response.text
    assert issued["refresh_token"] not in response.text


def test_owner_revocation_invalidates_access_and_refresh(server):
    client, manager = server
    registration = register(manager)
    issued = exchange(client, registration).json()
    jti = manager.token_service.authenticate(issued["access_token"])["jti"]
    assert client.delete(f"/oauth/tokens/{jti}").status_code == 204
    assert manager.token_service.introspect(issued["access_token"]) == {"active": False}
    assert manager.token_service.introspect(issued["refresh_token"]) == {"active": False}
    assert client.get("/oauth/tokens").json() == []
    assert client.delete(f"/oauth/tokens/{jti}").status_code == 204


def test_token_management_cannot_revoke_another_users_tokens(server):
    client, manager = server
    foreign = manager.token_service.issue(user_id=2, client_id="foreign", scopes=["read"], with_refresh=True)
    assert client.delete(f"/oauth/tokens/{foreign.jti}").status_code == 204
    assert manager.token_service.introspect(foreign.access_token)["active"] is True
    assert manager.token_service.introspect(foreign.refresh_token)["active"] is True


def test_bulk_revocation_preserves_other_users_and_personal_tokens(server):
    client, manager = server
    first = manager.token_service.issue(user_id=1, client_id="first", scopes=["read"], with_refresh=True)
    second = manager.token_service.issue(user_id=1, client_id="second", scopes=["write"], with_refresh=True)
    foreign = manager.token_service.issue(user_id=2, client_id="foreign", scopes=["read"], with_refresh=True)
    personal = manager.token_service.create_personal_access_token(user_id=1, name="personal", scopes=["read"])
    assert client.delete("/oauth/tokens").status_code == 204
    for token in [first, second]:
        assert manager.token_service.introspect(token.access_token) == {"active": False}
        assert manager.token_service.introspect(token.refresh_token) == {"active": False}
    assert manager.token_service.introspect(foreign.access_token)["active"] is True
    assert manager.token_service.introspect(personal.access_token)["active"] is True


def test_expired_access_token_can_still_revoke_its_refresh_chain(server):
    import time

    client, manager = server
    issued = manager.token_service.issue(user_id=1, client_id="first", scopes=["read"], with_refresh=True)
    manager.token_repository.find_access_token(issued.jti).expires_at = time.time() - 1
    manager.token_repository.purge_expired()
    listed = client.get("/oauth/tokens").json()
    assert listed[0]["jti"] == issued.jti
    assert listed[0]["active"] is False
    assert client.delete(f"/oauth/tokens/{issued.jti}").status_code == 204
    assert manager.token_service.introspect(issued.refresh_token) == {"active": False}


@pytest.mark.parametrize("token_kind", ["access_token", "refresh_token"])
def test_client_revocation_rejects_foreign_token_ownership(server, token_kind):
    client, manager = server
    owner = register(manager, confidential=True)
    foreign, foreign_secret = register(manager, confidential=True)
    issued = exchange(client, owner).json()
    response = client.post("/oauth/revoke", data={"token": issued[token_kind]}, auth=(foreign.id, foreign_secret))
    assert response.status_code == 200
    assert manager.token_service.introspect(issued["access_token"])["active"] is True
    assert manager.token_service.introspect(issued["refresh_token"])["active"] is True
    response = client.post("/oauth/revoke", data={"token": issued[token_kind]}, auth=(owner[0].id, owner[1]))
    assert response.status_code == 200
    assert manager.token_service.introspect(issued["access_token"]) == {"active": False}
    assert manager.token_service.introspect(issued["refresh_token"]) == {"active": False}


def test_refresh_token_introspection_requires_confidential_client_authentication(server):
    client, manager = server
    registration = register(manager, confidential=True)
    issued = exchange(client, registration).json()
    response = client.post(
        "/oauth/introspect", data={"token": issued["refresh_token"]}, auth=(registration[0].id, registration[1])
    )
    assert response.status_code == 200
    body = response.json()
    assert body["active"] is True
    assert body["token_type"] == "refresh_token"
    assert body["client_id"] == registration[0].id
    assert body["scope"] == "read"
    assert issued["refresh_token"] not in response.text
    public, _ = register(manager)
    response = client.post("/oauth/introspect", data={"token": issued["refresh_token"], "client_id": public.id})
    assert response.status_code == 401


def test_revocation_ignores_wrong_hints_and_unknown_tokens(server):
    client, manager = server
    registration = register(manager, confidential=True)
    issued = exchange(client, registration).json()
    credentials = (registration[0].id, registration[1])
    response = client.post(
        "/oauth/revoke", data={"token": issued["access_token"], "token_type_hint": "refresh_token"}, auth=credentials
    )
    assert response.status_code == 200
    assert manager.token_service.introspect(issued["access_token"]) == {"active": False}
    assert client.post("/oauth/revoke", data={"token": "unknown"}, auth=credentials).status_code == 200


@pytest.mark.parametrize(
    "method,path", [("GET", "/oauth/tokens"), ("DELETE", "/oauth/tokens"), ("DELETE", "/oauth/tokens/missing")]
)
def test_token_management_requires_authentication(server, method, path):
    client, _ = server
    client.cookies.clear()
    assert client.request(method, path).status_code == 401


def test_personal_token_management_supports_defaults_expiry_and_bulk_revocation(server):
    client, manager = server
    response = client.post("/oauth/personal-access-tokens", json={"name": "cli", "ttl": 60})
    assert response.status_code == 201
    body = response.json()
    assert body["scopes"] == ["read"]
    assert body["expires_in"] == 60
    oauth = manager.token_service.issue(user_id=1, client_id="oauth", scopes=["read"], with_refresh=True)
    foreign = manager.token_service.create_personal_access_token(user_id=2, name="other", scopes=["read"])
    listed = client.get("/oauth/personal-access-tokens")
    assert len(listed.json()) == 1
    assert listed.json()[0]["expires_at"] > listed.json()[0]["created_at"]
    assert body["access_token"] not in listed.text
    assert client.delete("/oauth/personal-access-tokens").status_code == 204
    assert manager.token_service.introspect(body["access_token"]) == {"active": False}
    assert manager.token_service.introspect(oauth.access_token)["active"] is True
    assert manager.token_service.introspect(foreign.access_token)["active"] is True


def test_personal_token_revocation_cannot_revoke_an_oauth_token(server):
    client, manager = server
    oauth = manager.token_service.issue(user_id=1, client_id="oauth", scopes=["read"], with_refresh=True)
    assert client.delete(f"/oauth/personal-access-tokens/{oauth.jti}").status_code == 204
    assert manager.token_service.introspect(oauth.access_token)["active"] is True


@pytest.mark.parametrize("ttl", [0, -1])
def test_personal_tokens_reject_invalid_lifetimes(server, ttl):
    client, _ = server
    assert client.post("/oauth/personal-access-tokens", json={"name": "cli", "ttl": ttl}).status_code == 422


def test_client_authenticated_endpoints_skip_session_csrf(server):
    client, manager = server
    registration = register(manager, confidential=True)
    application, secret = registration
    from fastapi.testclient import TestClient as PlainTestClient

    plain = PlainTestClient(client.app, base_url="https://server.example", cookies=client.cookies)
    response = plain.post(
        "/oauth/token", data={"grant_type": "client_credentials"}, auth=(application.id, secret)
    )
    assert response.status_code == 200
    assert plain.post("/oauth/authorize", json=authorization(application.id)).status_code == 403
