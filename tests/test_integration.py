import base64
import hashlib


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def get_token(client, username="ada@example.com", password="secret", scope="read write"):
    resp = client.post("/oauth/token", data={
        "grant_type": "password", "username": username, "password": password, "scope": scope,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- password grant + protected routes ----------------------------------
def test_password_grant_returns_bearer_token(client):
    body = get_token(client)
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert "refresh_token" in body
    assert body["scope"] == "read write"


def test_password_grant_rejects_bad_credentials(client):
    resp = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "nope",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_simple_token_endpoint(client):
    resp = client.post("/token", data={"username": "ada@example.com", "password": "secret"})
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_protected_route_requires_token(client):
    assert client.get("/user").status_code == 401


def test_protected_route_with_token(client):
    token = get_token(client)["access_token"]
    resp = client.get("/user", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "ada@example.com"


def test_protected_route_rejects_garbage_token(client):
    resp = client.get("/user", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


# --- scope enforcement --------------------------------------------------
def test_scope_protected_route_allows_when_scope_present(client):
    token = get_token(client, scope="read")["access_token"]
    resp = client.get("/needs-read", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_scope_protected_route_forbids_when_scope_missing(client):
    token = get_token(client, scope="read")["access_token"]
    resp = client.get("/needs-admin", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "insufficient_scope"


# --- refresh rotation ---------------------------------------------------
def test_refresh_token_grant_rotates(client):
    body = get_token(client, scope="read")
    resp = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": body["refresh_token"],
    })
    assert resp.status_code == 200
    new_body = resp.json()
    assert new_body["access_token"] != body["access_token"]
    # old refresh token is now invalid
    reuse = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": body["refresh_token"],
    })
    assert reuse.status_code == 400


# --- clients + client credentials + auth code ---------------------------
def test_client_registration_and_client_credentials(client):
    reg = client.post("/oauth/clients", json={"name": "svc", "confidential": True,
                                              "grant_types": ["client_credentials"]})
    assert reg.status_code == 201
    data = reg.json()
    assert data["secret"]

    resp = client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": data["id"],
        "client_secret": data["secret"], "scope": "read",
    })
    assert resp.status_code == 200
    assert "refresh_token" not in resp.json()


def test_client_credentials_rejects_bad_secret(client):
    reg = client.post("/oauth/clients", json={"name": "svc", "confidential": True}).json()
    resp = client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": reg["id"], "client_secret": "wrong",
    })
    assert resp.status_code == 401


def test_authorization_code_flow_with_pkce(client):
    reg = client.post("/oauth/clients", json={
        "name": "spa", "confidential": False, "redirect_uris": ["https://spa.example/cb"],
    }).json()
    user_token = get_token(client)["access_token"]
    verifier = "verifier-verifier-verifier-verifier-1234567890"

    approve = client.post(
        "/oauth/authorize",
        json={
            "client_id": reg["id"], "redirect_uri": "https://spa.example/cb",
            "scope": "read", "state": "xyz",
            "code_challenge": s256(verifier), "code_challenge_method": "S256",
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert approve.status_code == 200, approve.text
    code = approve.json()["code"]
    assert approve.json()["state"] == "xyz"

    exchange = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": reg["id"],
        "redirect_uri": "https://spa.example/cb", "code_verifier": verifier,
    })
    assert exchange.status_code == 200, exchange.text
    assert exchange.json()["access_token"]


def test_authorization_endpoint_requires_authenticated_user(client):
    reg = client.post("/oauth/clients", json={
        "name": "spa", "confidential": False, "redirect_uris": ["https://spa.example/cb"]}).json()
    resp = client.post("/oauth/authorize", json={
        "client_id": reg["id"], "redirect_uri": "https://spa.example/cb", "scope": "read"})
    assert resp.status_code == 401


# --- introspection + revocation -----------------------------------------
def register_client(client):
    reg = client.post("/oauth/clients", json={"name": "resource-server", "confidential": True}).json()
    return {"client_id": reg["id"], "client_secret": reg["secret"]}


def test_introspection(client):
    creds = register_client(client)
    token = get_token(client, scope="read")["access_token"]
    resp = client.post("/oauth/introspect", data={"token": token, **creds})
    assert resp.status_code == 200
    assert resp.json()["active"] is True


def test_revocation_makes_token_inactive(client):
    creds = register_client(client)
    body = get_token(client, scope="read")
    token = body["access_token"]
    assert client.post("/oauth/revoke", data={"token": token, **creds}).status_code == 200
    # protected route now rejects it
    assert client.get("/user", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.post("/oauth/introspect", data={"token": token, **creds}).json()["active"] is False


# --- personal access tokens ---------------------------------------------
def test_personal_access_token_lifecycle(client):
    user_token = get_token(client)["access_token"]
    auth = {"Authorization": f"Bearer {user_token}"}

    create = client.post("/oauth/personal-access-tokens",
                         json={"name": "ci", "scopes": ["read"]}, headers=auth)
    assert create.status_code == 201, create.text
    pat = create.json()
    assert pat["access_token"]

    # PAT authenticates and carries its scope
    me = client.get("/needs-read", headers={"Authorization": f"Bearer {pat['access_token']}"})
    assert me.status_code == 200

    listing = client.get("/oauth/personal-access-tokens", headers=auth)
    assert any(t["name"] == "ci" for t in listing.json())

    deleted = client.delete(f"/oauth/personal-access-tokens/{pat['jti']}", headers=auth)
    assert deleted.status_code == 204
    assert client.get("/user", headers={"Authorization": f"Bearer {pat['access_token']}"}).status_code == 401


# --- password reset -----------------------------------------------------
def test_password_reset_flow(client):
    email = client.post("/password/email", json={"email": "grace@example.com"})
    assert email.status_code == 200
    token = email.json()["token"]

    reset = client.post("/password/reset", json={
        "email": "grace@example.com", "token": token, "password": "new-hopper"})
    assert reset.status_code == 200

    # new password works, old one doesn't
    assert client.post("/token", data={"username": "grace@example.com", "password": "new-hopper"}).status_code == 200
    assert client.post("/token", data={"username": "grace@example.com", "password": "hopper"}).status_code == 400


def test_password_reset_throttle(client):
    client.post("/password/email", json={"email": "grace@example.com"})
    second = client.post("/password/email", json={"email": "grace@example.com"})
    assert second.status_code == 429


def test_unsupported_grant_type(client):
    resp = client.post("/oauth/token", data={"grant_type": "telepathy"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"
