"""Regression tests for the security findings on PR #1 (task #892)."""
import base64
import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from fastapi_passport import Application, AuthProvider, AuthConfig
from fastapi_passport.security.hashing import BcryptHasher
from fastapi_passport.providers.memory import InMemoryUserProvider
from fastapi_passport.tokens.repository import InMemoryTokenRepository
from fastapi_passport.tokens.service import TokenService
from fastapi_passport.security.jwt import JWTEncoder
from fastapi_passport.clients.models import Client
from fastapi_passport.grants.authorization_code import AuthorizationCodeGrant
from fastapi_passport.exceptions import InvalidGrant


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def build_client(*, notifier=None, debug_expose=False):
    """A secure-by-default app: debug echo OFF unless explicitly requested."""
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    provider.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})

    captured = []

    class Config(AuthConfig):
        key = "security-fixes-secret-key-32-bytes-minimum!"
        bcrypt_rounds = 4
        debug_expose_reset_token = debug_expose
        password_reset_notifier = staticmethod(notifier) if notifier else None
        default = {"guard": "api", "passwords": "users"}
        guards = {"api": {"driver": "passport", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": provider}}
        passwords = {"users": {"provider": "users", "expire": 60, "throttle": 0}}

    app = Application([(AuthProvider, Config)])
    return TestClient(app.api), captured


# --- Finding 1: password-reset token must never leak in the response -----
def test_password_email_response_contains_no_token_by_default():
    captured = []
    client, _ = build_client(notifier=lambda email, token: captured.append((email, token)))

    resp = client.post("/password/email", json={"email": "ada@example.com"})
    assert resp.status_code == 200
    # The response body must NOT carry a usable token.
    assert "token" not in resp.json()
    assert resp.json() == {"status": "If that account exists, a reset link has been sent."}
    # ...but the token was delivered out-of-band via the notifier and is usable.
    assert len(captured) == 1
    email, token = captured[0]
    assert email == "ada@example.com" and token
    ok = client.post("/password/reset", json={"email": email, "token": token, "password": "new-pass"})
    assert ok.status_code == 200


def test_debug_flag_can_expose_token_but_is_off_by_default():
    assert AuthConfig.debug_expose_reset_token is False
    client, _ = build_client(debug_expose=True)
    resp = client.post("/password/email", json={"email": "ada@example.com"})
    assert resp.json().get("token")  # opt-in only


# --- Finding 4: no account enumeration via /password/email or grant ------
def test_password_email_unknown_account_is_indistinguishable():
    client, _ = build_client()
    known = client.post("/password/email", json={"email": "ada@example.com"})
    unknown = client.post("/password/email", json={"email": "ghost@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()  # identical, non-enumerable response


def test_password_grant_same_error_for_unknown_user_and_wrong_password():
    client, _ = build_client()
    wrong_pw = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "nope"})
    unknown = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ghost@example.com", "password": "nope"})
    assert wrong_pw.status_code == unknown.status_code == 400
    assert wrong_pw.json() == unknown.json()  # same generic invalid_grant


def test_provider_dummy_verify_exists():
    provider = InMemoryUserProvider(hasher=BcryptHasher(rounds=4))
    assert callable(getattr(provider, "dummy_verify", None))
    provider.dummy_verify()  # must not raise


# --- Finding 2: PKCE enforced for public clients -------------------------
def test_public_client_cannot_get_code_without_pkce():
    client, _ = build_client()
    reg = client.post("/oauth/clients", json={
        "name": "spa", "confidential": False, "redirect_uris": ["https://spa/cb"]}).json()
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]

    resp = client.post("/oauth/authorize",
                       json={"client_id": reg["id"], "redirect_uri": "https://spa/cb", "scope": "read"},
                       headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_exchange_rejects_challengeless_code_without_client_auth():
    """Defense-in-depth: even a stored code with no challenge cannot be redeemed
    by an unauthenticated (public) client."""
    svc = TokenService(encoder=JWTEncoder(secret="x" * 40), repository=InMemoryTokenRepository())
    grant = AuthorizationCodeGrant(svc)
    public = Client(id="pub", name="spa", confidential=False, redirect_uris=["https://spa/cb"])
    svc.repository.store_auth_code(
        code="leaked", client_id="pub", user_id=1, scopes=["read"], redirect_uri="https://spa/cb",
        code_challenge=None, code_challenge_method=None, expires_at=time.time() + 60)
    with pytest.raises(InvalidGrant):
        grant.handle(client=public, code="leaked", redirect_uri="https://spa/cb",
                     code_verifier=None, client_authenticated=False)


def test_public_client_full_pkce_flow_still_works():
    client, _ = build_client()
    reg = client.post("/oauth/clients", json={
        "name": "spa", "confidential": False, "redirect_uris": ["https://spa/cb"]}).json()
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]
    verifier = "verifier-verifier-verifier-verifier-1234567890"
    code = client.post("/oauth/authorize", json={
        "client_id": reg["id"], "redirect_uri": "https://spa/cb", "scope": "read",
        "code_challenge": s256(verifier), "code_challenge_method": "S256"},
        headers={"Authorization": f"Bearer {token}"}).json()["code"]
    exchange = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": reg["id"],
        "redirect_uri": "https://spa/cb", "code_verifier": verifier})
    assert exchange.status_code == 200


# --- Finding 3: introspect + revoke require client authentication --------
def test_introspect_requires_client_auth():
    client, _ = build_client()
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]
    assert client.post("/oauth/introspect", data={"token": token}).status_code == 401


def test_revoke_requires_client_auth():
    client, _ = build_client()
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]
    assert client.post("/oauth/revoke", data={"token": token}).status_code == 401


def test_introspect_and_revoke_accept_basic_auth():
    client, _ = build_client()
    reg = client.post("/oauth/clients", json={"name": "rs", "confidential": True}).json()
    basic = base64.b64encode(f"{reg['id']}:{reg['secret']}".encode()).decode()
    headers = {"Authorization": f"Basic {basic}"}
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]

    assert client.post("/oauth/introspect", data={"token": token}, headers=headers).json()["active"] is True
    assert client.post("/oauth/revoke", data={"token": token}, headers=headers).status_code == 200


# --- Finding 5: redirect_to query params are URL-encoded -----------------
def test_redirect_to_url_encodes_state():
    client, _ = build_client()
    reg = client.post("/oauth/clients", json={
        "name": "spa", "confidential": False, "redirect_uris": ["https://spa/cb"]}).json()
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]
    verifier = "verifier-verifier-verifier-verifier-1234567890"
    resp = client.post("/oauth/authorize", json={
        "client_id": reg["id"], "redirect_uri": "https://spa/cb", "scope": "read",
        "state": "a b&c=d", "code_challenge": s256(verifier), "code_challenge_method": "S256"},
        headers={"Authorization": f"Bearer {token}"}).json()
    # raw special characters must be percent-encoded, not passed through verbatim
    assert "a b&c=d" not in resp["redirect_to"]
    assert "state=a+b%26c%3Dd" in resp["redirect_to"]
