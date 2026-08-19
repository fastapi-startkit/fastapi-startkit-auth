"""Regression tests for the security findings on PR #1 (task #892).

The secure-by-default app (debug reset-token echo OFF) comes from the shared
``auth_client`` fixture in conftest; only tests that opt into the debug echo
pass ``debug_expose=True``.
"""
import base64
import time

import pytest

from fastapi_startkit_auth import AuthConfig
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.tokens.repository import InMemoryTokenRepository
from fastapi_startkit_auth.tokens.service import TokenService
from fastapi_startkit_auth.security.jwt import JWTEncoder
from fastapi_startkit_auth.clients.models import Client
from fastapi_startkit_auth.grants.authorization_code import AuthorizationCodeGrant
from fastapi_startkit_auth.exceptions import InvalidGrant


# --- Finding 1: password-reset token must never leak in the response -----
def test_password_email_response_contains_no_token_by_default(auth_client):
    client, captured = auth_client()

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


def test_debug_flag_can_expose_token_but_is_off_by_default(auth_client):
    assert AuthConfig.debug_expose_reset_token is False
    client, _ = auth_client(debug_expose=True)
    resp = client.post("/password/email", json={"email": "ada@example.com"})
    assert resp.json().get("token")  # opt-in only


# --- Finding 4: no account enumeration via /password/email or grant ------
def test_password_email_unknown_account_is_indistinguishable(auth_client):
    client, _ = auth_client()
    known = client.post("/password/email", json={"email": "ada@example.com"})
    unknown = client.post("/password/email", json={"email": "ghost@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()  # identical, non-enumerable response


def test_password_grant_same_error_for_unknown_user_and_wrong_password(auth_client):
    client, _ = auth_client()
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
def test_public_client_cannot_get_code_without_pkce(auth_client):
    client, _ = auth_client()
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


def test_public_client_full_pkce_flow_still_works(auth_client, s256):
    client, _ = auth_client()
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
def test_introspect_requires_client_auth(auth_client):
    client, _ = auth_client()
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]
    assert client.post("/oauth/introspect", data={"token": token}).status_code == 401


def test_revoke_requires_client_auth(auth_client):
    client, _ = auth_client()
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]
    assert client.post("/oauth/revoke", data={"token": token}).status_code == 401


def test_introspect_and_revoke_accept_basic_auth(auth_client):
    client, _ = auth_client()
    reg = client.post("/oauth/clients", json={"name": "rs", "confidential": True}).json()
    basic = base64.b64encode(f"{reg['id']}:{reg['secret']}".encode()).decode()
    headers = {"Authorization": f"Basic {basic}"}
    token = client.post("/oauth/token", data={
        "grant_type": "password", "username": "ada@example.com", "password": "secret"}).json()["access_token"]

    assert client.post("/oauth/introspect", data={"token": token}, headers=headers).json()["active"] is True
    assert client.post("/oauth/revoke", data={"token": token}, headers=headers).status_code == 200


# --- Finding 5: redirect_to query params are URL-encoded -----------------
def test_redirect_to_url_encodes_state(auth_client, s256):
    client, _ = auth_client()
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
