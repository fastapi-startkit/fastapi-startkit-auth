import base64
import hashlib

import pytest

from fastapi_passport.exceptions import InvalidGrant
from fastapi_passport.security.hashing import BcryptHasher
from fastapi_passport.security.jwt import JWTEncoder
from fastapi_passport.tokens.repository import InMemoryTokenRepository
from fastapi_passport.tokens.service import TokenService
from fastapi_passport.providers.memory import InMemoryUserProvider
from fastapi_passport.clients.models import Client
from fastapi_passport.grants.password import PasswordGrant
from fastapi_passport.grants.client_credentials import ClientCredentialsGrant
from fastapi_passport.grants.refresh import RefreshTokenGrant
from fastapi_passport.grants.authorization_code import AuthorizationCodeGrant
from fastapi_passport.grants.pkce import verify_pkce


SECRET = "grants-test-secret-key-32-bytes-minimum!"


@pytest.fixture
def service():
    return TokenService(encoder=JWTEncoder(secret=SECRET), repository=InMemoryTokenRepository(),
                        access_ttl=3600, refresh_ttl=7200)


@pytest.fixture
def users():
    hasher = BcryptHasher(rounds=4)
    p = InMemoryUserProvider(hasher=hasher, username_field="username")
    p.add({"id": 1, "username": "ada", "password": hasher.make("secret")})
    return p


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# --- password grant ------------------------------------------------------
def test_password_grant_issues_tokens(service, users):
    grant = PasswordGrant(service, users)
    issued = grant.handle(username="ada", password="secret", scopes=["read"], client_id="c1")
    assert issued.refresh_token is not None
    assert service.authenticate(issued.access_token)["sub"] == "1"


def test_password_grant_rejects_bad_password(service, users):
    grant = PasswordGrant(service, users)
    with pytest.raises(InvalidGrant):
        grant.handle(username="ada", password="wrong", scopes=[], client_id="c1")


def test_password_grant_rejects_unknown_user(service, users):
    grant = PasswordGrant(service, users)
    with pytest.raises(InvalidGrant):
        grant.handle(username="ghost", password="secret", scopes=[], client_id="c1")


# --- client credentials --------------------------------------------------
def test_client_credentials_issues_token_without_user_or_refresh(service):
    grant = ClientCredentialsGrant(service)
    client = Client(id="c1", name="svc", confidential=True)
    issued = grant.handle(client=client, scopes=["read"])
    assert issued.refresh_token is None
    claims = service.authenticate(issued.access_token)
    assert claims["sub"] is None
    assert claims["client_id"] == "c1"


# --- refresh -------------------------------------------------------------
def test_refresh_grant(service, users):
    issued = PasswordGrant(service, users).handle(username="ada", password="secret", scopes=["read"], client_id="c1")
    rotated = RefreshTokenGrant(service).handle(refresh_token=issued.refresh_token, scopes=None)
    assert rotated.access_token != issued.access_token


# --- authorization code + PKCE ------------------------------------------
def test_pkce_verify_s256():
    verifier = "abc123abc123abc123abc123abc123abc123abc123xyz"
    assert verify_pkce(verifier, s256(verifier), "S256") is True
    assert verify_pkce("wrong", s256(verifier), "S256") is False


def test_pkce_verify_plain():
    assert verify_pkce("plainverifier", "plainverifier", "plain") is True
    assert verify_pkce("plainverifier", "other", "plain") is False


def test_authorization_code_flow_with_pkce(service):
    grant = AuthorizationCodeGrant(service)
    client = Client(id="c1", name="spa", confidential=False, redirect_uris=["https://spa/cb"])
    verifier = "verifier-verifier-verifier-verifier-1234567890"
    code = grant.issue_code(
        client=client, user_id=1, scopes=["read"],
        redirect_uri="https://spa/cb", code_challenge=s256(verifier), code_challenge_method="S256",
    )
    issued = grant.handle(client=client, code=code, redirect_uri="https://spa/cb", code_verifier=verifier)
    assert service.authenticate(issued.access_token)["sub"] == "1"


def test_authorization_code_rejects_bad_verifier(service):
    grant = AuthorizationCodeGrant(service)
    client = Client(id="c1", name="spa", confidential=False, redirect_uris=["https://spa/cb"])
    verifier = "verifier-verifier-verifier-verifier-1234567890"
    code = grant.issue_code(
        client=client, user_id=1, scopes=["read"],
        redirect_uri="https://spa/cb", code_challenge=s256(verifier), code_challenge_method="S256",
    )
    with pytest.raises(InvalidGrant):
        grant.handle(client=client, code=code, redirect_uri="https://spa/cb", code_verifier="attacker")


def test_authorization_code_is_single_use(service):
    grant = AuthorizationCodeGrant(service)
    client = Client(id="c1", name="spa", confidential=False, redirect_uris=["https://spa/cb"])
    verifier = "verifier-verifier-verifier-verifier-1234567890"
    code = grant.issue_code(
        client=client, user_id=1, scopes=["read"],
        redirect_uri="https://spa/cb", code_challenge=s256(verifier), code_challenge_method="S256",
    )
    grant.handle(client=client, code=code, redirect_uri="https://spa/cb", code_verifier=verifier)
    with pytest.raises(InvalidGrant):
        grant.handle(client=client, code=code, redirect_uri="https://spa/cb", code_verifier=verifier)


def test_authorization_code_rejects_redirect_uri_mismatch(service):
    grant = AuthorizationCodeGrant(service)
    client = Client(id="c1", name="spa", confidential=False, redirect_uris=["https://spa/cb"])
    verifier = "verifier-verifier-verifier-verifier-1234567890"
    code = grant.issue_code(
        client=client, user_id=1, scopes=["read"],
        redirect_uri="https://spa/cb", code_challenge=s256(verifier), code_challenge_method="S256",
    )
    with pytest.raises(InvalidGrant):
        grant.handle(client=client, code=code, redirect_uri="https://evil/cb", code_verifier=verifier)
