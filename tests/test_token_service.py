import pytest

from fastapi_startkit_auth.exceptions import InvalidGrant, InvalidToken
from fastapi_startkit_auth.security.jwt import JWTEncoder
from fastapi_startkit_auth.tokens.repository import InMemoryTokenRepository
from fastapi_startkit_auth.tokens.service import TokenService

SECRET = "unit-test-secret-key-at-least-32-bytes!!"


def make_service(**kw):
    return TokenService(
        encoder=JWTEncoder(secret=SECRET),
        repository=InMemoryTokenRepository(),
        access_ttl=3600,
        refresh_ttl=7200,
        personal_access_ttl=100000,
        **kw,
    )


def test_issue_access_token_returns_jwt_and_metadata():
    svc = make_service()
    issued = svc.issue(user_id=1, client_id="c1", scopes=["read", "write"])
    assert issued.token_type == "Bearer"
    assert issued.expires_in == 3600
    assert issued.scopes == ["read", "write"]
    claims = svc.authenticate(issued.access_token)
    assert claims["sub"] == "1"
    assert claims["scopes"] == ["read", "write"]


def test_issue_with_refresh_token():
    svc = make_service()
    issued = svc.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    assert issued.refresh_token is not None


def test_authenticate_rejects_revoked_access_token():
    svc = make_service()
    issued = svc.issue(user_id=1, client_id="c1", scopes=["read"])
    claims = svc.authenticate(issued.access_token)
    svc.revoke_access(claims["jti"])
    with pytest.raises(InvalidToken):
        svc.authenticate(issued.access_token)


def test_refresh_rotates_and_revokes_old_tokens():
    svc = make_service()
    issued = svc.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    old_claims = svc.authenticate(issued.access_token)

    rotated = svc.refresh(issued.refresh_token)
    assert rotated.refresh_token != issued.refresh_token

    # old access token is now revoked
    with pytest.raises(InvalidToken):
        svc.authenticate(issued.access_token)
    # new access token works
    assert svc.authenticate(rotated.access_token)["sub"] == "1"
    # replaying the old refresh token fails and revokes the whole family
    with pytest.raises(InvalidGrant):
        svc.refresh(issued.refresh_token)
    with pytest.raises(InvalidToken):
        svc.authenticate(rotated.access_token)
    with pytest.raises(InvalidGrant):
        svc.refresh(rotated.refresh_token)


def test_refresh_rejects_unknown_token():
    svc = make_service()
    with pytest.raises(InvalidGrant):
        svc.refresh("not-a-real-refresh-token")


def test_refresh_can_narrow_scopes():
    svc = make_service()
    issued = svc.issue(user_id=1, client_id="c1", scopes=["read", "write"], with_refresh=True)
    rotated = svc.refresh(issued.refresh_token, scopes=["read"])
    assert rotated.scopes == ["read"]


def test_refresh_cannot_widen_scopes():
    svc = make_service()
    issued = svc.issue(user_id=1, client_id="c1", scopes=["read"], with_refresh=True)
    with pytest.raises(InvalidGrant):
        svc.refresh(issued.refresh_token, scopes=["read", "admin"])


def test_personal_access_token_is_long_lived_and_named():
    svc = make_service()
    issued = svc.create_personal_access_token(user_id=7, name="ci-token", scopes=["read"])
    assert issued.expires_in == 100000
    claims = svc.authenticate(issued.access_token)
    record = svc.repository.find_access_token(claims["jti"])
    assert record.personal_access is True
    assert record.name == "ci-token"


def test_introspect_active_and_inactive():
    svc = make_service()
    issued = svc.issue(user_id=1, client_id="c1", scopes=["read"])
    data = svc.introspect(issued.access_token)
    assert data["active"] is True
    assert data["scope"] == "read"
    assert data["sub"] == "1"

    svc.revoke_access(svc.authenticate(issued.access_token)["jti"])
    assert svc.introspect(issued.access_token) == {"active": False}


def test_introspect_garbage_token_is_inactive():
    svc = make_service()
    assert svc.introspect("garbage") == {"active": False}
