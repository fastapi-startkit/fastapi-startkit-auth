import time

from fastapi_startkit_auth.tokens.repository import InMemoryTokenRepository


def test_access_token_record_roundtrip():
    repo = InMemoryTokenRepository()
    rec = repo.store_access_token(jti="j1", user_id=1, client_id="c1", scopes=["read"], expires_at=time.time() + 60)
    found = repo.find_access_token("j1")
    assert found is rec
    assert found.scopes == ["read"]
    assert found.revoked is False


def test_revoke_access_token():
    repo = InMemoryTokenRepository()
    repo.store_access_token(jti="j1", user_id=1, client_id="c1", scopes=[], expires_at=time.time() + 60)
    assert repo.revoke_access_token("j1") is True
    assert repo.find_access_token("j1").revoked is True
    # revoking an unknown token is a no-op
    assert repo.revoke_access_token("nope") is False


def test_refresh_token_rotation_revokes_old():
    repo = InMemoryTokenRepository()
    old = repo.store_refresh_token(token_id="r1", access_jti="j1", user_id=1, client_id="c1", scopes=["read"], expires_at=time.time() + 600)
    assert repo.find_refresh_token("r1") is old
    repo.revoke_refresh_token("r1")
    assert repo.find_refresh_token("r1").revoked is True


def test_authorization_code_single_use():
    repo = InMemoryTokenRepository()
    repo.store_auth_code(
        code="abc",
        client_id="c1",
        user_id=1,
        scopes=["read"],
        redirect_uri="https://app/cb",
        code_challenge="xyz",
        code_challenge_method="S256",
        expires_at=time.time() + 60,
    )
    code = repo.pull_auth_code("abc")
    assert code.user_id == 1
    # second pull returns nothing (consumed)
    assert repo.pull_auth_code("abc") is None


def test_purge_removes_expired_access_tokens():
    repo = InMemoryTokenRepository()
    repo.store_access_token(jti="old", user_id=1, client_id="c1", scopes=[], expires_at=time.time() - 10)
    repo.store_access_token(jti="new", user_id=1, client_id="c1", scopes=[], expires_at=time.time() + 60)
    repo.purge_expired()
    assert repo.find_access_token("old") is None
    assert repo.find_access_token("new") is not None
