import time

import pytest

from fastapi_startkit_auth.exceptions import InvalidToken
from fastapi_startkit_auth.security.jwt import JWTEncoder


SECRET = "test-secret-that-is-at-least-32-bytes-long!"


def make_encoder(**kw):
    return JWTEncoder(secret=SECRET, algorithm="HS256", **kw)


def test_encode_then_decode_roundtrips_claims():
    enc = make_encoder()
    token = enc.encode({"sub": "42", "scopes": ["read"]}, ttl_seconds=60)
    claims = enc.decode(token)
    assert claims["sub"] == "42"
    assert claims["scopes"] == ["read"]


def test_encode_sets_expiry_and_issued_at():
    enc = make_encoder()
    token = enc.encode({"sub": "1"}, ttl_seconds=60)
    claims = enc.decode(token)
    assert claims["exp"] - claims["iat"] == 60
    assert "jti" in claims


def test_expired_token_is_rejected():
    enc = make_encoder()
    token = enc.encode({"sub": "1"}, ttl_seconds=-1)
    with pytest.raises(InvalidToken):
        enc.decode(token)


def test_tampered_token_is_rejected():
    enc = make_encoder()
    token = enc.encode({"sub": "1"}, ttl_seconds=60)
    other = JWTEncoder(secret="different-secret-also-32-bytes-long-yes!!", algorithm="HS256")
    with pytest.raises(InvalidToken):
        other.decode(token)


def test_decode_without_verifying_expiry():
    enc = make_encoder()
    token = enc.encode({"sub": "1"}, ttl_seconds=-1)
    claims = enc.decode(token, verify_exp=False)
    assert claims["sub"] == "1"


def test_each_token_has_unique_jti():
    enc = make_encoder()
    a = enc.decode(enc.encode({"sub": "1"}, ttl_seconds=60))
    b = enc.decode(enc.encode({"sub": "1"}, ttl_seconds=60))
    assert a["jti"] != b["jti"]
