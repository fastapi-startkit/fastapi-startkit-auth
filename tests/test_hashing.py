from fastapi_startkit_auth.security.hashing import BcryptHasher


def test_hash_is_not_plaintext():
    hasher = BcryptHasher()
    hashed = hasher.make("secret-password")
    assert hashed != "secret-password"
    assert hashed.startswith("$2")


def test_verify_matches_correct_password():
    hasher = BcryptHasher()
    hashed = hasher.make("secret-password")
    assert hasher.verify("secret-password", hashed) is True


def test_verify_rejects_wrong_password():
    hasher = BcryptHasher()
    hashed = hasher.make("secret-password")
    assert hasher.verify("wrong", hashed) is False


def test_verify_rejects_malformed_hash():
    hasher = BcryptHasher()
    assert hasher.verify("secret-password", "not-a-hash") is False


def test_long_passwords_are_supported():
    # bcrypt truncates at 72 bytes; the hasher must pre-hash so long inputs stay distinct.
    hasher = BcryptHasher()
    base = "a" * 80
    hashed = hasher.make(base)
    assert hasher.verify(base, hashed) is True
    assert hasher.verify("a" * 72 + "different", hashed) is False
