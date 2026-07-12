"""Regression tests for task #894: the password-reset throttle must not leak
account existence. Rapid repeated requests for a known vs unknown email must be
indistinguishable at the HTTP boundary (no 429 leak), while the server still
throttles (the notifier is not invoked beyond the throttle allowance)."""
from fastapi.testclient import TestClient

from fastapi_startkit_auth import Application, AuthProvider, AuthConfig
from fastapi_startkit_auth.security.hashing import BcryptHasher
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider


def build():
    hasher = BcryptHasher(rounds=4)
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    provider.add({"id": 1, "email": "ada@example.com", "password": hasher.make("secret")})

    sent: list[tuple[str, str]] = []

    class Config(AuthConfig):
        key = "throttle-enum-secret-key-32-bytes-minimum!!"
        bcrypt_rounds = 4
        password_reset_notifier = staticmethod(lambda email, token: sent.append((email, token)))
        default = {"guard": "api", "passwords": "users"}
        guards = {"api": {"driver": "passport", "provider": "users"}}
        providers = {"users": {"driver": "instance", "instance": provider}}
        # A real throttle window (not 0) so a rapid second request is throttled.
        passwords = {"users": {"provider": "users", "expire": 60, "throttle": 60}}

    return TestClient(Application([(AuthProvider, Config)]).api), sent


def test_rapid_requests_for_known_email_do_not_leak_429():
    client, sent = build()
    first = client.post("/password/email", json={"email": "ada@example.com"})
    second = client.post("/password/email", json={"email": "ada@example.com"})
    assert first.status_code == 200
    assert second.status_code == 200  # throttled, but no 429 leak
    assert first.json() == second.json()
    # Server-side throttle held: the notifier fired only once despite two requests.
    assert len(sent) == 1


def test_known_and_unknown_emails_are_indistinguishable_under_rapid_requests():
    client, sent = build()
    known1 = client.post("/password/email", json={"email": "ada@example.com"})
    known2 = client.post("/password/email", json={"email": "ada@example.com"})
    unknown1 = client.post("/password/email", json={"email": "ghost@example.com"})
    unknown2 = client.post("/password/email", json={"email": "ghost@example.com"})

    statuses = {known1.status_code, known2.status_code, unknown1.status_code, unknown2.status_code}
    assert statuses == {200}
    bodies = {
        known1.text, known2.text, unknown1.text, unknown2.text,
    }
    assert len(bodies) == 1  # every response body is byte-for-byte identical

    # Unknown account never triggers delivery; known account delivered once only.
    assert [e for e, _ in sent] == ["ada@example.com"]


def test_notifier_not_invoked_beyond_throttle():
    client, sent = build()
    for _ in range(5):
        client.post("/password/email", json={"email": "ada@example.com"})
    assert len(sent) == 1  # only the first, throttle-permitted request delivers
