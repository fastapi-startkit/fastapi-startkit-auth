"""Regression tests for task #894: the password-reset throttle must not leak
account existence. Rapid repeated requests for a known vs unknown email must be
indistinguishable at the HTTP boundary (no 429 leak), while the server still
throttles (the notifier is not invoked beyond the throttle allowance).

A real throttle window (throttle=60, not 0) is required so a rapid second
request is actually throttled."""


def test_rapid_requests_for_known_email_do_not_leak_429(auth_client):
    client, sent = auth_client(throttle=60)
    first = client.post("/password/email", json={"email": "ada@example.com"})
    second = client.post("/password/email", json={"email": "ada@example.com"})
    assert first.status_code == 200
    assert second.status_code == 200  # throttled, but no 429 leak
    assert first.json() == second.json()
    # Server-side throttle held: the notifier fired only once despite two requests.
    assert len(sent) == 1


def test_known_and_unknown_emails_are_indistinguishable_under_rapid_requests(auth_client):
    client, sent = auth_client(throttle=60)
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


def test_notifier_not_invoked_beyond_throttle(auth_client):
    client, sent = auth_client(throttle=60)
    for _ in range(5):
        client.post("/password/email", json={"email": "ada@example.com"})
    assert len(sent) == 1  # only the first, throttle-permitted request delivers
