from __future__ import annotations

import base64
import hashlib
import hmac


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def verify_pkce(code_verifier: str, code_challenge: str, method: str | None) -> bool:
    """Validate a PKCE ``code_verifier`` against a stored challenge (RFC 7636).

    ``S256`` compares the base64url-encoded SHA-256 of the verifier; ``plain``
    (and a missing method) compares verbatim. Comparison is constant-time.
    """
    if not code_verifier or not code_challenge:
        return False
    method = (method or "plain").upper()
    if method == "S256":
        expected = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    elif method == "PLAIN":
        expected = code_verifier
    else:
        return False
    return hmac.compare_digest(expected, code_challenge)
