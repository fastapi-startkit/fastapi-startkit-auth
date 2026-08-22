"""Auth error hierarchy.

Error codes follow the OAuth2 error registry (RFC 6749 §5.2) so they can be
surfaced verbatim in token-endpoint responses.
"""
from __future__ import annotations


class AuthError(Exception):
    """Base class for all authentication/authorization failures."""

    error = "invalid_request"
    status_code = 400

    def __init__(self, description: str | None = None) -> None:
        self.description = description or self.__class__.__doc__ or self.error
        super().__init__(self.description)

    def to_dict(self) -> dict:
        return {"error": self.error, "error_description": self.description}


class InvalidRequest(AuthError):
    """The request is missing a required parameter or is otherwise malformed."""

    error = "invalid_request"
    status_code = 400


class InvalidClient(AuthError):
    """Client authentication failed (unknown client or bad secret)."""

    error = "invalid_client"
    status_code = 401


class InvalidGrant(AuthError):
    """The provided credentials, code, or refresh token are invalid or expired."""

    error = "invalid_grant"
    status_code = 400


class UnsupportedGrantType(AuthError):
    """The authorization server does not support this grant type."""

    error = "unsupported_grant_type"
    status_code = 400


class UnauthorizedClient(AuthError):
    """The client is not permitted to use this grant type."""

    error = "unauthorized_client"
    status_code = 400


class InvalidToken(AuthError):
    """The access token is expired, malformed, revoked, or otherwise invalid."""

    error = "invalid_token"
    status_code = 401


class InvalidSession(AuthError):
    """The session cookie is missing, expired, or no longer valid."""

    error = "invalid_session"
    status_code = 401


class InsufficientScope(AuthError):
    """The token does not carry the scopes required for this resource."""

    error = "insufficient_scope"
    status_code = 403


class ThrottleException(AuthError):
    """Too many requests for this action; retry later."""

    error = "throttled"
    status_code = 429
