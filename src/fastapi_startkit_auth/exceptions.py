"""Auth exception hierarchy.

Error codes follow the OAuth2 error registry (RFC 6749 §5.2) so they can be
surfaced verbatim in token-endpoint responses.
"""
from __future__ import annotations


class AuthException(Exception):
    """Base class for all authentication/authorization failures."""

    error = "invalid_request"
    status_code = 400

    def __init__(self, description: str | None = None) -> None:
        self.description = description or self.__class__.__doc__ or self.error
        super().__init__(self.description)

    def to_dict(self) -> dict:
        return {"error": self.error, "error_description": self.description}


class InvalidRequestException(AuthException):
    """The request is missing a required parameter or is otherwise malformed."""

    error = "invalid_request"
    status_code = 400


class InvalidClientException(AuthException):
    """Client authentication failed (unknown client or bad secret)."""

    error = "invalid_client"
    status_code = 401


class InvalidGrantException(AuthException):
    """The provided credentials, code, or refresh token are invalid or expired."""

    error = "invalid_grant"
    status_code = 400


class InvalidCredentialsException(InvalidGrantException):
    """The username or password is incorrect (password grant)."""

    error = "invalid_grant"
    status_code = 400


class UnsupportedGrantTypeException(AuthException):
    """The authorization server does not support this grant type."""

    error = "unsupported_grant_type"
    status_code = 400


class UnauthorizedClientException(AuthException):
    """The client is not permitted to use this grant type."""

    error = "unauthorized_client"
    status_code = 400


class InvalidTokenException(AuthException):
    """The access token is expired, malformed, revoked, or otherwise invalid."""

    error = "invalid_token"
    status_code = 401


class AuthenticationException(AuthException):
    """The session cookie is missing, expired, or no longer valid."""

    error = "invalid_session"
    status_code = 401


class CsrfTokenMismatchException(AuthException):
    """The request is missing a valid CSRF token for this session."""

    error = "csrf_token_mismatch"
    status_code = 403


class MissingScopeException(AuthException):
    """The token does not carry the scopes required for this resource."""

    error = "insufficient_scope"
    status_code = 403


class ThrottleException(AuthException):
    """Too many requests for this action; retry later."""

    error = "throttled"
    status_code = 429


class InvalidScopeException(AuthException):
    """The requested scope is unknown or not allowed."""

    error = "invalid_scope"
    status_code = 400


class InvalidTargetException(AuthException):
    """The requested resource is unknown or does not match the grant (RFC 8707)."""

    error = "invalid_target"
    status_code = 400


class UnsupportedResponseTypeException(AuthException):
    """The authorization endpoint only issues authorization codes."""

    error = "unsupported_response_type"
    status_code = 400


class AccessDeniedException(AuthException):
    """The resource owner did not approve the authorization request."""

    error = "access_denied"
    status_code = 400


# Deprecated aliases for the names used before the Exception-suffix rename.
# Remove them in the next major release.
AuthError = AuthException
InvalidRequest = InvalidRequestException
InvalidClient = InvalidClientException
InvalidGrant = InvalidGrantException
UnsupportedGrantType = UnsupportedGrantTypeException
UnauthorizedClient = UnauthorizedClientException
InvalidToken = InvalidTokenException
InvalidSession = AuthenticationException
CsrfTokenMismatch = CsrfTokenMismatchException
InsufficientScope = MissingScopeException
InvalidScope = InvalidScopeException
InvalidTarget = InvalidTargetException
UnsupportedResponseType = UnsupportedResponseTypeException
AccessDenied = AccessDeniedException
