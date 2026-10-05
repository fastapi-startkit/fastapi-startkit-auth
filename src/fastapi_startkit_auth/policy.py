from __future__ import annotations

import re
from dataclasses import dataclass

from .clients.models import Client
from .exceptions import InvalidGrant, InvalidRequest, InvalidScope, InvalidTarget, UnauthorizedClient

# RFC 7636 §4.1/§4.2: a verifier is 43-128 unreserved characters; an S256 challenge
# is the unpadded base64url SHA-256, always 43 characters.
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")


@dataclass(frozen=True)
class GrantPolicy:
    """What the authorization server may grant, built from ``OAuth2Config``.

    ``scopes`` is the scope catalog: when non-empty, every requested scope must be
    listed in it (``"*"`` included). ``resources`` lists the RFC 8707 resource
    indicators tokens may be bound to; a resource outside it is refused.
    ``pkce_methods`` lists the accepted ``code_challenge_method`` values
    (case-insensitive, as in ``verify_pkce``); a missing method means ``plain``.
    ``require_pkce`` makes every client, confidential ones included, send a
    ``code_challenge``. ``require_redirect_uri`` makes every authorization
    request name one of the client's registered redirect URIs.
    """

    scopes: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()
    pkce_methods: frozenset[str] = frozenset({"S256", "plain"})
    require_pkce: bool = False
    require_redirect_uri: bool = False

    def check_scopes(self, scopes: list[str]) -> None:
        if not self.scopes:
            return
        unknown = sorted(set(scopes) - self.scopes)
        if unknown:
            raise InvalidScope(f"Unknown scope(s): {' '.join(unknown)}.")

    def check_client_scopes(self, client: Client, scopes: list[str]) -> None:
        if not client.allows_scopes(scopes):
            raise InvalidScope("The client is not allowed to request these scopes.")

    def check_resource(self, resource: str | None) -> None:
        if resource is not None and resource not in self.resources:
            raise InvalidTarget("The requested resource is not served by this authorization server.")

    def check_pkce(self, confidential: bool, code_challenge: str | None, method: str | None) -> None:
        if not code_challenge:
            if self.require_pkce or not confidential:
                raise InvalidRequest("A PKCE code_challenge is required.")
            return
        method = (method or "plain").upper()
        if method not in {allowed.upper() for allowed in self.pkce_methods}:
            raise InvalidRequest(f"code_challenge_method must be one of: {', '.join(sorted(self.pkce_methods))}.")
        pattern = _S256_CHALLENGE if method == "S256" else _VERIFIER
        if not pattern.fullmatch(code_challenge):
            raise InvalidRequest("code_challenge is not a valid RFC 7636 challenge.")

    def check_redirect(self, client: Client, redirect_uri: str | None) -> None:
        if redirect_uri is None:
            if self.require_redirect_uri:
                raise InvalidRequest("redirect_uri is required.")
            return
        if "#" in redirect_uri or not client.allows_redirect(redirect_uri):
            raise InvalidRequest("redirect_uri is not registered for this client.")


def ensure_client_may(client: Client, grant: str) -> None:
    if client.revoked or not client.allows_grant(grant):
        raise UnauthorizedClient(f"Client is not authorized for the {grant} grant.")


def ensure_valid_verifier(code_verifier: str | None) -> None:
    if not code_verifier or not _VERIFIER.fullmatch(code_verifier):
        raise InvalidGrant("PKCE verification failed.")


def ensure_same_resource(granted: str | None, requested: str | None) -> None:
    if requested is not None and requested != granted:
        raise InvalidTarget("The requested resource does not match the grant.")
