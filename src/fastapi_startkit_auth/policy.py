from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import InvalidRequest, InvalidScope, InvalidTarget

if TYPE_CHECKING:
    from .clients.models import Client


@dataclass(frozen=True)
class GrantPolicy:
    """What the authorization server may grant, built from ``AuthConfig``.

    ``scopes`` is the scope catalog: when non-empty, every requested scope must be
    listed in it (``"*"`` included). ``resources`` lists the RFC 8707 resource
    indicators tokens may be bound to; a resource outside it is refused.
    ``pkce_methods`` lists the accepted ``code_challenge_method`` values.
    """

    scopes: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()
    pkce_methods: frozenset[str] = frozenset({"S256", "plain"})

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

    def check_pkce_method(self, code_challenge: str | None, method: str | None) -> None:
        if code_challenge and (method or "plain") not in self.pkce_methods:
            raise InvalidRequest(f"code_challenge_method must be one of: {', '.join(sorted(self.pkce_methods))}.")


def ensure_same_resource(granted: str | None, requested: str | None) -> None:
    if requested is not None and requested != granted:
        raise InvalidTarget("The requested resource does not match the grant.")
