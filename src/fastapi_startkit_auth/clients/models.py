from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Client:
    """An OAuth2 client (application).

    Confidential clients authenticate with a secret; public clients (SPAs, native
    apps) do not and must use the authorization-code + PKCE flow. An empty
    ``grant_types`` means the client may use any supported grant.

    ``provider`` names the ``AuthConfig.providers`` entry whose users this
    client acts for; ``None`` means the default guard's provider.

    ``scopes`` lists the scopes the client may request; empty means any.
    """

    id: str
    name: str
    secret: str | None = None
    redirect_uris: list[str] = field(default_factory=list)
    confidential: bool = True
    grant_types: list[str] = field(default_factory=list)
    revoked: bool = False
    provider: str | None = None
    scopes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # list("read") would silently become ["r", "e", "a", "d"].
        if isinstance(self.scopes, str):
            raise TypeError("Client.scopes must be a list of scope names, not a string.")
        self.scopes = list(self.scopes)

    def allows_redirect(self, uri: str) -> bool:
        return uri in self.redirect_uris

    def allows_scopes(self, scopes: list[str]) -> bool:
        return not self.scopes or set(scopes) <= set(self.scopes)

    def allows_grant(self, grant_type: str) -> bool:
        if not self.grant_types:
            return True
        return grant_type in self.grant_types
