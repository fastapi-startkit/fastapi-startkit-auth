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
    """

    id: str
    name: str
    secret: str | None = None
    redirect_uris: list[str] = field(default_factory=list)
    confidential: bool = True
    grant_types: list[str] = field(default_factory=list)
    revoked: bool = False
    provider: str | None = None

    def allows_redirect(self, uri: str) -> bool:
        return uri in self.redirect_uris

    def allows_grant(self, grant_type: str) -> bool:
        if not self.grant_types:
            return True
        return grant_type in self.grant_types
