import asyncio
from urllib.parse import urlsplit

from cleo.helpers import option
from fastapi_startkit.console import Command

from ..concurrency import call


def _valid_redirect(uri: str | None) -> bool:
    if not uri:
        return False
    parts = urlsplit(uri)
    return bool(parts.scheme) and not parts.fragment


class OAuth2ClientCommand(Command):
    name = "auth:oauth2:client"
    description = "Create a public PKCE or confidential first-party OAuth client."
    options = [
        option("public", description="Create a public client without a secret."),
        option("name", description="Client name.", flag=False),
        option(
            "redirect-uri", description="Exact callback URI; repeat for multiple callbacks.", flag=False, multiple=True
        ),
    ]

    def handle(self) -> int:
        name = self.option("name") or self.ask("Client name")
        redirects = self.option("redirect-uri") or [self.ask("Redirect URI")]
        if not name or not all(_valid_redirect(uri) for uri in redirects):
            self.line_error("A client name and absolute redirect URIs without fragments are required.")
            return 1
        manager = self.container.make("auth_manager")
        client, secret = asyncio.run(
            call(
                manager.client_repository.register,
                name=name,
                redirect_uris=redirects,
                confidential=not self.option("public"),
                grant_types=["authorization_code", "refresh_token"],
            )
        )
        self.line(f"Client ID: {client.id}")
        if secret is not None:
            self.line(f"Client secret: {secret}")
            self.line("Save this secret now; it will not be shown again.")
        self.line("Authorization code with PKCE and refresh tokens enabled.")
        return 0
