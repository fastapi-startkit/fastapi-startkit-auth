"""Installs this package's session-auth stack onto the FastAPI app."""
from fastapi_startkit.support import Provider

from fastapi_startkit_auth import AuthProvider as AuthPackageProvider

from config.auth import ExampleAuthConfig


class AuthStackProvider(Provider):
    """Adapts this package's plain-FastAPI AuthProvider to the framework.

    Booted after FastAPIProvider has created the FastAPI instance, so the
    session/CSRF middleware ends up outside InertiaMiddleware (middleware
    added later wraps middleware added earlier).
    """

    provider_key = "auth"

    def boot(self) -> None:
        AuthPackageProvider(ExampleAuthConfig).register(self.app.fastapi)
