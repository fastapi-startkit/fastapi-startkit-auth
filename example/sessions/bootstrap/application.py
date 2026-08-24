"""Session-based login example: fastapi-startkit + fastapi-startkit-auth + Inertia.js.

Canonical fastapi-startkit bootstrap: the Application composes providers —
FastAPIProvider creates the FastAPI instance, ViteProvider (configured via the
published config/vite.py) and InertiaProvider wire the frontend integration,
and two app-local providers install this package's session-auth stack and the
web routes declared in routes/web.py.

Run from the example root (example/sessions — see README.md for the full setup):

    uv run uvicorn bootstrap.application:app --factory --reload
"""
from pathlib import Path

from fastapi_startkit import Application
from fastapi_startkit.fastapi import FastAPIConfig, FastAPIProvider
from fastapi_startkit.inertia import InertiaProvider
from fastapi_startkit.support import Provider
from fastapi_startkit.vite import ViteProvider

from fastapi_startkit_auth import AuthConfig
from fastapi_startkit_auth import AuthProvider as AuthPackageProvider
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

# The example root: config/, resources/templates and public/ resolve from
# here, one level above bootstrap/.
BASE_PATH = Path(__file__).resolve().parent.parent


def seeded_users() -> InMemoryUserProvider:
    hasher = BcryptHasher()
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    provider.add({"id": 1, "email": "demo@example.com", "password": hasher.make("password")})
    return provider


class ExampleAuthConfig(AuthConfig):
    # Demo-only signing key; generate your own for real applications.
    key = "example-sessions-demo-key-0123456789abcdef"
    default = {"guard": "web", "passwords": "users"}
    guards = {"web": {"driver": "session", "provider": "users"}}
    providers = {"users": {"driver": "instance", "instance": seeded_users()}}
    # secure=False because the example runs over plain http://127.0.0.1 —
    # the package warns about it; keep secure cookies on in production.
    session = {"secure": False}
    # SPA mode adds CsrfMiddleware: axios echoes the XSRF-TOKEN cookie into
    # the X-XSRF-TOKEN header, so the frontend needs no CSRF code.
    spa = {"enabled": True}


class AuthStackProvider(Provider):
    """Adapts this package's plain-FastAPI AuthProvider to the framework.

    Booted after FastAPIProvider has created the FastAPI instance, so the
    session/CSRF middleware ends up outside InertiaMiddleware (middleware
    added later wraps middleware added earlier).
    """

    provider_key = "auth"

    def boot(self) -> None:
        AuthPackageProvider(ExampleAuthConfig).register(self.app.fastapi)


class WebRoutesProvider(Provider):
    provider_key = "web"

    def boot(self) -> None:
        from routes.web import router

        # Include the wrapped APIRouter: FastAPI's lazy router inclusion
        # resolves routes off the concrete APIRouter type, and the startkit
        # Router only proxies attribute access to it.
        self.app.include_router(router.router)


app = Application(
    base_path=BASE_PATH,
    providers=[
        (FastAPIProvider, FastAPIConfig),
        ViteProvider,
        InertiaProvider,
        AuthStackProvider,
        WebRoutesProvider,
    ],
)
