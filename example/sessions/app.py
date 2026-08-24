"""Session-based login example: fastapi-startkit + fastapi-startkit-auth + Inertia.js.

Canonical fastapi-startkit bootstrap: the Application composes providers —
FastAPIProvider creates the FastAPI instance, ViteProvider/InertiaProvider wire
the frontend integration, and two app-local providers install this package's
session-auth stack and the web routes.

Run from this directory (see README.md for the full setup):

    uv run uvicorn app:app --reload
"""
from pathlib import Path

from fastapi import Depends
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel

from fastapi_startkit import Application
from fastapi_startkit.fastapi import FastAPIConfig, FastAPIProvider, Router
from fastapi_startkit.inertia import Inertia, InertiaProvider
from fastapi_startkit.support import Provider
from fastapi_startkit.vite import ViteProvider

from fastapi_startkit_auth import Auth, AuthConfig
from fastapi_startkit_auth import AuthProvider as AuthPackageProvider
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher

BASE_PATH = Path(__file__).resolve().parent

LOGIN_ERROR = "These credentials do not match our records."


class LoginCredentials(BaseModel):
    email: str
    password: str


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


# --- controllers ------------------------------------------------------


def public_user(user: dict) -> dict:
    return {"id": user["id"], "email": user["email"]}


def home(auth: Auth = Depends(Auth.scoped)) -> Response:
    return RedirectResponse("/dashboard" if auth.check() else "/login", status_code=303)


def login_page(auth: Auth = Depends(Auth.scoped)) -> Response:
    if auth.check():
        return RedirectResponse("/dashboard", status_code=303)
    return Inertia.render("Login")


def attempt_login(credentials: LoginCredentials, auth: Auth = Depends(Auth.scoped)) -> Response:
    if auth.attempt(credentials.model_dump()):
        return RedirectResponse("/dashboard", status_code=303)
    # A failed login has no session to flash errors into, so render the page
    # directly; Inertia's useForm reads page.props.errors either way.
    return Inertia.render("Login", {"errors": {"email": LOGIN_ERROR}})


def dashboard(auth: Auth = Depends(Auth.scoped)) -> Response:
    user = auth.user()
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return Inertia.render("Dashboard", {"user": public_user(user)})


def logout(auth: Auth = Depends(Auth.scoped)) -> Response:
    auth.logout()
    return RedirectResponse("/login", status_code=303)


class WebRoutesProvider(Provider):
    provider_key = "web"

    def boot(self) -> None:
        router = Router()
        router.get("/", home)
        router.get("/login", login_page, name="login")
        router.post("/login", attempt_login, name="login.attempt")
        router.get("/dashboard", dashboard, name="dashboard")
        router.post("/logout", logout, name="logout")
        # Include the wrapped APIRouter: FastAPI's lazy router inclusion
        # resolves routes off the concrete APIRouter type, and the startkit
        # Router only proxies attribute access to it.
        self.app.include_router(router.router)


app = Application(
    base_path=BASE_PATH,
    providers=[
        (FastAPIProvider, FastAPIConfig),
        (
            ViteProvider,
            {
                "public_path": str(BASE_PATH / "public"),
                # Vite 5+ writes the manifest to a .vite/ subdirectory.
                "manifest_filename": ".vite/manifest.json",
            },
        ),
        InertiaProvider,
        AuthStackProvider,
        WebRoutesProvider,
    ],
)
