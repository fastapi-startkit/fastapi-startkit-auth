"""Session-based login example: FastAPI + fastapi-startkit-auth + Inertia.js.

Run from this directory (see README.md for the full setup):

    uv run uvicorn app:app --reload
"""
from pathlib import Path

from fastapi import Depends
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel

from fastapi_startkit.application import Application
from fastapi_startkit.inertia import Inertia, InertiaProvider
from fastapi_startkit.vite import ViteProvider

from fastapi_startkit_auth import Auth, AuthConfig, AuthProvider
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


application = Application(
    base_path=BASE_PATH,
    providers=[
        (
            ViteProvider,
            {
                "public_path": str(BASE_PATH / "public"),
                # Vite 5+ writes the manifest to a .vite/ subdirectory.
                "manifest_filename": ".vite/manifest.json",
            },
        ),
    ],
)

app = application.fastapi

# InertiaProvider is booted after the FastAPI instance exists: the framework's
# Application.add_middleware needs it, but it is only created lazily, so
# booting Inertia inside Application(providers=[...]) would fail on a fresh
# checkout where public/build has not been built yet.
_inertia = InertiaProvider(application)
_inertia.register()
_inertia.boot()

AuthProvider(ExampleAuthConfig).register(app)


def public_user(user: dict) -> dict:
    return {"id": user["id"], "email": user["email"]}


@app.get("/", response_model=None)
def home(auth: Auth = Depends(Auth.scoped)) -> Response:
    return RedirectResponse("/dashboard" if auth.check() else "/login", status_code=303)


@app.get("/login", response_model=None)
def login_page(auth: Auth = Depends(Auth.scoped)) -> Response:
    if auth.check():
        return RedirectResponse("/dashboard", status_code=303)
    return Inertia.render("Login")


@app.post("/login", response_model=None)
def login(credentials: LoginCredentials, auth: Auth = Depends(Auth.scoped)) -> Response:
    if auth.attempt(credentials.model_dump()):
        return RedirectResponse("/dashboard", status_code=303)
    # A failed login has no session to flash errors into, so render the page
    # directly; Inertia's useForm reads page.props.errors either way.
    return Inertia.render("Login", {"errors": {"email": LOGIN_ERROR}})


@app.get("/dashboard", response_model=None)
def dashboard(auth: Auth = Depends(Auth.scoped)) -> Response:
    user = auth.user()
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return Inertia.render("Dashboard", {"user": public_user(user)})


@app.post("/logout", response_model=None)
def logout(auth: Auth = Depends(Auth.scoped)) -> Response:
    auth.logout()
    return RedirectResponse("/login", status_code=303)
