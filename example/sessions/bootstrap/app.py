"""Session-based login example: fastapi-startkit + fastapi-startkit-auth + Inertia.js.

Canonical fastapi-startkit bootstrap: the Application composes providers —
FastAPIProvider creates the FastAPI instance, ViteProvider (configured via the
published config/vite.py) and InertiaProvider wire the frontend integration,
and RouteProvider registers the web routes declared in routes/web.py. The
session-auth stack is registered directly on the built FastAPI app below.

Run from the example root (example/sessions — see README.md for the full setup):

    uv run uvicorn bootstrap.app:app --factory --reload
"""
from pathlib import Path

from fastapi_startkit import Application
from fastapi_startkit.fastapi import FastAPIConfig, FastAPIProvider
from fastapi_startkit.inertia import InertiaProvider
from fastapi_startkit.vite import ViteProvider

from fastapi_startkit_auth import AuthProvider as AuthPackageProvider

from app.providers.route_provider import RouteProvider
from config.auth import ExampleAuthConfig

# The example root: config/, resources/templates and public/ resolve from
# here, one level above bootstrap/.
BASE_PATH = Path(__file__).resolve().parent.parent


app = Application(
    base_path=BASE_PATH,
    providers=[
        (FastAPIProvider, FastAPIConfig),
        ViteProvider,
        InertiaProvider,
        RouteProvider,
    ],
)

AuthPackageProvider(ExampleAuthConfig).register(app.fastapi)
