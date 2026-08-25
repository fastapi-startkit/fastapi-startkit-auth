"""Session-based login example: fastapi-startkit + fastapi-startkit-auth + Inertia.js.

Canonical fastapi-startkit bootstrap: the Application composes providers —
FastAPIProvider creates the FastAPI instance, ViteProvider (configured via the
published config/vite.py) and InertiaProvider wire the frontend integration,
and two app-local providers install this package's session-auth stack
(AuthStackProvider) and the web routes declared in routes/web.py
(RouteProvider).

Run from the example root (example/sessions — see README.md for the full setup):

    uv run uvicorn bootstrap.app:app --factory --reload
"""
from pathlib import Path

from fastapi_startkit import Application
from fastapi_startkit.fastapi import FastAPIConfig, FastAPIProvider
from fastapi_startkit.inertia import InertiaProvider
from fastapi_startkit.vite import ViteProvider

from app.providers.auth_stack_provider import AuthStackProvider
from app.providers.route_provider import RouteProvider

# The example root: config/, resources/templates and public/ resolve from
# here, one level above bootstrap/.
BASE_PATH = Path(__file__).resolve().parent.parent


app = Application(
    base_path=BASE_PATH,
    providers=[
        (FastAPIProvider, FastAPIConfig),
        ViteProvider,
        InertiaProvider,
        AuthStackProvider,
        RouteProvider,
    ],
)
