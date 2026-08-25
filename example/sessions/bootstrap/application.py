from pathlib import Path

from fastapi_startkit import Application
from fastapi_startkit.fastapi import FastAPIConfig, FastAPIProvider
from fastapi_startkit.inertia import InertiaProvider
from fastapi_startkit.vite import ViteProvider

from app.providers.auth_service_provider import AuthServiceProvider
from app.providers.route_provider import RouteProvider

BASE_PATH = Path(__file__).resolve().parent.parent


app = Application(
    base_path=BASE_PATH,
    providers=[
        (FastAPIProvider, FastAPIConfig),
        ViteProvider,
        InertiaProvider,
        AuthServiceProvider,
        RouteProvider,
    ],
)
