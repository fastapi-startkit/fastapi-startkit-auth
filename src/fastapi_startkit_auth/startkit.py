"""Publishable-asset provider for `fastapi-startkit` applications."""
from __future__ import annotations

from pathlib import Path

from fastapi_startkit.support import Provider

_PUBLISHABLE = Path(__file__).resolve().parent / "publishable"


class AuthServiceProvider(Provider):
    """Registers the auth package's publishable assets with the framework.

    Add it to the application's ``providers=[...]`` list, then publish the
    CORS stub with ``provider:publish -p auth`` (copied to ``config/cors.py``).
    The stub's defaults are also merged under the ``cors`` config key, so the
    published file only overrides them.
    """

    provider_key = "auth"

    def register(self) -> None:
        cors_stub = str(_PUBLISHABLE / "cors.py")
        self.merge_config_from(cors_stub, "cors")
        self.publishes({cors_stub: "config/cors.py"})
