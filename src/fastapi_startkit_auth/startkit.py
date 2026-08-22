"""Framework-native provider for `fastapi-startkit` applications.

This module is the only place the package touches the optional framework
dependency, and it is imported lazily (via the package ``__getattr__``), so
plain-FastAPI installs never load it. Install the extra to use it::

    pip install fastapi-startkit-auth[startkit]
"""
from __future__ import annotations

from pathlib import Path

try:
    from fastapi_startkit.support import Provider
except ImportError as exc:  # pragma: no cover - exercised via the package import test
    raise ImportError(
        "AuthServiceProvider requires the optional 'fastapi-startkit' framework. "
        "Install it with: pip install fastapi-startkit-auth[startkit]"
    ) from exc

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
