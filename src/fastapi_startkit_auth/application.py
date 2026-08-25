from __future__ import annotations

from typing import Any, Iterable

from fastapi import FastAPI


class Application:
    """Thin composition root mirroring the framework's provider lifecycle.

    Providers are listed either bare or as a ``(ProviderClass, config)`` tuple
    (the config is instantiated when it is a class, as the framework does).
    Each provider is constructed as ``ProviderClass(application, config)``;
    every ``register()`` runs first, then every ``boot()``. The FastAPI
    instance is exposed as ``.fastapi`` (the accessor providers use, matching
    the framework Application) with ``.api`` kept as an alias, and the
    Application is itself ASGI-callable, so it can be served directly::

        app = Application([(AuthProvider, AuthConfig)])
        # uvicorn app:app        -> uses Application.__call__
        # uvicorn app:app.api    -> uses the FastAPI instance
    """

    def __init__(
        self,
        providers: Iterable[Any] | None = None,
        api: FastAPI | None = None,
    ) -> None:
        self.api = api or FastAPI(title="FastAPI Startkit Auth")
        self.providers: list[Any] = []
        for entry in providers or []:
            if isinstance(entry, tuple):
                provider_cls, config = entry
                if callable(config):
                    config = config()
            else:
                provider_cls, config = entry, None
            provider = provider_cls(self, config=config)
            provider.register()
            self.providers.append(provider)
        for provider in self.providers:
            provider.boot()

    @property
    def fastapi(self) -> FastAPI:
        return self.api

    @property
    def auth(self):
        """Return the AuthManager of the first registered provider."""
        return self.providers[0].manager if self.providers else None

    async def __call__(self, scope, receive, send):
        await self.api(scope, receive, send)
