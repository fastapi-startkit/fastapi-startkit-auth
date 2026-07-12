from __future__ import annotations

from typing import Any, Iterable

from fastapi import FastAPI


class Application:
    """Thin composition root mirroring ``Application([(AuthProvider, AuthConfig)])``.

    Creates a FastAPI app and registers each ``(ProviderClass, config)`` pair
    onto it. The resulting FastAPI instance is exposed as ``.api`` and the
    Application is itself ASGI-callable, so it can be served directly::

        app = Application([(AuthProvider, AuthConfig)])
        # uvicorn app:app        -> uses Application.__call__
        # uvicorn app:app.api    -> uses the FastAPI instance
    """

    def __init__(
        self,
        providers: Iterable[tuple[type, Any]] | None = None,
        api: FastAPI | None = None,
    ) -> None:
        self.api = api or FastAPI(title="FastAPI Passport")
        self.providers: list[Any] = []
        for provider_cls, config in providers or []:
            provider = provider_cls(config)
            provider.register(self.api)
            self.providers.append(provider)

    @property
    def auth(self):
        """Return the AuthManager of the first registered provider."""
        return self.providers[0].manager if self.providers else None

    async def __call__(self, scope, receive, send):
        await self.api(scope, receive, send)
