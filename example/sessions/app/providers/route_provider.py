"""Registers the web routes on the FastAPI app."""
from fastapi_startkit.support import Provider


class RouteProvider(Provider):
    provider_key = "web"

    def boot(self) -> None:
        from routes.web import router

        # Include the wrapped APIRouter: FastAPI's lazy router inclusion
        # resolves routes off the concrete APIRouter type, and the startkit
        # Router only proxies attribute access to it.
        self.app.include_router(router.router)
