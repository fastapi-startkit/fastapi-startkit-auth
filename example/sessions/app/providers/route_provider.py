from fastapi_startkit.support import Provider


class RouteProvider(Provider):
    provider_key = "web"

    def boot(self) -> None:
        from routes.web import router

        self.app.include_router(router.router)
