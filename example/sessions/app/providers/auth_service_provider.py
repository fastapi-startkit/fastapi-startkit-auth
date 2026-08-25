from fastapi_startkit.support import Provider

from fastapi_startkit_auth import AuthProvider as AuthPackageProvider

from config.auth import AuthConfig


class AuthServiceProvider(Provider):
    provider_key = "auth"

    def boot(self) -> None:
        AuthPackageProvider(AuthConfig).register(self.app.fastapi)
