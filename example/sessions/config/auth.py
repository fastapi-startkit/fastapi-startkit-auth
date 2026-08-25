"""Auth configuration for the session example.

Kept alongside config/vite.py per the canonical fastapi-startkit `config/`
convention. `AuthStackProvider` reads `ExampleAuthConfig` from here and applies
it to the FastAPI app.
"""
from fastapi_startkit_auth import AuthConfig
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher


def seeded_users() -> InMemoryUserProvider:
    hasher = BcryptHasher()
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    provider.add({"id": 1, "email": "demo@example.com", "password": hasher.make("password")})
    return provider


class ExampleAuthConfig(AuthConfig):
    # Demo-only signing key; generate your own for real applications.
    key = "example-sessions-demo-key-0123456789abcdef"
    default = {"guard": "web", "passwords": "users"}
    guards = {"web": {"driver": "session", "provider": "users"}}
    providers = {"users": {"driver": "instance", "instance": seeded_users()}}
    # secure=False because the example runs over plain http://127.0.0.1 —
    # the package warns about it; keep secure cookies on in production.
    session = {"secure": False}
    # SPA mode adds CsrfMiddleware: axios echoes the XSRF-TOKEN cookie into
    # the X-XSRF-TOKEN header, so the frontend needs no CSRF code.
    spa = {"enabled": True}
