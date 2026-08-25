from fastapi_startkit_auth import AuthConfig as BaseAuthConfig
from fastapi_startkit_auth.providers.memory import InMemoryUserProvider
from fastapi_startkit_auth.security.hashing import BcryptHasher


def seeded_users() -> InMemoryUserProvider:
    hasher = BcryptHasher()
    provider = InMemoryUserProvider(hasher=hasher, username_field="email")
    provider.add({"id": 1, "email": "demo@example.com", "password": hasher.make("password")})
    return provider


class AuthConfig(BaseAuthConfig):
    key = "example-sessions-demo-key-0123456789abcdef"
    default = {"guard": "web", "passwords": "users"}
    guards = {"web": {"driver": "session", "provider": "users"}}
    providers = {"users": {"driver": "instance", "instance": seeded_users()}}
    session = {"secure": False}
    spa = {"enabled": True}
