# fastapi-startkit-auth

Passport-style OAuth2 + JWT authentication for FastAPI.

`fastapi-startkit-auth` brings the ergonomics of [Laravel Passport](https://laravel.com/docs/13.x/passport)
to FastAPI: a config-driven guard/provider/passwords model layered on top of
OAuth2 grants and signed JWT access tokens (per the
[FastAPI security tutorial](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)).

## Features

| Area | What you get |
| --- | --- |
| **Config layer** | `AuthConfig` (`default` / `guards` / `providers` / `passwords`) + `AuthProvider`, with `SessionConfig` / `OAuth2Config` / `ApiTokenConfig` feature providers |
| **Password grant** | Opt-in legacy password grant → signed JWT access tokens (`/oauth/token`, `/token`) |
| **Refresh tokens** | Client-bound opaque refresh tokens with **rotation** and reuse detection |
| **Personal access tokens** | Named, long-lived tokens with scopes/abilities |
| **Client credentials** | Machine-to-machine grant |
| **Authorization code + PKCE** | OAuth 2.1 flow with S256 PKCE, explicit consent and `iss` (RFC 9207) |
| **Clients** | ORM client store and the `auth:oauth2:client` command |
| **Revocation & introspection** | RFC 7009 revoke + RFC 7662 introspect |
| **Password reset** | `password_reset_tokens` flow with configurable `expire` + `throttle` |
| **Guards & deps** | `current_user`, `optional_user`, `require_scopes` FastAPI dependencies |
| **Pluggable providers** | In-memory, generic ORM/masoniteorm model, or any custom `UserProvider` |

## Installation

Requires Python 3.10+.

```bash
pip install fastapi-startkit-auth
# or
uv add fastapi-startkit-auth
```

Optional extras:

| Extra | Installs | Use when |
| --- | --- | --- |
| `startkit` | `fastapi-startkit[database]>=0.60,<1.0` (Python 3.12+) | Registering the auth providers in a Startkit app, publishing migrations via `provider:publish`, and the `"orm"` stores |
| `masoniteorm` | `masonite-orm` | Using the `masoniteorm` user provider driver |

```bash
pip install "fastapi-startkit-auth[startkit]"
pip install "fastapi-startkit-auth[masoniteorm]"
```

The `startkit` and `masoniteorm` extras are mutually exclusive: `masonite-orm`
pins `cleo<2` while `fastapi-startkit` requires `cleo>=2.1`.

> Uses `bcrypt` directly (not `passlib`, which imports the `crypt` stdlib module
> removed in Python 3.13+), so it runs on modern Python.

## Quickstart

```python
from fastapi import Depends, FastAPI
from fastapi_startkit_auth import (
    AuthConfig, AuthOAuth2Provider, AuthProvider, OAuth2Config, current_user, require_scopes,
)
from myapp.models import User  # any active-record-style model


class Config(AuthConfig):
    default = {"guard": "api", "passwords": "users"}
    guards = {"api": {"driver": "passport", "provider": "users"}}
    providers = {"users": {"driver": "masoniteorm", "model": User}}
    passwords = {
        "users": {"provider": "users", "table": "password_reset_tokens",
                  "expire": 60, "throttle": 60},
    }


app = FastAPI()
AuthProvider(Config).register(app)                      # always first
AuthOAuth2Provider(OAuth2Config(key="change-me-to-a-long-random-secret")).register(app)


@app.get("/me")
def me(user=Depends(current_user)):
    return user


@app.get("/reports")
def reports(ctx=Depends(require_scopes("reports:read"))):
    return {"ok": True}
```

In a Startkit application, list `AuthProvider` and then the feature providers
(`AuthSessionProvider`, `AuthOAuth2Provider`, `AuthApiTokenProvider`) in the
application's providers instead.

## Configuration

`AuthConfig` mirrors Laravel's `config/auth.php`: guards, user providers and
password brokers. Each feature has its own config, handed to its provider:

| Provider | Config | Enables |
| --- | --- | --- |
| `AuthSessionProvider` | `SessionConfig` | cookie sessions (`"session"` guards), CSRF |
| `AuthOAuth2Provider` | `OAuth2Config` | the OAuth 2.1 server (`"passport"` guards) |
| `AuthApiTokenProvider` | `ApiTokenConfig` | opaque API tokens (`"token"` guards), SPA mode |

```python
OAuth2Config(
    key=None,                     # JWT secret (required in production)
    algorithm="HS256",
    access_token_ttl=3600,
    refresh_token_ttl=60 * 60 * 24 * 14,
    authorization_code_ttl=600,
    issuer=None,                  # stamps and verifies `iss`
    resources=[],                 # RFC 8707 resource indicators
    scopes={},                    # scope catalog; empty accepts any scope
    default_scopes=[],
    pkce_methods=["S256"],
    require_pkce=True,
    grant_types=["authorization_code", "client_credentials", "refresh_token"],
    tokens=OAuthTokensConfig(store="memory"),
    clients=OAuthClientsConfig(store="orm"),
)
```

Add `"password"` to `grant_types` to enable the legacy password grant (and the
`/token` endpoint). The OAuth settings formerly on `AuthConfig` (`key`,
`issuer`, `scopes`, ...) are still read from there with a `DeprecationWarning`.

### Provider drivers

| driver | meaning |
| --- | --- |
| `masoniteorm` / `orm` / `model` | wrap a model exposing `find(id)` and `where(field, value).first()` |
| `async_model` | same, for async ORMs where `find`, `first()` and `save()` are coroutines |
| `memory` | in-memory dict store (`users=[...]`) — great for tests/demos |
| `instance` | pass a ready `UserProvider` via `{"instance": ...}` |
| `factory` | pass a zero-arg callable returning a `UserProvider` |

Any object implementing the `UserProvider` protocol
(`retrieve_by_id`, `retrieve_by_credentials`, `validate_credentials`,
`get_identifier`, `update_password`) is a valid provider. Any of its methods
may be `async def`; one async method is enough for `AuthManager` to pick the
async guards, grants and broker. The sync classes refuse an awaitable result
with `AsyncMisconfiguration` instead of treating it as truthy.

Model-backed providers also accept `password_key` (the credentials key holding
the plaintext password, default: `password_field`) and `is_active` (a boolean
attribute name or a `callable(user) -> bool`; inactive users cannot log in,
authenticate, refresh or exchange a code, and introspect as inactive). The
`async_model` driver also takes an `async def` hook; the sync drivers reject
one at construction:

```python
providers = {
    "users": {
        "driver": "async_model",
        "model": User,
        "password_field": "hashed_password",
        "password_key": "password",
        "is_active": "is_active",
    }
}
```

### Multiple providers

With more than one provider, register each OAuth client with the provider whose
users it serves (Laravel Passport's `provider` column). The password grant then
authenticates against that provider, and refresh, code exchange and
introspection re-check the token owner against it. A client without a
`provider` uses the default guard's provider, and `/oauth/authorize` rejects a
client bound to a different provider with `unauthorized_client`:

```python
client, secret = manager.client_repository.register(name="admin-panel", provider="admins")
```

### ORM stores and migrations

With an async provider or store, `AuthManager` builds the async guards, grants,
token service and password broker automatically (use the `AsyncAuth` facade for
session login/logout). Sessions, API tokens and OAuth tokens persist through the
fastapi-startkit ORM (`pip install "fastapi-startkit-auth[startkit]"`, which pulls
in `fastapi-startkit[database]`). The package ships its own models
(`fastapi_startkit_auth.orm`) and uses no raw SQL:

```python
SessionConfig(store="orm")
ApiTokenConfig(store="orm")
OAuth2Config(tokens=OAuthTokensConfig(store="orm", connection="auth"))  # optional ORM connection name
```

`connection` names an entry of your database config; omit it to use the default
connection. Publish and run the migrations once per app. Each provider
publishes its own (all reversible and additive): sessions, personal API tokens,
and the OAuth access/refresh token, auth code and client tables plus the
`resource` and refresh `family_id` columns:

```bash
python artisan provider:publish -p auth-oauth2   # copies them to databases/migrations/
python artisan migrate
python artisan migrate:rollback           # drops them again
```

Single-use guarantees rely on conditional `UPDATE`/`DELETE` statements issued
through the ORM query builder: refresh-token rotation and authorization-code
redemption each have exactly one winner under concurrency.

The former `sql` and `async_sql` stores were removed; configuring them raises a
`ValueError` pointing at `"orm"`. Use `"memory"` or an `"instance"` store for
sync setups.

In mixed setups (async stores with a sync provider or a sync session store),
the sync calls — lookups, bcrypt, `is_active` hooks, a sync session store in
`SessionMiddleware` — run in the threadpool, never on the event loop.
An `is_active` attribute name or `async def` hook runs inline, since neither
blocks.

`AuthProvider` warms the providers up when the app starts (`await
manager.warm_up()`), so `AsyncModelUserProvider` computes its dummy hash off the
event loop before the first request. A login for an unknown user then costs
one bcrypt verify, the same as a wrong password.

## HTTP endpoints

| Method & path | Purpose |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 server metadata |
| `POST /oauth/token` | Token endpoint: `authorization_code`, `refresh_token`, `client_credentials` (+ `password` when enabled) |
| `POST /token` | Simple password grant (only when `"password"` is enabled) |
| `GET /oauth/authorize` | Validate an auth-code request for your consent screen |
| `POST /oauth/authorize` | Issue a code once the user consents (`"approved": true`) → `code`, `iss` |
| `POST /oauth/introspect` | RFC 7662 introspection (**confidential client authentication**) |
| `POST /oauth/revoke` | RFC 7009 revocation of a token and its chain (**client authentication**) |
| `GET/DELETE /oauth/tokens`, `DELETE /oauth/tokens/{jti}` | The user's OAuth tokens |
| `POST/GET/DELETE /oauth/personal-access-tokens`, `DELETE .../{jti}` | Personal access tokens |
| `POST /password/email` | Trigger a password-reset token (delivered out-of-band; see below) |
| `POST /password/reset` | Reset the password with a token |

### Password resets

`POST /password/email` always returns the same generic response whether or not
the account exists (no user enumeration) and **never** puts the token in the
response body. Configure how the token reaches the user with a notifier:

```python
class AuthConfig(BaseAuthConfig):
    password_reset_notifier = staticmethod(lambda email, token: send_email(email, token))
    # debug_expose_reset_token = True   # DEV ONLY: echo the token in the response
```

PKCE is required by default (`require_pkce=True`, `pkce_methods=["S256"]`):
send `code_challenge_method=S256` with a 43-character challenge, and a verifier
of 43–128 characters at exchange. A missing method means `plain`.

Clients are created with `python artisan auth:oauth2:client --name app
--redirect-uri https://app/cb [--public]` or
`manager.client_repository.register(...)`. Refresh tokens are bound to their
client; replaying a rotated refresh token revokes its whole family.

### Example: password grant

With `"password"` in `OAuth2Config.grant_types`:

```bash
curl -X POST localhost:8000/oauth/token \
  -d grant_type=password -d username=ada@example.com -d password=secret -d scope="read write"
# → { "access_token": "...", "token_type": "Bearer", "expires_in": 3600,
#     "refresh_token": "...", "scope": "read write" }
```

### Example: authorization code + PKCE

1. `POST /oauth/authorize` with the user's credentials, `approved: true`, `code_challenge` and `code_challenge_method: S256` → returns a single-use `code` and `iss`.
2. `POST /oauth/token` with `grant_type=authorization_code`, the `code`, and the `code_verifier`.

## Scopes / abilities

Tokens carry scopes; enforce them with the `require_scopes` dependency:

```python
require_scopes("posts:write")               # must have this scope
require_scopes("a", "b")                     # must have all
require_scopes("a", "b", mode="any")         # must have at least one
```

`*` is a wildcard scope that satisfies any check. Inside a handler you can also
inspect the `AuthContext` (`ctx.can(...)`, `ctx.can_any(...)`, `ctx.scopes`).

## Testing

```bash
uv sync --group dev
uv run pytest
uv run ruff check .
```

The async store and flow tests run on aiosqlite; set `TEST_ASYNCPG_DSN` to a
disposable Postgres database to also run them on asyncpg (CI does).

Or with pip:

```bash
pip install -e ".[test]"
pytest
```

## Releasing

Releases are cut from `main` with the release script (maintainers only):

```bash
./bin/release.sh          # patch bump
./bin/release.sh minor    # or: major
```

The script bumps the version (`pyproject.toml`, `__version__`, `uv.lock`),
builds sdist + wheel, validates them with `twine check`, uploads them to PyPI
with `twine upload`, then commits, tags `vX.Y.Z`, pushes, and creates a GitHub
release. Move the `Unreleased` notes in `CHANGELOG.md` under the new version
before running it.

It requires `uv`, an authenticated `gh`, and PyPI credentials for twine: either
a `[pypi]` entry in `~/.pypirc` (`username = __token__`, `password = pypi-...`)
or `TWINE_USERNAME=__token__` and `TWINE_PASSWORD=pypi-...` in the environment.

## License

MIT
