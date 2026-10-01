# fastapi-startkit-auth

Passport-style OAuth2 + JWT authentication for FastAPI.

`fastapi-startkit-auth` brings the ergonomics of [Laravel Passport](https://laravel.com/docs/13.x/passport)
to FastAPI: a config-driven guard/provider/passwords model layered on top of
OAuth2 grants and signed JWT access tokens (per the
[FastAPI security tutorial](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)).

## Features

| Area | What you get |
| --- | --- |
| **Config layer** | `AuthConfig` (`default` / `guards` / `providers` / `passwords`) + `AuthProvider` that registers into the app |
| **Password grant** | OAuth2 password grant → signed JWT access tokens with expiry (`/oauth/token`, `/token`) |
| **Refresh tokens** | Opaque refresh tokens with **rotation** and configurable TTL |
| **Personal access tokens** | Named, long-lived tokens with scopes/abilities |
| **Client credentials** | Machine-to-machine grant |
| **Authorization code + PKCE** | Browser/SPA flow with S256 & plain PKCE |
| **Clients** | Register / list / delete confidential & public clients |
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
| `startkit` | `fastapi-startkit>=0.51,<1.0` (Python 3.12+) | Registering `AuthServiceProvider` in a fastapi-startkit app and publishing its `config/cors.py` stub via `provider:publish -p auth` |
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
from fastapi import Depends
from fastapi_startkit_auth import Application, AuthProvider, AuthConfig, current_user, require_scopes
from myapp.models import User  # any active-record-style model


class Config(AuthConfig):
    key = "change-me-to-a-long-random-secret"   # JWT signing key

    default = {"guard": "api", "passwords": "users"}
    guards = {"api": {"driver": "passport", "provider": "users"}}
    providers = {"users": {"driver": "masoniteorm", "model": User}}
    passwords = {
        "users": {"provider": "users", "table": "password_reset_tokens",
                  "expire": 60, "throttle": 60},
    }


app = Application([(AuthProvider, Config)])
api = app.api  # the underlying FastAPI instance


@api.get("/me")
def me(user=Depends(current_user)):
    return user


@api.get("/reports")
def reports(ctx=Depends(require_scopes("reports:read"))):
    return {"ok": True}
```

Serve it:

```bash
uvicorn myapp:app        # Application is ASGI-callable
uvicorn myapp:app.api    # or serve the FastAPI instance directly
```

## Configuration

`AuthConfig` mirrors Laravel's `config/auth.php` and adds JWT/token knobs:

```python
class AuthConfig:
    default   = {"guard": "api", "passwords": "users"}
    guards    = {"api": {"driver": "passport", "provider": "users"}}
    providers = {"users": {"driver": "masoniteorm", "model": User}}
    passwords = {"users": {"provider": "users", "table": "password_reset_tokens",
                            "expire": 60, "throttle": 60}}

    # token settings (all optional, sensible defaults shown)
    key                        = None          # JWT secret (required in production)
    algorithm                  = "HS256"
    access_token_ttl           = 3600          # seconds
    refresh_token_ttl          = 60 * 60 * 24 * 14
    personal_access_token_ttl  = 60 * 60 * 24 * 365
    authorization_code_ttl     = 600
    bcrypt_rounds              = 12
```

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

### Async stores

With an async provider or store, `AuthManager` builds the async guards, grants,
token service and password broker automatically (use the `AsyncAuth` facade for
session login/logout). Sessions, API tokens and OAuth tokens can be persisted
with an async driver — an asyncpg pool, an aiosqlite connection, or a zero-arg
(async) factory returning one:

```python
session = {"store": "async_sql", "connection": pool}
api_tokens = {"store": "async_sql", "connection": pool}
tokens = {"store": "async_sql", "connection": pool}
```

The tables come from the migrations published by `AuthServiceProvider`
(`provider:publish -p auth`), or from each store's `await create_table()`.

Supported backends are PostgreSQL (asyncpg) and SQLite (aiosqlite). Any other
driver can be plugged in by passing an object with async `execute` (returning
the affected row count), `fetch_one` and `fetch_all` methods using `?`
placeholders. The stores use only portable SQL (no `RETURNING`); the DDL in
`create_table()` uses `CREATE ... IF NOT EXISTS`, so on MySQL use the
migrations instead.

In mixed setups (async stores with a sync provider or a sync session store),
the sync calls — lookups, bcrypt, `is_active` hooks, `SqlSessionStore` in
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
| `POST /oauth/token` | Unified token endpoint: `password`, `refresh_token`, `client_credentials`, `authorization_code` |
| `POST /token` | Simple password grant (FastAPI-tutorial style) |
| `POST /oauth/authorize` | Approve an auth-code request (requires an authenticated user) → returns `code` |
| `POST /oauth/introspect` | RFC 7662 token introspection (**requires client authentication**) |
| `POST /oauth/revoke` | RFC 7009 access/refresh token revocation (**requires client authentication**) |
| `POST/GET /oauth/clients`, `DELETE /oauth/clients/{id}` | Client registration & management |
| `POST/GET /oauth/personal-access-tokens`, `DELETE .../{jti}` | Personal access tokens |
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

The `code_challenge` for public clients is mandatory — a public (secretless)
client cannot obtain an authorization code without PKCE, and codes are verified
against the `code_verifier` at exchange.

### Example: password grant

```bash
curl -X POST localhost:8000/oauth/token \
  -d grant_type=password -d username=ada@example.com -d password=secret -d scope="read write"
# → { "access_token": "...", "token_type": "Bearer", "expires_in": 3600,
#     "refresh_token": "...", "scope": "read write" }
```

### Example: authorization code + PKCE

1. `POST /oauth/authorize` with a bearer token and `code_challenge` → returns a single-use `code`.
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

Releases are published by the `.github/workflows/release.yml` workflow using [trusted publishing](https://docs.pypi.org/trusted-publishers/),
so no PyPI API token is stored anywhere.

Releases are cut from `main` with the release script (maintainers only):

```bash
./bin/release.sh          # patch bump
./bin/release.sh minor    # or: major
```

The script bumps the version (`pyproject.toml`, `__version__`, `uv.lock`),
builds sdist + wheel, validates them with `twine check`, then commits, tags
`vX.Y.Z`, pushes, and creates a GitHub release. Move the `Unreleased` notes in
`CHANGELOG.md` under the new version before running it. It requires `uv` and
`gh` (authenticated).

Pushing the tag triggers the workflow, which rejects a tag that does not match the `pyproject.toml` version,
then runs the tests, builds the sdist and wheel, checks them with `twine`, and
publishes from the `pypi` GitHub environment. The PyPI project must register
that repository, workflow file, and environment as a trusted publisher.

## License

MIT
