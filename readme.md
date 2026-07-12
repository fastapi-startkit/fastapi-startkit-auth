# fastapi-passport

Passport-style OAuth2 + JWT authentication for FastAPI.

`fastapi-passport` brings the ergonomics of [Laravel Passport](https://laravel.com/docs/13.x/passport)
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

```bash
pip install fastapi-passport
# optional ORM provider driver
pip install "fastapi-passport[masoniteorm]"
```

> Uses `bcrypt` directly (not `passlib`, which imports the `crypt` stdlib module
> removed in Python 3.13+), so it runs on modern Python.

## Quickstart

```python
from fastapi import Depends
from fastapi_passport import Application, AuthProvider, AuthConfig, current_user, require_scopes
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
| `memory` | in-memory dict store (`users=[...]`) — great for tests/demos |
| `instance` | pass a ready `UserProvider` via `{"instance": ...}` |
| `factory` | pass a zero-arg callable returning a `UserProvider` |

Any object implementing the `UserProvider` protocol
(`retrieve_by_id`, `retrieve_by_credentials`, `validate_credentials`,
`get_identifier`, `update_password`) is a valid provider.

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
pip install -e ".[test]"
pytest
```

## License

MIT
