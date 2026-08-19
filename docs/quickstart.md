# Quickstart

Register the `AuthProvider` with an `Application`, then protect routes with the
provided dependencies.

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

## Serve it

`Application` is ASGI-callable, so point your server at either the app or its
FastAPI instance:

```bash
uvicorn myapp:app        # Application is ASGI-callable
uvicorn myapp:app.api    # or serve the FastAPI instance directly
```

## Get a token

Once running, exchange credentials for a JWT access token:

```bash
curl -X POST localhost:8000/oauth/token \
  -d grant_type=password -d username=ada@example.com -d password=secret -d scope="read write"
# → { "access_token": "...", "token_type": "Bearer", "expires_in": 3600,
#     "refresh_token": "...", "scope": "read write" }
```

Call a protected route with the token:

```bash
curl localhost:8000/me -H "Authorization: Bearer <access_token>"
```

Next: tune the [configuration](configuration.md), pick a
[provider](providers.md), and explore the full [HTTP endpoints](endpoints.md).
