# Cookie authentication

Cookie/session authentication for classic browser apps: an opaque session id in
an `HttpOnly` cookie, backed by a server-side session record. Logout and
revocation are authoritative because the browser only ever holds the id.

The package ships **no** `/login` or `/logout` routes — you wire your own with
the `Auth` facade, so the request/response shape stays fully yours.

## Quickstart

```python
from fastapi import Body, Depends
from fastapi_startkit_auth import (
    Application, Auth, AuthConfig, AuthProvider, InvalidSession, current_user,
)

class Config(AuthConfig):
    key = "..."  # stable secret
    default = {"guard": "web", "passwords": "users"}
    guards = {"web": {"driver": "session", "provider": "users"}}
    providers = {"users": {"driver": "memory", "users": [...]}}

app = Application([(AuthProvider, Config)])
api = app.api

@api.post("/login")
def login(payload: dict = Body(...), auth: Auth = Depends(Auth.scoped)):
    if not auth.attempt(payload):          # {"email": ..., "password": ...}
        raise InvalidSession("Invalid credentials.")
    return {"ok": True}

@api.post("/logout")
def logout(auth: Auth = Depends(Auth.scoped)):
    auth.logout()
    return {"ok": True}

@api.get("/me")
def me(user=Depends(current_user)):        # resolves via the session cookie
    return user
```

When any guard uses `{"driver": "session"}`, `AuthProvider` automatically
installs the session middleware that loads the session from the cookie before
your routes run and issues the cookie after them.

## The `Auth` facade

Request-scoped; obtain it with `Depends(Auth.scoped)`.

| Method | Purpose |
| --- | --- |
| `login(user_or_id)` | Start a session for a user instance or id; always issues a fresh session id |
| `attempt(credentials)` | Look up + verify credentials, then `login`; returns `bool`, never leaks which part failed |
| `logout()` | Delete the server-side session and expire the cookie |
| `user()` / `id()` / `check()` | Current user / identifier / authenticated? — never raise |
| `guard(name)` | Access a configured guard by name |

## Session configuration

Defaults (override any subset via `AuthConfig.session` — partial dicts merge):

```python
class Config(AuthConfig):
    session = {
        "store": "memory",            # "memory" | "sql" | "instance"
        "cookie": "startkit_session",
        "ttl": 7200,                  # absolute lifetime (seconds)
        "idle_ttl": None,             # optional sliding inactivity window
        "http_only": True,
        "same_site": "lax",
        "secure": True,               # opt out for local dev only (warns)
        "domain": None,
        "path": "/",
        "purge_interval": 300,        # seconds between SQL purge-on-create sweeps
    }
```

## Session stores

Everything programs against the `SessionStore` protocol (`create`, `find`,
`touch`, `regenerate_id`, `invalidate`, `purge_expired`); both bundled
implementations pass the same contract test suite.

- **`InMemorySessionStore`** (default) — dict-backed, for tests, demos, and
  single-process apps; mirrors the package's other in-memory repositories.
- **`SqlSessionStore`** — persistent `sessions` table via any DB-API 2.0
  connection using `qmark` placeholders (sqlite3 works out of the box):

```python
import sqlite3

class Config(AuthConfig):
    session = {
        "store": "sql",
        "connection": lambda: sqlite3.connect("app.db", check_same_thread=False),
        "table": "sessions",  # optional
    }
```

A custom store plugs in with `{"store": "instance", "instance": my_store}`.

## Security properties

- **Fixation protection** — `login()` always generates a new session id and
  invalidates any session that arrived with the request.
- **Authoritative logout** — `logout()` deletes the server-side record; a
  replayed old cookie is a 401, not a ghost session.
- **Cookie flags** — `HttpOnly`, `SameSite=Lax`, and `Secure` by default;
  setting `secure=False` emits a warning so it never slips into production.
- **Expiry** — absolute `ttl` plus optional `idle_ttl` sliding window
  (activity slides it; inactivity kills the session).
- **No enumeration** — `attempt()` returns a single `False` for unknown user
  and wrong password alike, with a timing-equalizing dummy hash verification.

## Next step: SPAs

Serving a single-page app on these sessions? Enable [SPA
authentication](spa-auth.md) to add CSRF protection (the
`/__auth__/csrf-cookie` endpoint plus the double-submit middleware) on top of
this cookie flow.
