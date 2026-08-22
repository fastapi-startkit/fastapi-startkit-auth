# SPA authentication

SPA mode is [cookie authentication](cookie-auth.md) plus CSRF protection: the
browser keeps the HttpOnly session cookie, and every state-changing request
must echo a per-session CSRF token that only your first-party JavaScript can
read. It is the Sanctum-style flow for single-page apps (Vue/React on Vite,
etc.) talking to a FastAPI backend.

## Enabling SPA mode

SPA mode is opt-in on top of a session guard:

```python
from fastapi_startkit_auth import Application, AuthProvider, AuthConfig


class Config(AuthConfig):
    key = "..."
    default = {"guard": "web", "passwords": "users"}
    guards = {"web": {"driver": "session", "provider": "users"}}
    providers = {"users": {"driver": "memory", "users": [...]}}
    spa = {
        "enabled": True,
        "stateful_origins": ["http://localhost:5173"],
    }


app = Application([(AuthProvider, Config)])
```

Enabling it registers two things:

- `GET /__auth__/csrf-cookie` — the SPA bootstrap endpoint;
- the CSRF middleware, which enforces the token on unsafe methods.

Without `spa["enabled"]`, cookie auth behaves exactly as in Phase 1 — no CSRF
endpoint, no enforcement.

## The axios flow

```js
// 1. Prime the CSRF cookie once (e.g. on app start), then log in.
await axios.get('/__auth__/csrf-cookie', { withCredentials: true });
await axios.post('/login', { email, password }, { withCredentials: true });

// 2. Authenticated, cookie-carrying requests just work; axios reads the
//    XSRF-TOKEN cookie and sends the X-XSRF-TOKEN header automatically.
await axios.post('/posts', { title: '...' }, { withCredentials: true });
```

What happens under the hood:

1. `GET /__auth__/csrf-cookie` returns `204` and sets two cookies: the HttpOnly
   session cookie (starting a **guest session** if you have none) and the
   `XSRF-TOKEN` cookie carrying the session's CSRF token. `XSRF-TOKEN` is
   deliberately **not** HttpOnly — the SPA must read it — and that is the
   mechanism, not a leak: the token is useless without the HttpOnly session
   cookie.
2. Axios (and most SPA HTTP clients) automatically copy the `XSRF-TOKEN`
   cookie into the `X-XSRF-TOKEN` header on every subsequent request.
3. The middleware compares the header against the server-side session token in
   constant time. Mismatch or absence on an unsafe method → `403`
   `csrf_token_mismatch`.
4. Logging in rotates the session id **and** the CSRF token (fixation
   protection); the response re-sets both cookies, so the client keeps working
   without extra calls. Logging out deletes both.

## What is checked, what is exempt

| Request | CSRF check |
| --- | --- |
| `POST` / `PUT` / `PATCH` / `DELETE` with a session cookie | required |
| `GET` / `HEAD` / `OPTIONS` | exempt (safe methods) |
| Requests without a session cookie (bearer/API-token clients) | exempt — no ambient credential, nothing to forge |
| Paths listed in `spa["csrf_exempt_paths"]` | exempt (e.g. third-party webhooks) |

When `stateful_origins` is configured, unsafe session-authenticated requests
that carry an `Origin` header from outside the list are rejected before the
token is even checked — defense in depth against cross-origin abuse.

## Configuration

```python
spa = {
    "enabled": False,             # opt-in switch
    "csrf_cookie": "XSRF-TOKEN",  # JS-readable cookie name
    "csrf_header": "X-XSRF-TOKEN",# header the middleware verifies
    "csrf_exempt_paths": [],      # exact paths, or prefixes ending with "*"
    "stateful_origins": [],       # first-party origins; empty = no Origin check
}
```

The CSRF cookie inherits the session cookie's `secure`, `same_site`, `domain`,
`path`, and `ttl` settings from the `session` config block.

## CORS for cross-origin SPAs

If the SPA is served from a different origin than the API (the usual Vite dev
setup), the browser needs CORS with credentials — and that requires an
**explicit** origin list; `*` silently breaks credentialed requests.

### With the fastapi-startkit framework

The package ships a framework-native provider that publishes a ready-made CORS
config stub. Install the optional extra and register the provider:

```bash
pip install "fastapi-startkit-auth[startkit]"
```

```python
from fastapi_startkit_auth import AuthServiceProvider

# in your fastapi-startkit application
providers = [
    # ...
    AuthServiceProvider,
]
```

Then publish the stub into your project:

```bash
python artisan provider:publish -p auth   # copies config/cors.py
```

Edit `config/cors.py` so `ALLOW_ORIGINS` matches your
`spa["stateful_origins"]`, and wire it into Starlette's `CORSMiddleware` as
shown in the stub's docstring. The stub's defaults are also merged under the
`cors` config key, so the published file only overrides them.

### Standalone (plain FastAPI)

The framework is optional — everything on this page except `provider:publish`
works on plain FastAPI. Configure CORS directly:

```python
from starlette.middleware.cors import CORSMiddleware

app.api.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # never "*" with credentials
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-XSRF-TOKEN"],
)
```

## Security notes

- The CSRF token is per-session, high-entropy, **rotated on login**, and
  compared with `secrets.compare_digest` (constant-time).
- The check is session-bound (double-submit **with state**): a forged or
  replayed cookie value cannot pass, because the header must match the token
  stored server-side for that exact session.
- Bearer-token requests are exempt by design: CSRF is an attack on ambient
  cookie credentials, which those requests do not use.
- Keep `session["secure"] = True` in production; the CSRF cookie follows it.
