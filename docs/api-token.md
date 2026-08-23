# API token authentication

Sanctum-style opaque tokens for mobile apps, CLIs, and third-party API access.
A token is a random `"{id}|{secret}"` string handed to the client **once**;
the server stores only a SHA-256 hash of the secret, so a leaked database
cannot reproduce valid tokens. No sessions, no cookies, no JWT signing key —
only Phase 0's guard registry.

## Quickstart

```python
from fastapi import Depends
from fastapi_startkit_auth import Application, AuthProvider, AuthConfig, current_user


class Config(AuthConfig):
    key = "..."
    default = {"guard": "api", "passwords": "users"}
    guards = {"api": {"driver": "token", "provider": "users"}}
    providers = {"users": {"driver": "memory", "users": [...]}}


app = Application([(AuthProvider, Config)])


@app.api.get("/me")
def me(user=Depends(current_user)):   # resolves via Authorization: Bearer {id}|{secret}
    return user
```

Issue a token from anywhere you hold the manager (a route, a CLI command, a
seeder):

```python
manager = app.api.state.auth_manager

issued = manager.api_tokens.create(user_id=1, name="cli", abilities=["posts:read"])
issued.plain_text        # "K7f...|Xk3f..." — show it to the user NOW; it cannot be shown again
issued.record.id         # the id half; use it to revoke or list
```

The client then authenticates with:

```
Authorization: Bearer {id}|{secret}
```

## Managing tokens

The package ships **no** token-management HTTP routes (the same
app-owns-routes decision as login/logout) — wire your own around
`manager.api_tokens`:

| Call | Effect |
| --- | --- |
| `create(user_id, name=None, abilities=None, expires_at=None)` | Issue a token; returns `NewApiToken` with the one-time `plain_text` |
| `verify(plain_text)` | Resolve a token to its record or raise a generic 401 |
| `revoke(token_id)` | Delete one token (revocation is row deletion) |
| `revoke_all(user_id)` | Delete every token the user holds |
| `tokens_for(user_id)` | List the user's live token records (never the secrets) |

Example self-service routes:

```python
@app.api.post("/tokens")
def create_token(name: str, user=Depends(current_user)):
    issued = manager.api_tokens.create(user_id=user["id"], name=name)
    return {"token": issued.plain_text, "id": issued.record.id}   # shown once

@app.api.delete("/tokens/{token_id}")
def revoke_token(token_id: str, user=Depends(current_user)):
    for record in manager.api_tokens.tokens_for(user["id"]):
        if record.id == token_id:
            manager.api_tokens.revoke(token_id)
    return {"ok": True}
```

!!! note "Rate-limit issuance"
    Token creation endpoints mint credentials — put your rate limiter in front
    of them, as you would a login route.

## Abilities

Abilities are the token-scoped permission list (default `["*"]` =
unrestricted). They flow into `AuthContext.scopes`, so enforcement is the
same dependency you already use for OAuth2 scopes — `require_abilities` is
the Sanctum-flavored alias of `require_scopes`:

```python
from fastapi_startkit_auth import require_abilities

@app.api.get("/posts")
def posts(ctx=Depends(require_abilities("posts:read"))):
    ...
```

A token lacking the ability gets `403 insufficient_scope`.

## Configuration

Defaults (override any subset via `AuthConfig.api_tokens` — partial dicts
merge):

```python
class Config(AuthConfig):
    api_tokens = {
        "store": "memory",           # "memory" | "sql" | "instance"
        "header": "Authorization",   # where the guard reads the token
        "ttl": None,                 # default lifetime (seconds); None = non-expiring
        "purge_interval": 300,       # throttles the purge-on-issue sweep
    }
```

- `header` — the default `"Authorization"` expects the `Bearer` scheme; any
  other name (e.g. `"X-Api-Token"`) is read as the raw token value.
- `ttl` — applied at creation when no explicit `expires_at` is passed;
  expired tokens fail verification and are swept opportunistically on the
  next issue (mirroring the session store's purge-on-create).

## Token stores

Everything programs against the `ApiTokenRepository` protocol (`create`,
`find`, `touch`, `revoke`, `revoke_all_for_user`, `list_for_user`,
`purge_expired`); both bundled implementations pass the same contract test
suite.

- **`InMemoryApiTokenRepository`** (default) — dict-backed, for tests, demos,
  and single-process apps.
- **`SqlApiTokenRepository`** — persistent `personal_api_tokens` table via any
  DB-API 2.0 connection using `qmark` placeholders (sqlite3 works out of the
  box):

```python
import sqlite3

class Config(AuthConfig):
    api_tokens = {
        "store": "sql",
        "connection": lambda: sqlite3.connect("app.db", check_same_thread=False),
        "table": "personal_api_tokens",  # optional
    }
```

A custom store plugs in with `{"store": "instance", "instance": my_repo}`.

## API tokens vs. OAuth2 personal access tokens

Both stay; pick by need:

| | API tokens (this page) | Personal access tokens (Passport) |
| --- | --- | --- |
| Format | Opaque `id\|secret`, DB-backed | Signed JWT + server-side record |
| Verification | One O(1) lookup + hash compare | Signature check + revocation lookup |
| Revocation | Delete the row | Mark the `jti` revoked |
| Signing key | Not needed | Requires the JWT `key` |
| Fits | First-party mobile/CLI clients | OAuth2 ecosystems already using Passport flows |

## Security properties

- **Hash at rest** — only `sha256(secret)` is stored. SHA-256 (not bcrypt) is
  the right tool here: the secret is 240 bits of randomness, so key
  stretching adds per-request latency without adding security.
- **Shown once** — the plaintext exists only in the `NewApiToken` returned by
  `create()`; it is never persisted, logged, or reconstructable.
- **Constant-time verification** — lookup is by id (no scan), then one
  `secrets.compare_digest` of hashes; unknown ids compare against a dummy
  hash so the miss path costs the same as a mismatch.
- **No enumeration** — malformed, unknown, wrong-secret, expired, and revoked
  tokens all fail with the same generic 401.
- **Expiry + revocation** — optional `expires_at` honored on every
  verification; revocation is deletion, so a revoked token is dead
  immediately across all processes sharing the store.
