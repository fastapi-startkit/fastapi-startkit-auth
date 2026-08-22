# Auth roadmap: cookie, SPA, and API-token authentication

`fastapi-startkit-auth` currently ships one of the four auth modes from the
product vision: the full OAuth2 server (Passport-style grants + JWT access
tokens). This document is the sequenced implementation plan for the remaining
three modes. It is a design/planning artifact — no feature code lands with it.

| Phase | Feature | Depends on | Status |
| --- | --- | --- | --- |
| 0 | Guard-driver groundwork (refactor, no behavior change) | — | planned |
| 1 | Cookie-based (session) authentication | Phase 0 | planned |
| 2 | SPA authentication (CSRF cookie + protection) | Phase 1 | planned |
| 3 | Token-based (API token) authentication | Phase 0 only | planned |

**Sequencing rationale.** Cookie/session auth is the foundation: the SPA mode
*is* cookie auth plus CSRF and CORS ergonomics, so Phase 2 strictly follows
Phase 1. API-token auth shares nothing with sessions — it only needs the
guard-driver registry from Phase 0 — so Phase 3 can proceed in parallel with
Phase 2 once Phase 1's groundwork is merged.

---

## What we reuse from the existing OAuth2 code

The survey of the current package found these patterns that every phase builds
on rather than reinvents:

- **Config model** — `AuthConfig` class attributes (`default` / `guards` /
  `providers` / `passwords`) mirroring `config/auth.php`. New modes are new
  guard *drivers* (`"session"`, `"token"`) next to the existing `"passport"`,
  plus new top-level config sections (`session`, `spa`) with sane defaults.
- **Manager wiring** — `AuthManager` builds named guards/providers/brokers from
  config and exposes them by name. New guards slot into `_build_guard`.
- **Provider registration** — `AuthProvider.register(app)` puts the manager on
  `app.state.auth_manager`, mounts routers, installs the `AuthError` JSON
  handler. Session middleware and CSRF middleware register in the same place.
- **User providers** — the `UserProvider` protocol (`retrieve_by_id`,
  `retrieve_by_credentials`, `validate_credentials`, …) is auth-mode agnostic;
  session and token guards consume it unchanged.
- **Storage pattern** — `InMemoryTokenRepository` / `InMemoryClientRepository` /
  `InMemoryPasswordResetRepository` define a documented method surface that
  apps re-implement against a real database. Session and API-token stores
  follow the exact same pattern (in-memory default + protocol).
- **DI pattern** — `current_user` / `optional_user` / `require_scopes` read the
  manager from `app.state`. They gain multi-guard resolution instead of being
  duplicated per mode.
- **Error taxonomy** — `AuthError` subclasses with `error` codes rendered by a
  single handler. New failures (CSRF mismatch, invalid session) join it.
- **Hashing** — `BcryptHasher` for credentials; API-token secrets use SHA-256
  (high-entropy random input, bcrypt unnecessary and too slow per-request).
- **Publish flow** — publishing is **provider-driven** (confirmed in task #1500,
  see [package-publish-contract.md](notes/package-publish-contract.md)). There is
  no manifest and no `package:publish` command. The package ships a framework-native
  **`AuthServiceProvider`** (extends `fastapi_startkit.support.Provider`) that calls
  `self.publishes({...})`; users publish the CORS stub with the framework's real
  command **`provider:publish -p auth`**. The framework dependency is an **optional
  extra** (`fastapi-startkit-auth[startkit]`) — the package still runs standalone on
  plain FastAPI, and the provider only activates when the app registers it.

---

## Phase 0 — Guard-driver groundwork (small refactor PR)

`AuthManager._build_guard` currently hardcodes `PassportGuard`. Before adding
modes, introduce a driver registry so guards are constructed by their config
`driver` key.

**Changes**

- `manager.py`: `_build_guard` dispatches on `spec["driver"]` via a
  `dict[str, factory]`; unknown drivers raise the existing `ValueError` style.
- `guards/__init__.py`: export a base `Guard` protocol (`user_from_token` →
  generalize to `authenticate(request) -> AuthContext` in later phases;
  Phase 0 keeps `PassportGuard`'s surface intact).
- No public-API or behavior change; pure enabling refactor.

**Tests** — existing suite must pass untouched; add one unit test asserting an
unknown guard driver raises a clear error.

---

## Phase 1 — Cookie-based (session) authentication

### Public API surface

```python
from fastapi_startkit_auth import Auth, current_user

@api.post("/login")
def login(auth: Auth = Depends(Auth.scoped)):
    auth.login(1)                      # by id
    # auth.attempt({"email": ..., "password": ...})  # by credentials
    return {"ok": True}

@api.post("/logout")
def logout(auth: Auth = Depends(Auth.scoped)):
    auth.logout()
```

- `Auth` — request-scoped facade: `login(user_or_id)`, `attempt(credentials)`,
  `logout()`, `user()`, `id()`, `check()`, `guard(name)`. The vision's
  `from fastapi_starkit.auth import Auth; Auth.login(1)` is the framework
  re-exporting this class; inside this package it lives at
  `fastapi_startkit_auth.Auth`.
- Config: `guards = {"web": {"driver": "session", "provider": "users"}}` plus a
  new `session` section (cookie name, ttl, `same_site`, `secure`, `http_only`,
  `domain`, `path`).
- `current_user` / `optional_user` resolve through the default guard, so route
  code is identical for session- and token-authenticated apps.
- The package ships **no** built-in `/login` / `/logout` routes (confirmed
  decision): it exposes only the `Auth` facade, guards, and session middleware,
  and the app wires its own routes as in the example above.

### Files / modules

| Path | Purpose |
| --- | --- |
| `sessions/models.py` | `SessionRecord` (id, user_id, guard, csrf_token, created_at, last_activity, expires_at) |
| `sessions/store.py` | `SessionStore` protocol + `InMemorySessionStore` (mirrors `InMemoryTokenRepository` shape: `create`, `find`, `invalidate`, `regenerate_id`, `purge_expired`) |
| `sessions/sql.py` | `SqlSessionStore`: persistent SQL implementation of the same protocol (sessions table) |
| `guards/session.py` | `SessionGuard`: resolves session cookie → `AuthContext(user=..., scopes=["*"])`; `login`/`logout` primitives |
| `facade.py` | `Auth` request-scoped facade over the manager + request session |
| `middleware/session.py` | Starlette middleware: read cookie → attach session to `request.state`; set/refresh cookie on response |
| `dependencies.py` (change) | guard-aware resolution: default guard decides cookie vs bearer; explicit `current_user(guard="web")` override |
| `manager.py` (change) | build `SessionGuard` for `driver: "session"`; own the `SessionStore` |
| `provider.py` (change) | install session middleware when any session guard is configured |
| `config.py` (change) | `session` defaults |

### Data model & storage

Server-side sessions (opaque random id in the cookie, record in the store) —
not client-side signed cookies — so logout/revocation is authoritative and the
model matches the package's existing repository pattern. Session ids are
generated with `secrets.token_urlsafe(32+)` and looked up by exact key.

Storage ships in three layers (confirmed decision — SQL persistence is in
scope, not follow-up work):

1. `SessionStore` protocol — the contract everything programs against;
2. `InMemorySessionStore` — default, tests/demos, matches the OAuth2 stores;
3. `SqlSessionStore` — persistent implementation backed by a `sessions` table
   (id PK, user_id, guard, csrf_token, created_at, last_activity, expires_at),
   selected via config (e.g. `session = {"store": "sql", ...}`), following the
   same driver-selection style as `providers`.

### Config / publish steps

None required for plain cookie auth. Document a `session` config block with
defaults: `cookie="startkit_session"`, `ttl=7200`, `http_only=True`,
`same_site="lax"`, `secure=True` (opt-out for local dev).

### Security considerations

- **Session fixation** — `login()` always regenerates the session id
  (`regenerate_id` invalidates the old record atomically).
- **Cookie flags** — `HttpOnly` + `SameSite=Lax` + `Secure` defaults; warn (like
  the existing ephemeral-key warning) when `secure=False`.
- **Logout** — deletes the server-side record, not just the cookie.
- **Absolute + idle expiry** — `expires_at` and `last_activity` sliding window.
- **No user enumeration** — `attempt()` failure is a single generic 401,
  matching the password-broker precedent.

### Test + QA strategy

- Unit: session store (create/find/expire/regenerate), `SessionGuard`, `Auth`
  facade against the in-memory provider (reuse `conftest.py` app builders).
- Integration: `TestClient` cookie round-trip — login sets cookie, `/me` works,
  logout kills it, old session id dead after regeneration.
- Security tests: fixation (pre-login id ≠ post-login id), expired-session 401,
  cookie flag assertions.
- QA checklist: manual browser flow against the demo app; verify OAuth2 flows
  are untouched when no session guard is configured.

---

## Phase 2 — SPA authentication (cookie auth + CSRF)

### Public API surface

```js
// SPA bootstraps CSRF, then logs in with cookies
axios.get('/__auth__/csrf-cookie').then(() => {
  axios.post('/login', {email, password});   // X-XSRF-TOKEN sent by axios
});
```

- `GET /__auth__/csrf-cookie` → 204, sets `XSRF-TOKEN` cookie (readable by JS,
  **not** HttpOnly) bound to the server-side session's `csrf_token`.
- CSRF middleware: unsafe methods (`POST/PUT/PATCH/DELETE`) on
  session-authenticated requests must send `X-XSRF-TOKEN` matching the session
  token; mismatch raises `CsrfTokenMismatch` (`403`, `error:
  "csrf_token_mismatch"`) through the existing `AuthError` handler.
- Config: `spa` section — `stateful_origins` (Sanctum-style list of first-party
  origins that get cookie auth; others must use tokens), `csrf_exempt_paths`,
  csrf cookie name.
- Publish: `AuthServiceProvider` (framework-native) exposes the CORS stub to the
  framework's `provider:publish -p auth`. Only available when the app installs the
  optional `fastapi-startkit-auth[startkit]` extra and registers the provider in its
  `providers=[...]` list; the package remains fully usable standalone without it.

### Files / modules

| Path | Purpose |
| --- | --- |
| `middleware/csrf.py` | verify header vs session token; issue/refresh `XSRF-TOKEN` cookie |
| `routes_spa.py` (or extend `routes.py`) | `/__auth__/csrf-cookie` endpoint |
| `exceptions.py` (change) | `CsrfTokenMismatch(AuthError)` |
| `sessions/models.py` (change) | `csrf_token` on `SessionRecord`, rotated on login |
| `provider.py` (change) or `startkit/provider.py` (new) | `AuthServiceProvider(fastapi_startkit.support.Provider)` — `provider_key = "auth"`, calls `self.publishes({<pkg>/publishable/cors.py: "config/cors.py"})`; imported lazily so it only loads when the `[startkit]` extra is present |
| `publishable/cors.py` | CORS config stub copied into the app by `provider:publish -p auth` |
| `config.py` (change) | `spa` defaults |
| `pyproject.toml` (change) | add `startkit = ["fastapi-startkit>=0.51"]` optional extra |

### Data model & storage

No new stores — the CSRF token is a field on the Phase 1 `SessionRecord`
(session-bound synchronizer token delivered via cookie, i.e. the
double-submit-with-state pattern; strictly stronger than stateless
double-submit).

### Config / publish steps

- `uv run python artisan provider:publish -p auth` copies `publishable/cors.py`
  into the app's config directory (as `config/cors.py`). The stub configures
  Starlette `CORSMiddleware` with `allow_credentials=True` and an **explicit**
  origin list (never `*` with credentials) matching `spa.stateful_origins`.
- Mechanism (confirmed in **task #1500**, see
  [package-publish-contract.md](notes/package-publish-contract.md)): publishing is
  **provider-driven**, not manifest-driven, and there is no `package:publish`
  command. `AuthServiceProvider.publishes({...})` registers the stub into
  `application.published_resources`; the framework's `provider:publish` copies it,
  prompting before overwriting an existing file. Package config defaults are exposed
  via `merge_config_from` so the published file only *overrides* (use a
  non-reserved key such as `cors`).
- Requires the app to install `fastapi-startkit-auth[startkit]` and register
  `AuthServiceProvider`. The CSRF endpoint and middleware do **not** depend on the
  framework and work standalone.

### Security considerations

- CSRF token is per-session, high-entropy, rotated on login/regeneration, and
  compared constant-time (`secrets.compare_digest`).
- Only *cookie-authenticated* requests are CSRF-checked — bearer-token requests
  are exempt by design (no ambient credential).
- `Origin`/`Referer` validation against `stateful_origins` as defense in depth.
- CORS with credentials requires exact origins; the published stub encodes
  that and refuses wildcard.
- `XSRF-TOKEN` cookie carries `Secure` + `SameSite=Lax` but not `HttpOnly` (it
  must be JS-readable — that is the mechanism, not a leak: it's useless without
  the HttpOnly session cookie).

### Test + QA strategy

- Unit: middleware accepts matching header, rejects missing/wrong/stale token;
  exempt paths and safe methods skip the check; bearer requests bypass it.
- Integration: full axios-shaped flow with `TestClient` — get csrf-cookie →
  login → mutate; assert 403 without header, 200 with.
- Security tests: token not rotated ⇒ fails after re-login; cross-origin
  request with valid session but foreign Origin rejected.
- QA checklist: real SPA smoke test (vite + axios demo) against dev server with
  CORS stub published via `provider:publish -p auth`; confirm `withCredentials`
  flow end-to-end.

---

## Phase 3 — Token-based (API token) authentication

Sanctum-style opaque tokens for mobile/CLI/third-party API access.
Independent of sessions; requires only Phase 0.

### Public API surface

```python
token = manager.api_tokens.create(user_id=1, name="cli", abilities=["posts:read"])
token.plain_text   # "1|Xk3f..." — shown exactly once

# request:  Authorization: Bearer 1|Xk3f...
@api.get("/me")
def me(user=Depends(current_user)):   # guard {"driver": "token"} resolves it
    ...
```

- Config: `guards = {"api": {"driver": "token", "provider": "users"}}` and an
  `api_tokens` section (`expire` days or `None`, token prefix).
- Optional router: `POST/GET/DELETE /__auth__/tokens` for self-service token
  management (auth required), mirroring the existing personal-access-token
  routes' shape.
- Abilities reuse `AuthContext.scopes`, so `require_scopes` works unchanged.

**Relation to existing JWT personal access tokens:** those are OAuth2 artifacts
(signed JWTs, server-side revocation list). API tokens are opaque
database-backed credentials: no signature, revocation is row deletion,
`last_used_at` tracking, and no dependency on the JWT signing key. Both stay;
docs will state when to use which.

### Files / modules

| Path | Purpose |
| --- | --- |
| `apitokens/models.py` | `ApiTokenRecord` (id, user_id, name, token_hash, abilities, last_used_at, expires_at, created_at) |
| `apitokens/repository.py` | `ApiTokenRepository` protocol + in-memory impl (existing repository pattern) |
| `apitokens/sql.py` | `SqlApiTokenRepository`: persistent SQL implementation of the same protocol (`personal_api_tokens` table) |
| `apitokens/service.py` | create (generate `{id}|{secret}`, store SHA-256 of secret), verify, revoke, purge |
| `guards/token.py` | `TokenGuard`: split bearer on `|`, O(1) lookup by id, constant-time hash compare → `AuthContext` |
| `manager.py` (change) | wire `driver: "token"`, own repository/service |
| `routes_tokens.py` (optional) | self-service token management router |

### Data model & storage

Token = `"{record_id}|{secret}"` where secret is `secrets.token_urlsafe(40)`.
Store only `sha256(secret)`; the id makes lookup O(1) so verification is one
fetch + one constant-time compare (no scan, no timing side-channel on
existence).

As with sessions, storage ships in three layers (confirmed decision):
`ApiTokenRepository` protocol, `InMemoryApiTokenRepository` default, and
`SqlApiTokenRepository` backed by a `personal_api_tokens` table (id PK,
user_id, name, token_hash, abilities, last_used_at, expires_at, created_at),
selected via the `api_tokens` config block.

### Config / publish steps

None mandatory; document the `api_tokens` config block. If a publishable config
stub is wanted later it follows the Phase 2 mechanism — a framework-native provider
calling `self.publishes({...})`, published via `provider:publish` (no manifest).

### Security considerations

- **Hash at rest** — SHA-256 is correct for 240-bit random secrets (bcrypt adds
  latency per API request, no security for non-guessable input).
- **Show once** — plaintext only in the creation response.
- **Constant-time compare** — `secrets.compare_digest` on hashes.
- **Expiry + revocation** — optional `expires_at`, delete-to-revoke,
  `purge_expired` maintenance mirroring the token repository.
- **Rate-limit issuance** — reuse the throttle pattern from the password broker
  on the management endpoints.

### Test + QA strategy

- Unit: service create/verify/revoke/expire; guard rejects malformed, unknown
  id, wrong secret, expired, revoked; abilities flow into `require_scopes`.
- Integration: issue token via route → call protected route → revoke → 401.
- Security tests: plaintext never retrievable post-creation; repository stores
  only hashes; timing-safe verification path covered.
- QA checklist: curl-driven flow against the demo app; confirm coexistence with
  passport guard (two guards, both drivers, no cross-talk).

---

## Cross-cutting concerns

- **Backwards compatibility** — default config keeps `driver: "passport"`;
  every phase is additive and gated on config. Existing test suite must stay
  green after each phase.
- **Multi-guard `current_user`** — after Phase 1, dependency resolution honors
  the configured default guard and accepts an explicit guard override; one
  shared code path, not per-mode dependencies.
- **Docs per phase** — each phase PR adds its docs page (`cookie-auth.md`,
  `spa-auth.md`, `api-tokens.md`) and mkdocs nav entry, following the existing
  docs site structure.
- **PR slicing** — Phase 0 is its own small PR; Phases 1–3 are one PR each,
  keeping review scope bounded. Each goes through the standard QA + code-review
  loop before the next dependent phase starts.

## Resolved decisions

1. **No built-in login routes.** The package does not ship `/login` /
   `/logout`; it exposes only the `Auth` facade, guards, and middleware, and
   the app wires its own routes. (The SPA `/__auth__/csrf-cookie` endpoint is
   unaffected — it is infrastructure, not a login route.)
2. **SQL persistence is in scope.** Sessions (Phase 1) and API tokens
   (Phase 3) each ship a protocol interface, an in-memory default, and a
   SQL-backed implementation selected via config.
3. **Publish contract is provider-driven** (resolved by task #1500, see
   [package-publish-contract.md](notes/package-publish-contract.md)). There is no
   manifest and no `package:publish` command. Phase 2 ships a framework-native
   `AuthServiceProvider` that publishes the CORS stub via `self.publishes({...})`,
   published with the real command `provider:publish -p auth`. The `fastapi-startkit`
   framework is an **optional extra** (`fastapi-startkit-auth[startkit]`); the package
   works standalone on plain FastAPI and the provider activates only when the app
   opts in.
