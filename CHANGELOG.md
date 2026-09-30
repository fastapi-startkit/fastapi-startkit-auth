# Changelog

All notable changes to `fastapi-startkit-auth` are documented in this file.

Release notes are also published on
[GitHub Releases](https://github.com/fastapi-startkit/fastapi-startkit-auth/releases).

## [Unreleased]

## [0.4.0]

### Added

- Async support for async ORMs and drivers, side by side with the sync API:
  - `AsyncModelUserProvider` (provider driver `"async_model"`) for models whose
    `find` / `where(...).first()` / `save` are coroutines; bcrypt runs in a
    worker thread.
  - `AsyncPassportGuard`, `AsyncSessionGuard`, `AsyncTokenGuard`,
    `AsyncTokenService`, `AsyncApiTokenManager`, `AsyncPasswordBroker`, the
    `Async*Grant` variants and the `AsyncAuth` facade.
  - `AuthManager` picks the async variant automatically when any provider
    method or store method is async; sync configurations keep getting the sync
    classes. Sync collaborators used from the async classes run in the
    threadpool.
  - `"async_sql"` stores for sessions (`AsyncSqlSessionStore`), personal API
    tokens (`AsyncSqlApiTokenRepository`) and a new `AuthConfig.tokens` block
    for OAuth access/refresh tokens and authorization codes
    (`AsyncSqlTokenRepository`). They accept an asyncpg pool/connection, an
    aiosqlite connection, or a zero-arg (async) factory. Supported backends are
    PostgreSQL and SQLite. Refresh tokens and authorization codes are stored as
    SHA-256 hashes; refresh revocation and code redemption are atomic and use
    only portable SQL. Expired rows are purged via `expires_at` indexes.
  - `fastapi-startkit` migrations for the five tables, published to
    `databases/migrations/` by `AuthServiceProvider`.
- `password_key` provider option: the credentials key holding the plaintext
  password, separate from the model column `password_field` (e.g.
  `password_key="password"`, `password_field="hashed_password"`). Defaults to
  `password_field`.
- `is_active` provider option (attribute name or callable; `async def` with
  the `async_model` driver). Inactive or deleted users are rejected by the
  password grant, the refresh and authorization-code grants, `Auth.attempt` /
  `AsyncAuth.attempt` and every guard, and introspect as inactive.
- `AsyncMisconfiguration`: raised when a sync guard, grant, broker or `Auth`
  receives an awaitable from a provider or store, so a half-async provider
  fails closed. Sync providers reject an `async def` `is_active` hook.
- CI runs the asyncpg store and flow tests against a Postgres service.
- `Typing :: Typed` classifier (the package already ships `py.typed`).

### Changed

- **Breaking (signature):** `current_context` and `optional_user` are now
  `async def` dependencies. `Depends(current_user)` and friends keep working
  unchanged; code calling them directly as plain functions must now await
  them. Sync guards still run in the threadpool.
- The built-in OAuth, password-reset and SPA csrf-cookie routes await async
  collaborators; `SessionMiddleware` accepts an async session store.
- `Auth` (sync facade) raises `RuntimeError` for async session guards; use
  `AsyncAuth` there.
- Minimum supported Python is now 3.10. 0.3.0 advertised `>=3.9` but fails on
  3.9 because runtime-evaluated annotations use `X | None` syntax.
- The `startkit` extra is bounded to `fastapi-startkit>=0.51,<1.0`.
- The package `__init__` imports its public API directly instead of through a
  lazy export table.
- The source distribution now ships the test suite and this changelog.
- Releases are published from GitHub Actions via PyPI trusted publishing on
  `vX.Y.Z` tags, replacing `bin/release.sh`.

## [0.3.0]

First release published to PyPI. Contains the 0.2.0 feature set, built with
the `uv_build` backend; no functional changes.

## [0.2.0]

Adds three new authentication modes alongside the existing OAuth2/JWT server,
so the package now covers the full Laravel-style auth surface.

### Added

- Guard-driver registry in `AuthManager`: guards resolve their driver
  (`token`, `session`, …) from a pluggable registry, enabling multiple guard
  types in one application (Phase 0).
- Cookie/session authentication: `Auth` facade, `SessionGuard`, session
  middleware, and in-memory + SQL session stores (Phase 1).
- SPA authentication with CSRF protection: `/__auth__/csrf-cookie` endpoint,
  double-submit-cookie middleware, and an `AuthServiceProvider` that publishes
  the `config/cors.py` stub via `provider:publish -p auth` (Phase 2).
- Sanctum-style API tokens: `TokenGuard`, opaque hashed tokens with abilities,
  and in-memory + SQL token stores (Phase 3).

### Security / Hardening

- Session guard verifies against a constant-time dummy hash when no user is
  found, closing a timing side-channel.
- SQL session and API-token stores prune expired rows; purge cadence is
  configurable.
- CSRF cookie endpoint hardened; token repr for `NewApiToken` redacts the
  plaintext value so it cannot leak into logs.
- DB-API connection vs. connection-factory detection now probes `execute()`
  instead of `callable()`, fixing misdetection of raw `sqlite3.Connection`
  objects in the SQL session and API-token stores.

## [0.1.0]

Initial release.

- Passport-style OAuth2 authorization server for FastAPI: authorization code
  (with PKCE), password, client credentials, and refresh token grants
- JWT access tokens with scopes, token guards, and route dependencies
- Personal access tokens
- Pluggable user/client providers (in-memory and Masonite ORM)
- Password reset flow with throttling hardened against account enumeration
