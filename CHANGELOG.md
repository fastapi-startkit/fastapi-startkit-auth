# Changelog

All notable changes to `fastapi-startkit-auth` are documented in this file.

Release notes are also published on
[GitHub Releases](https://github.com/fastapi-startkit/fastapi-startkit-auth/releases).

## [Unreleased]

### Changed

- Minimum supported Python is now 3.10. 0.3.0 advertised `>=3.9` but fails on
  3.9 because runtime-evaluated annotations use `X | None` syntax.
- The `startkit` extra is bounded to `fastapi-startkit>=0.51,<1.0`.
- The package `__init__` imports its public API directly instead of through a
  lazy export table.
- The source distribution now ships the test suite and this changelog.
- Releases are published from GitHub Actions via PyPI trusted publishing on
  `vX.Y.Z` tags, replacing `bin/release.sh`.

### Added

- `Typing :: Typed` classifier (the package already ships `py.typed`).

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
