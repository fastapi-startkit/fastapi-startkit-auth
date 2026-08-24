# Changelog

All notable changes to `fastapi-startkit-auth` are documented in this file.

Release notes are also published on
[GitHub Releases](https://github.com/fastapi-startkit/fastapi-startkit-auth/releases).

## [Unreleased]

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
