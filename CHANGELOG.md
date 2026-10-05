# Changelog

All notable changes to `fastapi-startkit-auth` are documented in this file.

Release notes are also published on
[GitHub Releases](https://github.com/fastapi-startkit/fastapi-startkit-auth/releases).

## [Unreleased]

### Breaking changes and upgrade notes

Each item lists what changed and what to do.

- **Feature providers replace `Application` and `AuthServiceProvider`.**
  Register `AuthProvider` first, then the features your guards use:
  `AuthSessionProvider(SessionConfig)`, `AuthOAuth2Provider(OAuth2Config)` and
  `AuthApiTokenProvider(ApiTokenConfig)`. Standalone apps call
  `Provider(config).register(app)`; Startkit apps list the providers in the
  application. *Migrate:* replace `Application([(AuthProvider, Config)])` with a
  `FastAPI()` app plus the providers, and `AuthServiceProvider` with
  `AuthProvider` + the feature providers.
- **Feature settings moved off `AuthConfig`.** The `session`, `api_tokens` and
  `spa` dicts are rejected at startup; use `SessionConfig`, `ApiTokenConfig`
  (`stateful_origins` turns on SPA mode) instead. *Migrate:* move each dict's
  keys onto the matching dataclass and pass it to its provider.
- **OAuth settings moved to `OAuth2Config`.** `key`, `algorithm`, the `*_ttl`
  values, `tokens`, `issuer`, `resources`, `scopes`, `pkce_methods` and
  `require_pkce` now live on `OAuth2Config`. Setting them on `AuthConfig` still
  works but emits a `DeprecationWarning`, and an explicit `OAuth2Config` value
  wins. *Migrate:* move them to `OAuth2Config`; the fallback will be removed in a
  future release.
- **Password grant is opt-in.** `OAuth2Config.grant_types` defaults to
  `["authorization_code", "client_credentials", "refresh_token"]`; `/oauth/token`
  with `grant_type=password` and `/token` answer `unsupported_grant_type`.
  *Migrate:* add `"password"` to `grant_types` to keep it.
- **Client-less refresh tokens need the password grant.** Refresh tokens are now
  bound to the issuing client: refreshing or revoking one requires that client's
  authentication. Tokens without a client (issued by the password grant) are only
  accepted while `"password"` is enabled. *Migrate:* send client credentials on
  refresh; keep `"password"` enabled while old client-less tokens are in use.
- **Consent is mandatory.** `POST /oauth/authorize` returns `access_denied`
  unless the body has `"approved": true`, and always returns `iss` (body and
  redirect, RFC 9207). `response_type` other than `code` fails with
  `unsupported_response_type`. *Migrate:* send `approved: true` after the user
  consents; `GET /oauth/authorize` validates a request for your consent screen.
- **PKCE no longer defaults to S256.** A missing `code_challenge_method` means
  `plain`, which the default `pkce_methods=["S256"]` refuses. RFC 7636 formats are
  enforced: an S256 challenge is 43 base64url characters, a verifier 43–128
  unreserved characters. *Migrate:* always send `code_challenge_method=S256` and
  a verifier of at least 43 characters.
- **`client_credentials` is for confidential clients only**; public, revoked or
  grant-disallowed clients get `unauthorized_client` / `invalid_client`.
  Confidential clients must authenticate on the code exchange. *Migrate:* give
  machine clients a secret and list the grant (or leave `grant_types` empty).
- **Introspection requires a confidential client.** *Migrate:* call
  `/oauth/introspect` with a confidential client's credentials.
- **`/oauth/clients` HTTP routes are removed.** *Migrate:* create clients with
  `auth:oauth2:client` (Startkit) or `manager.client_repository.register(...)`.
- **Password reset routes** move to their own router, mounted by `AuthProvider`
  whenever `AuthConfig.passwords` is set (no OAuth needed). Paths are unchanged.
- **Default guard changed** from `"api"` to `"web"` and `AuthConfig.guards`
  defaults to empty. *Migrate:* set `default` and `guards` explicitly.
- **CSRF is always on with sessions**, and also accepts the `_token` form field.
  *Migrate:* send `X-XSRF-TOKEN` (or `_token`) on unsafe requests, or list paths
  in `SessionConfig.csrf_exempt_paths`.
- **OAuth client store defaults to `"database"`** (the ORM `oauth_clients`
  table). *Migrate:* publish and run the migrations, or set
  `OAuth2Config(clients=OAuthClientsConfig(store="memory"))`.
- **Persistent stores are named `"database"`.** `store="orm"` still works for
  sessions, API tokens, OAuth tokens and OAuth clients, but emits a
  `DeprecationWarning` and will be removed in a future release. *Migrate:*
  replace `store="orm"` with `store="database"`.
- **Custom token repositories** must implement `consume_refresh_token` and
  `revoke_token_chain`, and `store_refresh_token` takes `family_id`.
- Error responses carry `Cache-Control: no-store`; `invalid_client` challenges
  with `WWW-Authenticate: Basic`.

### Migrations

All additive; the v0.6.x migrations are unchanged. Publish and run them when
using the ORM stores:

- `2026_10_04_000001_create_oauth_clients_table` — the `oauth_clients` table.
- `2026_10_04_000002_add_family_id_to_oauth_refresh_tokens_table` — a nullable,
  indexed `family_id` column on `oauth_refresh_tokens`.

### Added

- Refresh token families with reuse detection: replaying a rotated refresh token
  revokes the whole family, including when another authenticated client
  presents it. Refresh tokens are introspectable.
- `POST /oauth/revoke` (RFC 7009) revokes the token and its access/refresh chain;
  `GET`/`DELETE /oauth/tokens` and `DELETE /oauth/tokens/{jti}` let a user list
  and revoke their OAuth tokens. `DELETE /oauth/personal-access-tokens` revokes
  all personal access tokens, which also accept a `ttl`.
- `/.well-known/oauth-authorization-server` metadata (RFC 8414).
- `OAuth2Config.default_scopes`, `grant_types`, `require_redirect_uri` and
  `authorization_guard`.
- `OrmClientRepository` and the `auth:oauth2:client` command (`--public`,
  `--name`, repeatable `--redirect-uri`).
- `AuthMiddleware` and request-scoped facades: `Auth.user()`, `Session.token()`,
  `ApiToken.create(...)` work on the class inside a request. `Auth.validate`
  checks credentials without logging in.
- `auth` dependency; token guards fall back to the SPA session cookie.
- Guest sessions are persisted lazily, only when the response is sent.

### Added (resource indicators, #27)

- RFC 8707 resource indicators: `OAuth2Config.resources` lists the resources tokens
  may be bound to. The token endpoint and `/oauth/authorize` accept `resource`;
  the code and refresh token remember it and the access token carries it as `aud`.
  Unknown or mismatched resources fail with `invalid_target`.
- Guards accept an `audience`: a passport guard with `"audience": "<uri>"` only
  accepts tokens bound to that resource, and resource-bound tokens are refused by
  guards without it.
- `OAuth2Config.issuer` stamps and verifies the `iss` claim.
- `OAuth2Config.scopes` is a scope catalog: when set, grants refuse unknown scopes
  with `invalid_scope`.
- `OAuth2Config.pkce_methods` restricts `code_challenge_method` (e.g. `["S256"]`),
  compared case-insensitively; an unknown `code_challenge_method` is now refused
  at `/oauth/authorize` with `invalid_request`.
- `OAuth2Config.require_pkce` demands a `code_challenge` from confidential clients
  too (OAuth 2.1 / MCP).
- A repeated `resource` parameter on the token endpoint fails with `invalid_target`.
- Building a guard whose `audience` is not listed in `OAuth2Config.resources` emits
  a `UserWarning`.
- `GrantPolicy`, `InvalidScope` and `InvalidTarget` are exported; introspection
  reports `aud` and `iss` when present.
- Migration `add_resource_to_oauth_tables` adds a nullable `resource` column to
  `oauth_auth_codes` and `oauth_refresh_tokens`; publish and run it when using the
  ORM store.

### Changed

- **Breaking:** persistence now goes through the fastapi-startkit ORM with models
  shipped in `fastapi_startkit_auth.orm`; no raw SQL remains. Use
  `{"store": "orm"}` (optional ORM `connection` name) for sessions, API tokens and
  OAuth tokens.
- Requires `pyjwt>=2.10.1`.
- **Breaking:** the `startkit` extra now requires `fastapi-startkit[database]>=0.60`.
- Run the published migrations (`provider:publish -p auth`, then `migrate`) to
  create the tables; stores no longer create tables themselves.

### Removed

- **Breaking:** the `sql` / `async_sql` stores and the `SqlSessionStore`,
  `SqlApiTokenRepository`, `AsyncSql*` classes and database adapters.

### Added

- `Client.provider` (and `register(provider=...)`) binds an OAuth client to a
  user provider. `AuthManager.owner_provider(client_id)` resolves it, falling
  back to the default guard's provider.
- `AuthManager.warm_up()` and `AsyncModelUserProvider.warm_up()`, run from the
  app lifespan by `AuthProvider`, precompute the dummy hash at startup.

### Fixed

- Refresh, authorization-code exchange and introspection re-check the token
  owner against the provider of the issuing client instead of always using the
  default guard's provider. The password grant authenticates against the
  client's provider, and `/oauth/authorize` rejects a client bound to another
  provider.
- `AsyncModelUserProvider.is_active` only uses the threadpool for a sync
  callable hook. Attribute checks and `async def` hooks run inline.
- The first unknown-user login no longer pays an extra bcrypt hash to create
  the dummy hash.

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
- `bin/release.sh` uploads to PyPI with `twine upload`, matching
  fastapi-startkit; the tag-triggered trusted-publishing workflow is removed.

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
