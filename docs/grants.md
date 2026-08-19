# Grants

`POST /oauth/token` is a unified endpoint dispatched by `grant_type`. It supports
`password`, `refresh_token`, `client_credentials`, and `authorization_code`.

## Password grant

```bash
curl -X POST localhost:8000/oauth/token \
  -d grant_type=password -d username=ada@example.com -d password=secret -d scope="read write"
# → { "access_token": "...", "token_type": "Bearer", "expires_in": 3600,
#     "refresh_token": "...", "scope": "read write" }
```

`POST /token` is a simpler, FastAPI-tutorial-style password grant.

## Refresh token

Exchange an opaque refresh token for a new access token. Refresh tokens are
**rotated** on use — the old token is invalidated and a new one is returned.

```bash
curl -X POST localhost:8000/oauth/token \
  -d grant_type=refresh_token -d refresh_token=<token>
```

## Client credentials

Machine-to-machine grant; authenticate with client credentials and receive an
access token with no user context.

```bash
curl -X POST localhost:8000/oauth/token \
  -d grant_type=client_credentials -d client_id=<id> -d client_secret=<secret> -d scope="jobs:run"
```

## Authorization code + PKCE

Browser/SPA flow supporting `S256` and `plain` PKCE.

1. `POST /oauth/authorize` with a bearer token and a `code_challenge` → returns a
   single-use `code`.
2. `POST /oauth/token` with `grant_type=authorization_code`, the `code`, and the
   matching `code_verifier`.

!!! warning "PKCE is mandatory for public clients"
    A public (secretless) client cannot obtain an authorization code without
    PKCE. The `code_challenge` is required, and codes are verified against the
    `code_verifier` at exchange.

## Revocation & introspection

- `POST /oauth/revoke` — RFC 7009 revoke an access or refresh token
  (**requires client authentication**).
- `POST /oauth/introspect` — RFC 7662 introspection
  (**requires client authentication**).
