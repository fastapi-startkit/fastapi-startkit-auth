# HTTP endpoints

Registering the `AuthProvider` mounts the following routes.

| Method & path | Purpose |
| --- | --- |
| `POST /oauth/token` | Unified token endpoint: `password`, `refresh_token`, `client_credentials`, `authorization_code` |
| `POST /token` | Simple password grant (FastAPI-tutorial style) |
| `POST /oauth/authorize` | Approve an auth-code request (requires an authenticated user) → returns `code` |
| `POST /oauth/introspect` | RFC 7662 token introspection (**requires client authentication**) |
| `POST /oauth/revoke` | RFC 7009 access/refresh token revocation (**requires client authentication**) |
| `POST/GET /oauth/clients`, `DELETE /oauth/clients/{client_id}` | Client registration & management |
| `POST/GET /oauth/personal-access-tokens`, `DELETE .../{jti}` | Personal access tokens |
| `POST /password/email` | Trigger a password-reset token (delivered out-of-band) |
| `POST /password/reset` | Reset the password with a token |

See [Grants](grants.md) for how the token endpoints behave per `grant_type`, and
[Password resets](password-resets.md) for the reset flow.

## Clients

Confidential and public clients can be registered, listed, and deleted:

- `POST /oauth/clients` → `201` with the created client
- `GET /oauth/clients` → list clients
- `DELETE /oauth/clients/{client_id}` → `204`

Public (secretless) clients **must** use PKCE for the authorization-code grant.

## Personal access tokens

Named, long-lived tokens carrying scopes/abilities:

- `POST /oauth/personal-access-tokens` → `201`
- `GET /oauth/personal-access-tokens` → list
- `DELETE /oauth/personal-access-tokens/{jti}` → `204`
