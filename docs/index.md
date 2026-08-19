# fastapi-startkit-auth

Passport-style OAuth2 + JWT authentication for FastAPI.

`fastapi-startkit-auth` brings the ergonomics of
[Laravel Passport](https://laravel.com/docs/13.x/passport) to FastAPI: a
config-driven guard/provider/passwords model layered on top of OAuth2 grants and
signed JWT access tokens (per the
[FastAPI security tutorial](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)).

## Features

| Area | What you get |
| --- | --- |
| **Config layer** | `AuthConfig` (`default` / `guards` / `providers` / `passwords`) + `AuthProvider` that registers into the app |
| **Password grant** | OAuth2 password grant → signed JWT access tokens with expiry (`/oauth/token`, `/token`) |
| **Refresh tokens** | Opaque refresh tokens with **rotation** and configurable TTL |
| **Personal access tokens** | Named, long-lived tokens with scopes/abilities |
| **Client credentials** | Machine-to-machine grant |
| **Authorization code + PKCE** | Browser/SPA flow with S256 & plain PKCE |
| **Clients** | Register / list / delete confidential & public clients |
| **Revocation & introspection** | RFC 7009 revoke + RFC 7662 introspect |
| **Password reset** | `password_reset_tokens` flow with configurable `expire` + `throttle` |
| **Guards & deps** | `current_user`, `optional_user`, `require_scopes` FastAPI dependencies |
| **Pluggable providers** | In-memory, generic ORM/masoniteorm model, or any custom `UserProvider` |

## Where to next

- New here? Start with [Installation](installation.md) then the
  [Quickstart](quickstart.md).
- Wiring auth into your own app? See [Configuration](configuration.md) and
  [Providers](providers.md).
- Integrating a client? Browse the [HTTP endpoints](endpoints.md) and
  [Grants](grants.md).
- Locking down routes? Read [Scopes & abilities](scopes.md).

## License

Released under the MIT License.
