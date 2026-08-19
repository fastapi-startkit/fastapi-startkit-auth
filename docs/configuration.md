# Configuration

`AuthConfig` mirrors Laravel's `config/auth.php` and adds JWT/token knobs.
Subclass it and override the class attributes you care about — everything except
a signing `key` and a provider has a sensible default.

```python
class AuthConfig:
    default   = {"guard": "api", "passwords": "users"}
    guards    = {"api": {"driver": "passport", "provider": "users"}}
    providers = {"users": {"driver": "masoniteorm", "model": User}}
    passwords = {"users": {"provider": "users", "table": "password_reset_tokens",
                            "expire": 60, "throttle": 60}}

    # token settings (all optional, sensible defaults shown)
    key                        = None          # JWT secret (required in production)
    algorithm                  = "HS256"
    access_token_ttl           = 3600          # seconds
    refresh_token_ttl          = 60 * 60 * 24 * 14
    personal_access_token_ttl  = 60 * 60 * 24 * 365
    authorization_code_ttl     = 600
    bcrypt_rounds              = 12
```

## Structural keys

| Key | Purpose |
| --- | --- |
| `default` | The default `guard` and `passwords` broker names |
| `guards` | Named guards; each has a `driver` (`passport`) and a `provider` |
| `providers` | Named user providers; each has a `driver` and driver-specific options |
| `passwords` | Named password-reset brokers with `provider`, `table`, `expire`, `throttle` |

## Token settings

| Attribute | Default | Meaning |
| --- | --- | --- |
| `key` | `None` | JWT signing secret. **Required in production.** |
| `algorithm` | `"HS256"` | JWT signing algorithm |
| `access_token_ttl` | `3600` | Access token lifetime, seconds (1 hour) |
| `refresh_token_ttl` | `1209600` | Refresh token lifetime, seconds (14 days) |
| `personal_access_token_ttl` | `31536000` | Personal access token lifetime, seconds (1 year) |
| `authorization_code_ttl` | `600` | Authorization code lifetime, seconds (10 minutes) |
| `bcrypt_rounds` | `12` | bcrypt cost factor for password hashing |

## Password-reset delivery

| Attribute | Default | Meaning |
| --- | --- | --- |
| `password_reset_notifier` | `None` | Called as `notifier(email, token)` to deliver a reset token |
| `debug_expose_reset_token` | `False` | **DEV ONLY** — echo the plaintext reset token in the HTTP response |

See [Password resets](password-resets.md) for the full flow.

!!! warning "Set a strong `key` in production"
    Leaving `key` unset is only acceptable for tests. Use a long, random secret
    sourced from the environment, e.g. `key = os.environ["APP_KEY"]`.
