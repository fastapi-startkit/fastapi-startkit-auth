# Password resets

The reset flow is enumeration-safe: `POST /password/email` always returns the
same generic response whether or not the account exists, and **never** puts the
token in the response body.

## Endpoints

| Method & path | Purpose |
| --- | --- |
| `POST /password/email` | Trigger a password-reset token (delivered out-of-band) |
| `POST /password/reset` | Reset the password with a token |

## Delivering the token

Configure how the token reaches the user with a notifier on your config:

```python
class AuthConfig(BaseAuthConfig):
    password_reset_notifier = staticmethod(lambda email, token: send_email(email, token))
    # debug_expose_reset_token = True   # DEV ONLY: echo the token in the response
```

The notifier is called as `notifier(email, token)`. The plaintext token is never
returned in the HTTP response unless `debug_expose_reset_token` is explicitly
`True`.

!!! danger "Never enable `debug_expose_reset_token` in production"
    It echoes the plaintext reset token in the response and exists only for local
    development.

## Broker settings

Each `passwords` broker configures the reset table and timing:

```python
passwords = {
    "users": {
        "provider": "users",
        "table": "password_reset_tokens",
        "expire": 60,     # token validity, minutes
        "throttle": 60,   # min seconds between reset requests
    },
}
```

The `throttle` window is applied without leaking whether an account exists,
closing the enumeration side-channel.
