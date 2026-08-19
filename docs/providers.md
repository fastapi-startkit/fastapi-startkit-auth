# Providers

A **provider** tells the auth layer how to look up and verify users. Configure
one per entry in `providers`; each entry names a `driver` plus driver-specific
options.

```python
providers = {"users": {"driver": "masoniteorm", "model": User}}
```

## Built-in drivers

| driver | meaning |
| --- | --- |
| `masoniteorm` / `orm` / `model` | wrap a model exposing `find(id)` and `where(field, value).first()` |
| `memory` | in-memory dict store (`users=[...]`) — great for tests/demos |
| `instance` | pass a ready `UserProvider` via `{"instance": ...}` |
| `factory` | pass a zero-arg callable returning a `UserProvider` |

### ORM / model

```python
providers = {"users": {"driver": "masoniteorm", "model": User}}
```

The model only needs `find(id)` and `where(field, value).first()`, so most
active-record style ORMs work.

### In-memory

```python
providers = {
    "users": {
        "driver": "memory",
        "users": [{"id": 1, "email": "ada@example.com", "password": "<bcrypt-hash>"}],
    },
}
```

### Instance / factory

```python
providers = {"users": {"driver": "instance", "instance": my_provider}}
providers = {"users": {"driver": "factory", "factory": build_provider}}
```

## Custom providers

Any object implementing the `UserProvider` protocol is a valid provider:

- `retrieve_by_id(identifier)`
- `retrieve_by_credentials(credentials)`
- `validate_credentials(user, credentials)`
- `get_identifier(user)`
- `update_password(user, hashed_password)`

Wire it in with the `instance` or `factory` driver.
