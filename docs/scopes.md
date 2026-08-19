# Scopes & abilities

Tokens carry scopes. Enforce them on a route with the `require_scopes`
dependency.

```python
require_scopes("posts:write")               # must have this scope
require_scopes("a", "b")                     # must have all
require_scopes("a", "b", mode="any")         # must have at least one
```

`*` is a wildcard scope that satisfies any check.

## Inspecting the context

`require_scopes` (and `current_user` via the underlying `AuthContext`) give you
access to the authenticated context inside a handler:

```python
from fastapi import Depends
from fastapi_startkit_auth import require_scopes


@api.get("/reports")
def reports(ctx=Depends(require_scopes("reports:read"))):
    if ctx.can("reports:export"):
        ...
    return {"scopes": ctx.scopes}
```

Useful `AuthContext` members:

- `ctx.can(scope)` — has this scope (respects the `*` wildcard)
- `ctx.can_any(*scopes)` — has at least one of these scopes
- `ctx.scopes` — the granted scopes

## Dependencies

| Dependency | Behavior |
| --- | --- |
| `current_user` | Resolves the authenticated user; raises `401` if unauthenticated |
| `optional_user` | Resolves the user if present, otherwise `None` |
| `require_scopes(*scopes, mode="all")` | Enforces scopes; `mode="any"` requires at least one |
