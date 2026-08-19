# Installation

```bash
pip install fastapi-startkit-auth
# optional ORM provider driver
pip install "fastapi-startkit-auth[masoniteorm]"
```

Requires Python 3.9+.

!!! note "No passlib"
    The package uses `bcrypt` directly instead of `passlib`, which imports the
    `crypt` stdlib module removed in Python 3.13+. This keeps
    `fastapi-startkit-auth` running on modern Python.

## Extras

| Extra | Installs | When you need it |
| --- | --- | --- |
| `masoniteorm` | `masoniteorm>=2.18` | Using the `masoniteorm` / `orm` provider driver against a masoniteorm model |
| `test` | `pytest`, `pytest-asyncio`, `httpx` | Running the test suite locally |

## From source

```bash
git clone https://github.com/fastapi-startkit/fastapi-startkit-auth
cd fastapi-startkit-auth
pip install -e ".[test]"
pytest
```
