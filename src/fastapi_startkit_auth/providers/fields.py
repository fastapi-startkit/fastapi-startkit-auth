from __future__ import annotations

from typing import Any, Callable, Union

from ..concurrency import is_coroutine_callable

ActiveCheck = Union[Callable[[Any], bool], str, None]


def read_attribute(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def write_attribute(obj: Any, name: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


def active_check(is_active: ActiveCheck, allow_async: bool = False) -> Callable[[Any], Any]:
    if is_active is None:
        return lambda user: True
    if isinstance(is_active, str):
        return lambda user: bool(read_attribute(user, is_active))
    if not callable(is_active):
        raise TypeError(f"is_active must be an attribute name or a callable, got {is_active!r}.")
    if is_coroutine_callable(is_active) and not allow_async:
        raise TypeError(
            'An async is_active hook needs an async provider (driver "async_model"); '
            "a synchronous provider cannot await it."
        )
    return is_active
