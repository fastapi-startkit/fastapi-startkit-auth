from __future__ import annotations

from typing import Any, Callable, Union

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


def active_check(is_active: ActiveCheck) -> Callable[[Any], bool]:
    if is_active is None:
        return lambda user: True
    if isinstance(is_active, str):
        return lambda user: bool(read_attribute(user, is_active))
    return is_active
