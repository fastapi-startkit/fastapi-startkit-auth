from __future__ import annotations

from collections.abc import Callable
from typing import Any, Concatenate, Generic, ParamSpec, TypeVar

from .request_context import current_auth_request

P = ParamSpec("P")
R = TypeVar("R")


class ScopedMethod(Generic[P, R]):
    def __init__(self, method: Callable[Concatenate[Any, P], R]) -> None:
        self.method = method

    def __get__(self, instance: Any, owner: type) -> Callable[P, R]:
        if instance is None:
            context = current_auth_request()
            instance = owner(context.manager, context.request)
        return self.method.__get__(instance, owner)
