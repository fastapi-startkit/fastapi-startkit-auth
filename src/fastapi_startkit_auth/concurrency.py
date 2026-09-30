from __future__ import annotations

import inspect
from typing import Any, Callable

from starlette.concurrency import run_in_threadpool


async def resolve(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def call(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    if inspect.iscoroutinefunction(function):
        return await function(*args, **kwargs)
    return await run_in_threadpool(function, *args, **kwargs)


def is_async(obj: Any, method: str) -> bool:
    return inspect.iscoroutinefunction(getattr(obj, method, None))
