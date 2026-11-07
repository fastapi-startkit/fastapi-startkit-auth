from __future__ import annotations

import inspect
from typing import Any, Callable

from starlette.concurrency import run_in_threadpool


async def resolve(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def call(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    if is_coroutine_callable(function):
        return await function(*args, **kwargs)
    return await resolve(await run_in_threadpool(function, *args, **kwargs))


def is_coroutine_callable(obj: Any) -> bool:
    return inspect.iscoroutinefunction(obj) or inspect.iscoroutinefunction(getattr(obj, "__call__", None))
