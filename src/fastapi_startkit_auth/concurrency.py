from __future__ import annotations

import inspect
from typing import Any, Callable, Iterable

from starlette.concurrency import run_in_threadpool


class AsyncMisconfiguration(TypeError):
    pass


async def resolve(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def call(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    if is_coroutine_callable(function):
        return await function(*args, **kwargs)
    return await resolve(await run_in_threadpool(function, *args, **kwargs))


def ensure_sync(value: Any, source: str) -> Any:
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):
            value.close()
        raise AsyncMisconfiguration(
            f"{source} returned an awaitable in a synchronous auth path. "
            "Use an async provider/store so the async guards and grants are selected."
        )
    return value


def is_coroutine_callable(obj: Any) -> bool:
    return inspect.iscoroutinefunction(obj) or inspect.iscoroutinefunction(getattr(obj, "__call__", None))


def is_async(obj: Any, method: str) -> bool:
    return is_coroutine_callable(getattr(obj, method, None))


def has_async_methods(obj: Any, methods: Iterable[str] | None = None) -> bool:
    if methods is None:
        methods = [name for name in dir(obj) if not name.startswith("_")]
        return any(is_coroutine_callable(inspect.getattr_static(obj, name, None)) for name in methods)
    return any(is_async(obj, name) for name in methods)
