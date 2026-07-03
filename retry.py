# retry.py — small retry helper for transient network failures (no external dependency)
import asyncio
from typing import Awaitable, Callable, Tuple, Type, TypeVar

T = TypeVar("T")


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    attempts: int = 2,
    base_delay: float = 1.0,
    retry_on: Tuple[Type[BaseException], ...] = (Exception,),
) -> T:
    last_exc: BaseException = RuntimeError("retry_async called with attempts <= 0")
    for attempt in range(attempts):
        try:
            return await fn()
        except retry_on as e:
            last_exc = e
            if attempt < attempts - 1:
                await asyncio.sleep(base_delay * (2 ** attempt))
    raise last_exc
