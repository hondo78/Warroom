"""Redis-backed response cache for read-only aggregation endpoints.

Use as a decorator inside the @app.get(...) stack. Order matters:

    @app.get("/api/stats/summary")
    @cached(ttl=60)
    async def get_summary(...):
        ...

@app.get must stay OUTERMOST so FastAPI inspects the real function signature
for Depends; functools.wraps inside @cached preserves it.

Keys are derived from the wrapped function's name plus its query/path
parameters. Sentinel objects (DB sessions, Request, BackgroundTasks) are
auto-excluded so the cache works without further configuration.
"""
from __future__ import annotations

import functools
import json
import logging
from typing import Any, Callable

from app.geoip_service import get_redis

logger = logging.getLogger(__name__)

# kwargs that must never be part of the cache key (per-request objects).
_EXCLUDE_TYPE_NAMES = {"AsyncSession", "Request", "Response", "BackgroundTasks"}


def _key_for(func_name: str, kwargs: dict[str, Any]) -> str:
    parts: list[str] = []
    for k in sorted(kwargs):
        v = kwargs[k]
        if v is None:
            continue
        type_name = type(v).__name__
        if type_name in _EXCLUDE_TYPE_NAMES:
            continue
        parts.append(f"{k}={v}")
    return "cache:" + func_name + (":" + ":".join(parts) if parts else "")


def cached(ttl: int = 60) -> Callable:
    """Cache the endpoint's JSON-serialisable return value in Redis for `ttl`
    seconds. On Redis errors we fall through and compute fresh — caching is
    strictly best-effort, never on the critical-failure path.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            r = await get_redis()
            key = _key_for(func.__name__, kwargs)

            if r is not None:
                try:
                    hit = await r.get(key)
                    if hit is not None:
                        return json.loads(hit)
                except Exception as e:
                    logger.debug(f"cache read miss ({key}): {e}")

            result = await func(*args, **kwargs)

            if r is not None:
                try:
                    await r.setex(key, ttl, json.dumps(result, default=str))
                except Exception as e:
                    logger.debug(f"cache write skip ({key}): {e}")

            return result

        return wrapper

    return decorator
