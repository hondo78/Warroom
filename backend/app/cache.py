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

Single-flight + stale-while-revalidate
--------------------------------------
A plain "miss → compute" cache is a stampede amplifier on this dataset: the
heavy firewall_logs aggregates run for minutes, so during a single miss window
every browser auto-refresh, every open tab and the cache warmer each started
their own copy of the same query. Each copy pinned a DB pool connection until
it finished, the pool (20) was exhausted within a minute, and then *every*
endpoint — including the trivial ones — failed with
"QueuePool limit of size 10 overflow 10 reached". That is what made the
dashboard show partial or no data at all.

So:
  * only ONE caller per key recomputes at a time (Redis NX lock);
  * everyone else gets the previous value back instantly, even if it is past
    its TTL (kept for `stale_grace` seconds beyond it);
  * only a genuinely cold key (nothing cached at all) makes followers wait,
    and even then they wait for the leader instead of piling onto the DB.
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import time
import uuid
from typing import Any, Callable

from fastapi import HTTPException

from app.geoip_service import get_redis

logger = logging.getLogger(__name__)

# kwargs that must never be part of the cache key (per-request objects).
_EXCLUDE_TYPE_NAMES = {"AsyncSession", "Request", "Response", "BackgroundTasks"}

# Marker on the stored envelope so pre-existing (bare) cache entries written by
# the older implementation are still readable during a rolling restart.
_ENVELOPE = "_wr"

# How long a stale value stays servable after its TTL expired. Generous on
# purpose: serving a 10-minute-old aggregate beats serving an error.
_DEFAULT_STALE_GRACE = 3600

# Upper bound on how long one leader may hold the recompute lock. Must exceed
# the slowest query, otherwise the lock expires under a leader that is still
# running and a second one starts the same multi-minute query — the stampede
# this module exists to prevent. The cap on "slowest" is the background pool's
# statement_timeout (600s, see database.py), which is what the cache warmer
# runs on, so the lock has to outlive that rather than undercut it.
_LOCK_TTL = 660

# Cold-miss followers wait this long for the leader's result before giving up.
_COLD_WAIT_SECONDS = 25
_COLD_POLL_INTERVAL = 0.25


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


def _unpack(raw: str | bytes) -> tuple[Any, float] | None:
    """Decode a stored entry into (value, expires_at). Bare legacy entries are
    reported as already-expired-but-servable, so they behave as stale data and
    get replaced on the next recompute."""
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if isinstance(data, dict) and data.get(_ENVELOPE) == 1:
        return data.get("v"), float(data.get("exp") or 0)
    return data, 0.0


def _pack(value: Any, ttl: int) -> str:
    return json.dumps(
        {_ENVELOPE: 1, "exp": time.time() + ttl, "v": value}, default=str
    )


async def _release(r, lock_key: str, token: str) -> None:
    """Drop the recompute lock, but only if it is still ours.

    A leader that outlived ``_LOCK_TTL`` no longer holds the lock: it expired
    and a second caller took it. An unconditional DELETE in that leader's
    ``finally`` would free the *new* leader's lock and let a third caller start
    the same query — the stampede this module exists to prevent, arriving by
    the one path nobody watches. The compare-and-delete runs server-side so it
    cannot lose the race between the read and the delete.
    """
    try:
        await r.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
            "return redis.call('del', KEYS[1]) else return 0 end",
            1, lock_key, token,
        )
    except Exception:
        pass


def cached(ttl: int = 60, stale_grace: int = _DEFAULT_STALE_GRACE) -> Callable:
    """Cache the endpoint's JSON-serialisable return value in Redis.

    `ttl` is the freshness window; for `stale_grace` seconds beyond it the old
    value is still handed out to callers while a single leader recomputes.
    On Redis errors we fall through and compute fresh — caching is strictly
    best-effort, never on the critical-failure path.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            r = await get_redis()
            key = _key_for(func.__name__, kwargs)

            if r is None:                       # no Redis → straight through
                return await func(*args, **kwargs)

            lock_key = key + ":lock"

            async def read() -> tuple[Any, float] | None:
                try:
                    raw = await r.get(key)
                except Exception as e:
                    logger.debug(f"cache read failed ({key}): {e}")
                    return None
                return _unpack(raw) if raw is not None else None

            async def compute_and_store() -> Any:
                result = await func(*args, **kwargs)
                try:
                    await r.setex(key, ttl + stale_grace, _pack(result, ttl))
                except Exception as e:
                    logger.debug(f"cache write skip ({key}): {e}")
                return result

            entry = await read()
            if entry is not None and time.time() < entry[1]:
                return entry[0]                 # fresh hit

            # Stale or missing → exactly one caller recomputes.
            token = uuid.uuid4().hex
            try:
                got_lock = await r.set(lock_key, token, nx=True, ex=_LOCK_TTL)
            except Exception as e:
                logger.debug(f"cache lock failed ({key}): {e}")
                return await func(*args, **kwargs)

            if got_lock:
                try:
                    return await compute_and_store()
                except HTTPException:
                    # The endpoint chose this response deliberately (a revoked
                    # API token, a bad parameter). Serving stale data with a 200
                    # instead would hide a broken integration for the whole
                    # stale window — the fallback below is for queries that
                    # *failed*, not for answers we were given.
                    raise
                except Exception:
                    # Leader failed; hand back stale data rather than an error.
                    if entry is not None:
                        logger.warning(
                            f"cache: recompute of {key} failed, serving stale"
                        )
                        return entry[0]
                    raise
                finally:
                    await _release(r, lock_key, token)

            # Someone else is recomputing.
            if entry is not None:
                return entry[0]                 # stale-while-revalidate

            # Cold key: wait for the leader instead of duplicating its query.
            deadline = time.monotonic() + _COLD_WAIT_SECONDS
            while time.monotonic() < deadline:
                await asyncio.sleep(_COLD_POLL_INTERVAL)
                fresh = await read()
                if fresh is not None:
                    return fresh[0]
                # Redis errors end the wait; an error raised by the endpoint
                # itself must not be mistaken for one, or a real 400/500 comes
                # back to the caller as a misleading "still computing" 503.
                try:
                    took_over = (not await r.exists(lock_key)
                                 and await r.set(lock_key, token, nx=True, ex=_LOCK_TTL))
                except Exception:
                    break
                if took_over:
                    # Leader died without storing anything — take over.
                    try:
                        return await compute_and_store()
                    finally:
                        await _release(r, lock_key, token)

            raise HTTPException(
                status_code=503,
                detail="Aggregation is being computed, please retry shortly",
                headers={"Retry-After": "10"},
            )

        return wrapper

    return decorator
