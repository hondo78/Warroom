"""Redis-backed rolling cache of recent failed-login attempts.

The failed-login agent used to re-scan the (huge) ``firewall_logs`` table on
every loop. Instead we keep a rolling working-set of attempts in a Redis sorted
set (score = epoch seconds), topped up incrementally from Postgres and trimmed
to a retention window. The distributed sweep then reads its pattern-detection
input straight from this cache — cheap, real-time, and decoupled from the 40GB
table — and the LLM reasons over it.

All functions degrade gracefully: a Redis outage makes :func:`recent` return
``None`` (distinct from ``[]`` = genuinely empty) so the caller can fall back to
a direct database read.
"""

import json
import logging
from datetime import datetime, timezone

from app.geoip_service import get_redis

logger = logging.getLogger(__name__)

_ZSET = "agent:faillogin:zset"
_CURSOR = "agent:faillogin:cursor"
# Longest window we ever analyse; entries older than this are trimmed away.
RETENTION_SECONDS = 24 * 3600


def _member(a: dict) -> str:
    # Stable per source row (``uid`` = firewall_logs id) so repeated top-ups are
    # idempotent — ZADD just refreshes the score for an already-seen attempt.
    return json.dumps({
        "uid": a.get("uid"),
        "ip": a.get("ip"),
        "user": a.get("user"),
        "component": a.get("component"),
        "country": a.get("country"),
        "ts": a.get("ts"),
    }, ensure_ascii=False, sort_keys=True)


def _score(ts_iso: str | None) -> float:
    if not ts_iso:
        return 0.0
    try:
        dt = datetime.fromisoformat(ts_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return 0.0


async def get_cursor() -> str | None:
    """ISO timestamp of the newest attempt already cached (for incremental
    top-up), or None if the cache is cold / Redis is down."""
    try:
        r = await get_redis()
        return await r.get(_CURSOR)
    except Exception:
        return None


async def add_attempts(attempts: list[dict], now: datetime) -> int:
    """Add attempts to the cache, advance the cursor, and trim old entries.
    Each attempt needs ``uid``/``ip``/``ts`` (ISO) + optional user/component/
    country. Returns how many were written (0 on Redis error)."""
    if not attempts:
        # Still trim on empty top-ups so the window stays bounded.
        await trim(now)
        return 0
    try:
        r = await get_redis()
        mapping = {_member(a): _score(a.get("ts")) for a in attempts}
        await r.zadd(_ZSET, mapping)
        newest = max((a.get("ts") for a in attempts if a.get("ts")), default=None)
        if newest:
            await r.set(_CURSOR, newest)
        await trim(now)
        return len(mapping)
    except Exception as e:
        logger.warning(f"login_cache add_attempts failed: {e}")
        return 0


async def trim(now: datetime) -> None:
    try:
        r = await get_redis()
        cutoff = now.timestamp() - RETENTION_SECONDS
        await r.zremrangebyscore(_ZSET, "-inf", f"({cutoff}")
    except Exception:
        pass


async def recent(minutes: int, now: datetime) -> list[dict] | None:
    """Attempts from the last ``minutes`` (newest first). Returns None when the
    cache is unavailable so the caller can fall back to the database."""
    try:
        r = await get_redis()
        lo = now.timestamp() - max(1, minutes) * 60
        members = await r.zrangebyscore(_ZSET, lo, now.timestamp())
    except Exception as e:
        logger.warning(f"login_cache recent failed: {e}")
        return None
    out: list[dict] = []
    for m in members:
        try:
            out.append(json.loads(m))
        except (ValueError, TypeError):
            continue
    out.sort(key=lambda a: a.get("ts") or "", reverse=True)
    return out
