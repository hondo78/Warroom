"""Redis-backed rolling cache of the request paths each IP hit on the WAF.

The WAF agent decides per source-IP whether the 4xx/5xx noise it produced is a
real attack. Counts alone don't distinguish a misconfigured client (hammering
*one* broken path) from a directory/wordlist brute-force scanner (walking
*hundreds of distinct* paths — ``/wp-admin``, ``/.env``, ``/phpmyadmin`` …).

So we keep, per IP, the distinct paths it requested in a Redis sorted set
(score = epoch seconds, one member per distinct path+status+method). It's
topped up incrementally from the WAF loop's window and trimmed to a 24h
retention window; the LLM then reasons over the accumulated set to spot the
wordlist pattern. Mirrors :mod:`app.login_cache`.

All functions degrade gracefully: a Redis outage makes :func:`recent_paths`
return ``None`` (distinct from ``[]`` = genuinely empty) so the caller can
decide whether to fall back.
"""

import json
import logging
from datetime import datetime, timezone

from app.geoip_service import get_redis

logger = logging.getLogger(__name__)

_KEY_PREFIX = "agent:waf:paths:"
# Longest window we ever analyse; entries older than this are trimmed away and
# the per-IP key expires once the IP goes quiet.
RETENTION_SECONDS = 24 * 3600
# Hard cap on distinct paths kept per IP — a scanner can emit thousands; we only
# need enough to recognise the pattern, and this bounds memory per key.
MAX_PATHS_PER_IP = 2000


def _key(ip: str) -> str:
    return f"{_KEY_PREFIX}{ip}"


def _member(entry: dict) -> str:
    # Stable per (path, status, method) so repeated top-ups are idempotent —
    # ZADD just refreshes the score for an already-seen path. We count *distinct*
    # paths, so collapsing repeat hits of the same path is exactly what we want
    # (total hit counts come from the loop's own 4xx/5xx aggregates).
    return json.dumps({
        "path": entry.get("path"),
        "status": entry.get("status"),
        "method": entry.get("method"),
    }, ensure_ascii=False, sort_keys=True)


def _score(ts: object) -> float:
    if isinstance(ts, datetime):
        dt = ts
    elif isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            return 0.0
    else:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


async def add_paths(ip: str, entries: list[dict], now: datetime) -> int:
    """Add request paths for ``ip`` to its cache, refresh the key TTL, and trim
    old entries. Each entry needs ``path`` + optional ``status``/``method``/
    ``ts``. Returns how many were written (0 on Redis error / empty input)."""
    if not ip or not entries:
        return 0
    try:
        r = await get_redis()
        key = _key(ip)
        mapping = {
            _member(e): _score(e.get("ts")) for e in entries if e.get("path")
        }
        if not mapping:
            return 0
        await r.zadd(key, mapping)
        # Trim by age first, then by count (keep the most recent).
        cutoff = now.timestamp() - RETENTION_SECONDS
        await r.zremrangebyscore(key, "-inf", f"({cutoff}")
        await r.zremrangebyrank(key, 0, -(MAX_PATHS_PER_IP + 1))
        # Refresh expiry so abandoned IPs self-clean.
        await r.expire(key, RETENTION_SECONDS)
        return len(mapping)
    except Exception as e:
        logger.warning(f"waf_path_cache add_paths failed for {ip}: {e}")
        return 0


async def recent_paths(ip: str, minutes: int, now: datetime) -> list[dict] | None:
    """Distinct paths ``ip`` hit in the last ``minutes`` (newest first). Returns
    None when the cache is unavailable so the caller can fall back."""
    if not ip:
        return []
    try:
        r = await get_redis()
        lo = now.timestamp() - max(1, minutes) * 60
        members = await r.zrevrangebyscore(_key(ip), now.timestamp(), lo)
    except Exception as e:
        logger.warning(f"waf_path_cache recent_paths failed for {ip}: {e}")
        return None
    out: list[dict] = []
    for m in members:
        try:
            out.append(json.loads(m))
        except (ValueError, TypeError):
            continue
    return out
