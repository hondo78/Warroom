"""Outbound OSINT-provider usage telemetry.

Each external API call (AbuseIPDB, VirusTotal, Shodan, GreyNoise,
Sophos Intelix, ip-api.com) is counted in an in-memory dict per
(provider, status, day-bucket). A scheduler job flushes the dict to the
``osint_usage`` table once a minute via UPSERT. The stats endpoint then
joins these counts against the configured per-provider quota limits to
report utilization — so an operator can see at a glance whether the
WAF/IPS/Agent loops are about to burn through a daily allowance.

``status`` values:
  - ``success``    real HTTP 200 with payload
  - ``no_record``  real HTTP 404 or 200-but-empty (still counts against quota)
  - ``error``      auth failure, HTTP 5xx, timeout (typically NOT billed but
                   still surfaced so misconfigurations show up)
  - ``cache_hit``  served from Redis; NO outbound call happened — does not
                   count against quota and is reported separately for the
                   cache-hit-rate widget
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from app.config import settings
from app.database import async_session

logger = logging.getLogger(__name__)


# (provider, status, bucket_day) -> count
_counter: dict[tuple[str, str, datetime], int] = defaultdict(int)
_last_called: dict[tuple[str, str, datetime], datetime] = {}
_lock = asyncio.Lock()


# Providers we track. Order is also the display order in the UI.
PROVIDERS: list[str] = [
    "abuseipdb",
    "virustotal",
    "shodan",
    "greynoise",
    "intelix",
    "ipinfo",
]


def _day_bucket(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


async def record(provider: str, status: str) -> None:
    """Record one outbound call. ``status`` must be one of the documented
    values (success/no_record/error/cache_hit). Cheap and lock-protected so
    multiple async provider calls can hit it concurrently."""
    if provider not in PROVIDERS:
        # Silently drop unknown providers — keeps the table cardinality bounded
        return
    now = datetime.now(timezone.utc)
    key = (provider, status, _day_bucket(now))
    async with _lock:
        _counter[key] += 1
        _last_called[key] = now


async def flush_to_db() -> int:
    """Move the in-memory counter into ``osint_usage`` via UPSERT.

    Returns the number of (provider, status, day) tuples flushed."""
    async with _lock:
        if not _counter:
            return 0
        snapshot = dict(_counter)
        last_snap = dict(_last_called)
        _counter.clear()
        _last_called.clear()

    upsert_sql = text("""
        INSERT INTO osint_usage (provider, status, bucket_day, count, last_called_at)
        VALUES (:provider, :status, :bucket_day, :count, :last_called_at)
        ON CONFLICT (provider, status, bucket_day)
        DO UPDATE SET
            count = osint_usage.count + EXCLUDED.count,
            last_called_at = GREATEST(osint_usage.last_called_at, EXCLUDED.last_called_at)
    """)

    async with async_session() as db:
        for (provider, status, bucket_day), cnt in snapshot.items():
            await db.execute(upsert_sql, {
                "provider": provider,
                "status": status,
                "bucket_day": bucket_day,
                "count": cnt,
                "last_called_at": last_snap.get(
                    (provider, status, bucket_day), datetime.now(timezone.utc)
                ),
            })
        await db.commit()
    return len(snapshot)


def _limits_for(provider: str) -> tuple[int, int]:
    """Return (daily_limit, monthly_limit). 0 = no limit configured."""
    daily = getattr(settings, f"osint_{provider}_daily_limit", 0) or 0
    monthly = getattr(settings, f"osint_{provider}_monthly_limit", 0) or 0
    return int(daily), int(monthly)


def _pct(n: int, limit: int) -> float | None:
    if limit <= 0:
        return None
    return round((n / limit) * 100, 1)


async def _real_counts(provider: str) -> tuple[int, int]:
    """(today_real, month_real) outbound calls for ``provider`` — excludes
    cache_hit, includes both the flushed DB rows and the not-yet-flushed
    in-memory counters so a hard quota gate can't overshoot within a flush
    window."""
    now = datetime.now(timezone.utc)
    today = _day_bucket(now)
    month_start = today.replace(day=1)
    async with _lock:
        pend_today = sum(c for (p, s, d), c in _counter.items()
                         if p == provider and s != "cache_hit" and d == today)
        pend_month = sum(c for (p, s, d), c in _counter.items()
                         if p == provider and s != "cache_hit" and d >= month_start)
    async with async_session() as db:
        rows = (await db.execute(text("""
            SELECT bucket_day, COALESCE(SUM(count), 0)
            FROM osint_usage
            WHERE provider = :p AND status <> 'cache_hit' AND bucket_day >= :m
            GROUP BY bucket_day
        """), {"p": provider, "m": month_start})).all()
    db_today = sum(int(c) for d, c in rows if d == today)
    db_month = sum(int(c) for _d, c in rows)
    return db_today + pend_today, db_month + pend_month


async def quota_exhausted(provider: str) -> bool:
    """True if ``provider`` has reached its configured DAILY or MONTHLY limit
    (0 = no limit). Used to hard-stop automatic lookups before they burn through
    a paid allowance."""
    daily, monthly = _limits_for(provider)
    if daily <= 0 and monthly <= 0:
        return False
    today_real, month_real = await _real_counts(provider)
    if daily > 0 and today_real >= daily:
        return True
    if monthly > 0 and month_real >= monthly:
        return True
    return False


async def query_usage(days: int = 30) -> dict[str, Any]:
    """Per-provider aggregation with quota utilization.

    Today's count and this-month's count exclude ``cache_hit`` (those didn't
    burn quota). Cache-hit-rate is computed as cache_hit / (cache_hit + real)
    over the window.
    """
    now = datetime.now(timezone.utc)
    today = _day_bucket(now)
    month_start = today.replace(day=1)
    window_start = today - timedelta(days=days - 1)

    # Pull pre-snapshot of pending counters too so the UI looks live without
    # waiting for the 60s flush job. Just merge into the response on top of
    # the DB rows.
    async with _lock:
        pending = dict(_counter)
        pending_last = dict(_last_called)

    async with async_session() as db:
        rows = (await db.execute(text("""
            SELECT provider, status, bucket_day, count, last_called_at
            FROM osint_usage
            WHERE bucket_day >= :since
        """), {"since": window_start})).all()

    # Materialize a per-provider × per-day series for charts plus rolled
    # totals across today / this month / window.
    per_provider: dict[str, dict[str, Any]] = {}
    for prov in PROVIDERS:
        per_provider[prov] = {
            "provider": prov,
            "today": defaultdict(int),    # status -> count
            "month": defaultdict(int),
            "window": defaultdict(int),
            "last_called_at": None,
            "by_day": defaultdict(lambda: defaultdict(int)),  # day_iso -> status -> count
        }

    def _accumulate(prov: str, status: str, day: datetime, count: int, last_called: datetime | None):
        if prov not in per_provider:
            return
        rec = per_provider[prov]
        rec["window"][status] += count
        if day >= month_start:
            rec["month"][status] += count
        if day == today:
            rec["today"][status] += count
        rec["by_day"][day.isoformat()][status] += count
        if last_called is not None:
            if rec["last_called_at"] is None or last_called > rec["last_called_at"]:
                rec["last_called_at"] = last_called

    for prov, status, bucket_day, cnt, lc in rows:
        _accumulate(prov, status, bucket_day, int(cnt), lc)

    for (prov, status, bucket_day), cnt in pending.items():
        _accumulate(
            prov, status, bucket_day, cnt,
            pending_last.get((prov, status, bucket_day)),
        )

    # Cleanup: convert defaultdicts and compute derived fields
    out_providers: list[dict[str, Any]] = []
    for prov in PROVIDERS:
        rec = per_provider[prov]
        daily_limit, monthly_limit = _limits_for(prov)

        # Real calls = anything that actually went out (exclude cache_hit)
        def _real(d):
            return sum(v for k, v in d.items() if k != "cache_hit")

        today_real = _real(rec["today"])
        month_real = _real(rec["month"])
        window_real = _real(rec["window"])
        window_cache = rec["window"].get("cache_hit", 0)
        cache_rate = round(
            (window_cache / (window_cache + window_real)) * 100, 1
        ) if (window_cache + window_real) else None

        # Highest utilization decides the badge color in the UI
        daily_pct = _pct(today_real, daily_limit)
        monthly_pct = _pct(month_real, monthly_limit)
        utilization_pct = max(
            [p for p in (daily_pct, monthly_pct) if p is not None],
            default=None,
        )
        if utilization_pct is None:
            warn = "ok"
        elif utilization_pct >= 100:
            warn = "exceeded"
        elif utilization_pct >= 80:
            warn = "warn"
        else:
            warn = "ok"

        out_providers.append({
            "provider": prov,
            "today": dict(rec["today"]),
            "month": dict(rec["month"]),
            "window": dict(rec["window"]),
            "today_real": today_real,
            "month_real": month_real,
            "window_real": window_real,
            "window_cache_hit": window_cache,
            "cache_hit_rate_pct": cache_rate,
            "daily_limit": daily_limit,
            "monthly_limit": monthly_limit,
            "daily_used_pct": daily_pct,
            "monthly_used_pct": monthly_pct,
            "warn_level": warn,
            "last_called_at": rec["last_called_at"].isoformat() if rec["last_called_at"] else None,
            "by_day": [
                {"day": day, **counts}
                for day, counts in sorted(rec["by_day"].items())
            ],
        })

    # Global rollups for KPI cards
    total_today = sum(p["today_real"] for p in out_providers)
    total_month = sum(p["month_real"] for p in out_providers)
    total_window = sum(p["window_real"] for p in out_providers)
    total_cache = sum(p["window_cache_hit"] for p in out_providers)
    global_cache_rate = round(
        (total_cache / (total_cache + total_window)) * 100, 1
    ) if (total_cache + total_window) else None
    near_limit = sum(1 for p in out_providers if p["warn_level"] in ("warn", "exceeded"))

    return {
        "as_of": now.isoformat(),
        "window_start": window_start.isoformat(),
        "month_start": month_start.isoformat(),
        "totals": {
            "today_real": total_today,
            "month_real": total_month,
            "window_real": total_window,
            "window_cache_hit": total_cache,
            "global_cache_hit_rate_pct": global_cache_rate,
            "providers_near_limit": near_limit,
        },
        "providers": out_providers,
    }
