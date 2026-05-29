"""LLM-call telemetry — sibling of ``osint_metrics``.

Every outbound ``/chat/completions`` call is counted in an in-memory dict
per ``(source, status, model, bucket_day)``. A scheduler job flushes the
dict into ``llm_usage`` once a minute via UPSERT. The stats endpoint then
aggregates this to per-source / per-model totals, average latency, and
token consumption (so the operator can spot runaway prompts before the
bill arrives if they ever switch from local LMStudio to a paid backend).

``source`` values:
  - ``alert``         LLM call inside ``agent_loop`` for a Sophos alert
  - ``waf``           LLM call inside ``agent_waf_loop``
  - ``ips``           LLM call inside ``agent_ips_loop``
  - ``failed_login``  LLM call inside ``agent_failed_login_loop``
  - ``test``          probe call from ``/api/admin/test/agent``
  - ``manual``        any other caller (currently unused but reserved)

``status``: ``success`` for HTTP 200 + parseable JSON, ``error`` for any
exception path (transport, timeout, JSON-shape failure, validation).
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from app.database import async_session

logger = logging.getLogger(__name__)


# (source, status, model, bucket_day) -> aggregated metrics
class _Bucket:
    __slots__ = ("count", "prompt_tokens", "completion_tokens", "duration_ms", "last_called_at")

    def __init__(self) -> None:
        self.count = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.duration_ms = 0
        self.last_called_at: datetime | None = None


_counter: dict[tuple[str, str, str, datetime], _Bucket] = defaultdict(_Bucket)
_lock = asyncio.Lock()


SOURCES: list[str] = ["alert", "waf", "ips", "failed_login", "test", "manual"]


def _day_bucket(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


async def record(
    source: str,
    status: str,
    model: str,
    duration_ms: int,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
) -> None:
    """Record one LLM call. Token counts are optional — many local
    backends don't surface them (or return 0). The recorder never raises;
    a broken metrics layer must never break the agent pipeline."""
    if not source:
        source = "manual"
    if not status:
        status = "success"
    if not model:
        model = "unknown"
    now = datetime.now(timezone.utc)
    key = (source[:20], status[:20], model[:120], _day_bucket(now))
    async with _lock:
        b = _counter[key]
        b.count += 1
        b.prompt_tokens += int(prompt_tokens or 0)
        b.completion_tokens += int(completion_tokens or 0)
        b.duration_ms += int(duration_ms or 0)
        b.last_called_at = now


async def flush_to_db() -> int:
    """UPSERT the in-memory counter into ``llm_usage`` and clear it.
    Returns the number of (source, status, model, day) tuples flushed."""
    async with _lock:
        if not _counter:
            return 0
        snapshot = dict(_counter)
        _counter.clear()

    upsert_sql = text("""
        INSERT INTO llm_usage
            (source, status, model, bucket_day, count, prompt_tokens,
             completion_tokens, duration_ms, last_called_at)
        VALUES (:source, :status, :model, :bucket_day, :count, :pt, :ct, :dur, :last)
        ON CONFLICT (source, status, model, bucket_day)
        DO UPDATE SET
            count             = llm_usage.count + EXCLUDED.count,
            prompt_tokens     = llm_usage.prompt_tokens + EXCLUDED.prompt_tokens,
            completion_tokens = llm_usage.completion_tokens + EXCLUDED.completion_tokens,
            duration_ms       = llm_usage.duration_ms + EXCLUDED.duration_ms,
            last_called_at    = GREATEST(llm_usage.last_called_at, EXCLUDED.last_called_at)
    """)

    async with async_session() as db:
        for (source, status, model, bucket_day), b in snapshot.items():
            await db.execute(upsert_sql, {
                "source": source,
                "status": status,
                "model": model,
                "bucket_day": bucket_day,
                "count": b.count,
                "pt": b.prompt_tokens,
                "ct": b.completion_tokens,
                "dur": b.duration_ms,
                "last": b.last_called_at or datetime.now(timezone.utc),
            })
        await db.commit()
    return len(snapshot)


async def query_usage(
    days: int = 30,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, Any]:
    """Aggregated LLM usage.

    Defaults to the last ``days`` days. If ``start`` / ``end`` are given they
    override the days window — useful for the analyzer card on /stats.html
    which exposes per-day date pickers. Both are clamped to day-buckets.

    Shape::

        {
          "as_of":         "<ISO>",
          "window_start":  "<ISO>",
          "window_end":    "<ISO>",
          "month_start":   "<ISO>",
          "totals":        {today_calls, month_calls, window_calls,
                            today_tokens, month_tokens,
                            success_rate_pct, avg_duration_ms},
          "by_source":     [{source, count, success, error,
                             prompt_tokens, completion_tokens,
                             avg_duration_ms, last_called_at}, …],
          "by_model":      [{model, count, prompt_tokens, completion_tokens, avg_duration_ms}, …],
          "totals_by_day": [{day, count, prompt_tokens, completion_tokens}, …],
          "by_source_by_day": {
            "<source>": [{day, count, prompt_tokens, completion_tokens}, …]
          }
        }
    """
    now = datetime.now(timezone.utc)
    today = _day_bucket(now)
    month_start = today.replace(day=1)
    if start is not None:
        window_start = _day_bucket(start)
        window_end = _day_bucket(end) if end is not None else today
    else:
        window_start = today - timedelta(days=days - 1)
        window_end = today
    if window_end < window_start:
        window_start, window_end = window_end, window_start

    async with _lock:
        # Snapshot pending counters so the UI reflects very recent activity
        pending = {k: (b.count, b.prompt_tokens, b.completion_tokens,
                       b.duration_ms, b.last_called_at)
                   for k, b in _counter.items()}

    async with async_session() as db:
        rows = (await db.execute(text("""
            SELECT source, status, model, bucket_day,
                   count, prompt_tokens, completion_tokens, duration_ms, last_called_at
            FROM llm_usage
            WHERE bucket_day >= :since AND bucket_day <= :until
        """), {"since": window_start, "until": window_end})).all()

    # Combine DB rows + in-memory pending into a unified list of tuples
    combined: list[tuple[str, str, str, datetime, int, int, int, int, datetime | None]] = []
    for r in rows:
        combined.append((r[0], r[1], r[2], r[3], int(r[4]), int(r[5]), int(r[6]), int(r[7]), r[8]))
    for (s, st, m, d), (cnt, pt, ct, dur, last) in pending.items():
        if window_start <= d <= window_end:
            combined.append((s, st, m, d, cnt, pt, ct, dur, last))

    # by_source rollup
    by_source: dict[str, dict[str, Any]] = {}
    for s in SOURCES:
        by_source[s] = {
            "source": s, "count": 0, "success": 0, "error": 0,
            "prompt_tokens": 0, "completion_tokens": 0, "duration_ms": 0,
            "last_called_at": None,
        }

    # by_model rollup, by_day rollup, KPIs
    by_model: dict[str, dict[str, Any]] = {}
    by_day: dict[str, dict[str, Any]] = {}
    by_source_by_day: dict[str, dict[str, dict[str, Any]]] = {}
    today_calls = 0; month_calls = 0; window_calls = 0
    today_tokens = 0; month_tokens = 0
    total_success = 0; total_error = 0
    total_duration_ms = 0
    last_called_overall: datetime | None = None

    for s, st, m, d, cnt, pt, ct, dur, last in combined:
        tok = pt + ct
        # by_source
        rec = by_source.setdefault(s, {
            "source": s, "count": 0, "success": 0, "error": 0,
            "prompt_tokens": 0, "completion_tokens": 0, "duration_ms": 0,
            "last_called_at": None,
        })
        rec["count"] += cnt
        rec["prompt_tokens"] += pt
        rec["completion_tokens"] += ct
        rec["duration_ms"] += dur
        if st == "success":
            rec["success"] += cnt
            total_success += cnt
        else:
            rec["error"] += cnt
            total_error += cnt
        if last and (rec["last_called_at"] is None or last > rec["last_called_at"]):
            rec["last_called_at"] = last
        if last and (last_called_overall is None or last > last_called_overall):
            last_called_overall = last

        # by_model
        mrec = by_model.setdefault(m, {
            "model": m, "count": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "duration_ms": 0,
        })
        mrec["count"] += cnt
        mrec["prompt_tokens"] += pt
        mrec["completion_tokens"] += ct
        mrec["duration_ms"] += dur

        # by_day (global)
        day_iso = d.isoformat()
        drec = by_day.setdefault(day_iso, {
            "day": day_iso, "count": 0, "prompt_tokens": 0, "completion_tokens": 0,
        })
        drec["count"] += cnt
        drec["prompt_tokens"] += pt
        drec["completion_tokens"] += ct

        # by_source_by_day — for the analyzer chart on /stats.html
        by_source_by_day.setdefault(s, {})
        sd = by_source_by_day[s].setdefault(day_iso, {
            "day": day_iso, "count": 0,
            "prompt_tokens": 0, "completion_tokens": 0,
        })
        sd["count"] += cnt
        sd["prompt_tokens"] += pt
        sd["completion_tokens"] += ct

        # Rollups for KPI tiles
        window_calls += cnt
        total_duration_ms += dur
        if d >= month_start:
            month_calls += cnt
            month_tokens += tok
        if d == today:
            today_calls += cnt
            today_tokens += tok

    # Derived metrics + cleanup
    for rec in by_source.values():
        rec["avg_duration_ms"] = round(rec["duration_ms"] / rec["count"], 1) if rec["count"] else None
        if rec["last_called_at"]:
            rec["last_called_at"] = rec["last_called_at"].isoformat()
        # drop the raw duration sum from the user-facing payload
        rec.pop("duration_ms", None)

    for mrec in by_model.values():
        mrec["avg_duration_ms"] = round(mrec["duration_ms"] / mrec["count"], 1) if mrec["count"] else None
        mrec.pop("duration_ms", None)

    success_rate = round((total_success / (total_success + total_error)) * 100, 1) if (total_success + total_error) else None
    avg_dur_overall = round(total_duration_ms / window_calls, 1) if window_calls else None

    # Convert the per-source-per-day map into sorted lists for the frontend
    by_source_by_day_out: dict[str, list[dict[str, Any]]] = {
        src: sorted(days_map.values(), key=lambda r: r["day"])
        for src, days_map in by_source_by_day.items()
    }

    return {
        "as_of": now.isoformat(),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "month_start": month_start.isoformat(),
        "totals": {
            "today_calls": today_calls,
            "month_calls": month_calls,
            "window_calls": window_calls,
            "today_tokens": today_tokens,
            "month_tokens": month_tokens,
            "success_rate_pct": success_rate,
            "avg_duration_ms": avg_dur_overall,
            "last_called_at": last_called_overall.isoformat() if last_called_overall else None,
        },
        "by_source": sorted(by_source.values(), key=lambda r: r["count"], reverse=True),
        "by_model":  sorted(by_model.values(),  key=lambda r: r["count"], reverse=True),
        "totals_by_day": sorted(by_day.values(), key=lambda r: r["day"]),
        "by_source_by_day": by_source_by_day_out,
    }
