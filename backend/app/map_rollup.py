"""Incremental daily rollup of the geo-located firewall_logs behind the attack map.

The attack map used to aggregate 4-11M raw ``firewall_logs`` rows on every cache
miss (13-30s cold). This keeps a compact per-day, per-attacker rollup
(``fw_map_daily``) that the map reads instead — thousands of rows, sub-second.

Maintenance is incremental by an **id watermark** (``rollup_state.last_id``):
``firewall_logs.id`` is a strictly increasing serial, so every row is folded in
exactly once regardless of created_at ordering. Counts are additive; the ON
CONFLICT merge unions the per-day metadata arrays (capped) and keeps the precise
min/max ``created_at`` as first/last-seen.
"""
from __future__ import annotations

import logging

from sqlalchemy import text

from app.database import async_session

logger = logging.getLogger(__name__)

# Private/reserved ranges: an IP in one of these is "internal", so the OTHER end
# of the connection is the external threat. Kept identical to the attack-map
# endpoint so the rollup and any live fallback agree.
_PRIVATE_CIDRS = (
    "'10.0.0.0/8'", "'172.16.0.0/12'", "'192.168.0.0/16'",
    "'127.0.0.0/8'", "'169.254.0.0/16'", "'0.0.0.0/8'", "'100.64.0.0/10'",
)


def _is_private_sql(col: str) -> str:
    checks = " OR ".join(f"{col}::inet <<= inet {c}" for c in _PRIVATE_CIDRS)
    return f"({col} ~ '^[0-9.]+$' AND ({checks}))"


def threat_ip_sql(src: str = "source_ip", dst: str = "destination_ip") -> str:
    return f"""CASE
        WHEN {src} IS NULL THEN {dst}
        WHEN {dst} IS NULL THEN {src}
        WHEN {_is_private_sql(src)} AND NOT {_is_private_sql(dst)} THEN {dst}
        ELSE {src}
    END"""


def inbound_sql(src: str = "source_ip", dst: str = "destination_ip") -> str:
    return f"({src} IS NOT NULL AND NOT {_is_private_sql(src)} AND {_is_private_sql(dst)})"


def outbound_sql(src: str = "source_ip", dst: str = "destination_ip") -> str:
    return f"({dst} IS NOT NULL AND {_is_private_sql(src)} AND NOT {_is_private_sql(dst)})"


def _arr(expr: str, cap: int = 12) -> str:
    # COALESCE to '{}' — array_agg over an all-filtered-out group returns NULL,
    # but the rollup columns are NOT NULL.
    return (f"COALESCE((array_agg(DISTINCT {expr}) "
            f"FILTER (WHERE {expr} IS NOT NULL))[1:{cap}], '{{}}')")


def _merge(col: str, cap: int = 12) -> str:
    return (f"COALESCE((SELECT (array_agg(DISTINCT e))[1:{cap}] "
            f"FROM unnest(t.{col} || EXCLUDED.{col}) e WHERE e IS NOT NULL), '{{}}')")


def _upsert_sql() -> str:
    threat = threat_ip_sql()
    inb = inbound_sql()
    outb = outbound_sql()
    return f"""
    WITH batch AS (
        SELECT id, created_at, severity, source_ip, destination_ip,
               attacker_lat, attacker_lon, attacker_country, attacker_city,
               attacker_asn, attacker_org, threat_name, action, log_type,
               destination_port, user_name, firewall_name,
               ({threat}) AS threat_ip
        FROM firewall_logs
        WHERE id > :lo AND id <= :hi
          AND attacker_lat IS NOT NULL AND attacker_lon IS NOT NULL
          AND created_at IS NOT NULL
    ),
    agg AS (
        SELECT date_trunc('day', created_at)::date AS day,
               threat_ip,
               attacker_lat AS lat, attacker_lon AS lon,
               max(attacker_country) AS country, max(attacker_city) AS city,
               count(*) AS cnt, max(severity) AS max_severity,
               min(created_at) AS first_seen, max(created_at) AS last_seen,
               max(attacker_asn) AS asn, max(attacker_org) AS org,
               COALESCE(bool_or({inb}), false) AS has_inbound,
               COALESCE(bool_or({outb}), false) AS has_outbound,
               {_arr('threat_name')} AS threats,
               {_arr('action')} AS actions,
               {_arr('log_type')} AS log_types,
               {_arr('destination_port::text')} AS dest_ports,
               {_arr('user_name')} AS users,
               {_arr('firewall_name')} AS firewalls
        FROM batch
        WHERE threat_ip IS NOT NULL
        GROUP BY day, threat_ip, lat, lon
    )
    INSERT INTO fw_map_daily AS t
        (day, threat_ip, lat, lon, country, city, cnt, max_severity,
         first_seen, last_seen, asn, org, has_inbound, has_outbound,
         threats, actions, log_types, dest_ports, users, firewalls)
    SELECT day, threat_ip, lat, lon, country, city, cnt, max_severity,
           first_seen, last_seen, asn, org, has_inbound, has_outbound,
           threats, actions, log_types, dest_ports, users, firewalls
    FROM agg
    ON CONFLICT (day, threat_ip, lat, lon) DO UPDATE SET
        cnt = t.cnt + EXCLUDED.cnt,
        max_severity = GREATEST(t.max_severity, EXCLUDED.max_severity),
        first_seen = LEAST(t.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(t.last_seen, EXCLUDED.last_seen),
        country = COALESCE(EXCLUDED.country, t.country),
        city = COALESCE(EXCLUDED.city, t.city),
        asn = COALESCE(EXCLUDED.asn, t.asn),
        org = COALESCE(EXCLUDED.org, t.org),
        has_inbound = t.has_inbound OR EXCLUDED.has_inbound,
        has_outbound = t.has_outbound OR EXCLUDED.has_outbound,
        threats = {_merge('threats')},
        actions = {_merge('actions')},
        log_types = {_merge('log_types')},
        dest_ports = {_merge('dest_ports')},
        users = {_merge('users')},
        firewalls = {_merge('firewalls')}
    """


# Built once — the threat/inbound/outbound expressions are static.
_UPSERT_SQL = None


def _sql() -> str:
    global _UPSERT_SQL
    if _UPSERT_SQL is None:
        _UPSERT_SQL = _upsert_sql()
    return _UPSERT_SQL


# Transaction-scoped advisory lock so two refreshers (e.g. the scheduled job and
# a manual backfill) can never process overlapping id ranges — that would
# double-count the additive `cnt`. Whoever holds it wins; others skip this tick.
_LOCK_KEY = 776612001


async def refresh_map_rollup(chunk: int = 1_000_000) -> dict:
    """Fold one id-chunk of new firewall_logs rows into fw_map_daily.

    Returns {processed, watermark, caught_up}. Safe to call repeatedly and
    concurrently; each row is processed exactly once (strictly increasing id
    watermark, serialized by an advisory lock)."""
    async with async_session() as db:
        if not await db.scalar(text("SELECT pg_try_advisory_xact_lock(:k)"),
                               {"k": _LOCK_KEY}):
            return {"processed": 0, "watermark": None, "caught_up": True,
                    "skipped": True}
        lo = (await db.scalar(
            text("SELECT last_id FROM rollup_state WHERE name = 'map_rollup'")
        )) or 0
        hi_cap = lo + chunk
        max_in_range = await db.scalar(text(
            "SELECT max(id) FROM firewall_logs WHERE id > :lo AND id <= :hi"
        ), {"lo": lo, "hi": hi_cap})
        if max_in_range is None:
            return {"processed": 0, "watermark": lo, "caught_up": True}

        res = await db.execute(text(_sql()), {"lo": lo, "hi": max_in_range})
        processed = res.rowcount if res.rowcount is not None else -1
        await db.execute(text(
            "INSERT INTO rollup_state (name, last_id, updated_at) "
            "VALUES ('map_rollup', :wm, now()) "
            "ON CONFLICT (name) DO UPDATE SET last_id = :wm, updated_at = now()"
        ), {"wm": max_in_range})
        await db.commit()

        table_max = await db.scalar(text("SELECT max(id) FROM firewall_logs"))
        caught_up = table_max is None or max_in_range >= table_max
        return {"processed": processed, "watermark": max_in_range, "caught_up": caught_up}


async def refresh_map_rollup_job() -> None:
    """Scheduler entry point: catch up in a few chunks per tick so a burst of
    ingestion doesn't leave the rollup lagging, but bound the work per run."""
    for _ in range(6):
        r = await refresh_map_rollup()
        if r["caught_up"] or r["processed"] == 0:
            break
