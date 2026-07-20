import hashlib
import hmac
import logging
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Body, FastAPI, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, text, case, literal_column
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cached
from app.collector import collect_all, collect_o365
from app.config import settings
from app.database import async_session, ensure_schema, get_db
from app.geoip_service import get_redis, close_redis
from fastapi.responses import PlainTextResponse

from app.models import AgentApprovalPattern, AgentDecision, Alert, AnomalyVerdict, AppSetting, BlockedDomain, BlockedIp, BlockedUrl, Detection, Endpoint, Event, FirewallLocation, FirewallLog, GeoIPCache, Honeypot, HoneypotEvent, M365LoginProfile, MonitoredConnection, MonitoredEvent, NetflowBucket, NetflowIfaceBucket, O365AuditLog, OsintResult, ShodanHost, WatchlistIp, WhitelistedIp
from app.o365_client import app_display_name, o365_client
from app.sophos_client import sophos_client
from app.settings_store import (
    MANAGED_KEYS,
    SECRET_KEYS,
    apply_overrides_to_settings,
    save_settings,
    serialize_settings,
)

import json
import httpx

logging.basicConfig(level=settings.log_level.upper())
logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def verify_api_key(request: Request, x_api_key: str | None = Header(default=None)):
    # The Teams webhook authenticates itself with its own HMAC signature
    # (Teams never sends X-API-Key), so it is exempt from the global key check.
    if request.url.path.startswith("/api/teams/"):
        return
    # Honeypot pods authenticate with their own per-pod bearer token (they run on
    # remote hosts and never hold the Warroom API key), so the agent-facing
    # endpoints are exempt from the global key check and verify the token inline.
    if request.url.path.startswith("/api/honeypot/agent/"):
        return
    expected = settings.warroom_api_key
    if not expected:
        # Open mode: warning is logged once at startup; do not block.
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-API-Key",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.warroom_api_key:
        logger.warning(
            "WARROOM_API_KEY is empty — backend runs in OPEN mode. "
            "Set WARROOM_API_KEY in .env to require authentication on /api/*."
        )
    await ensure_schema()
    # Encrypt any plaintext secrets already in app_settings (one-time, idempotent).
    from app.settings_store import encrypt_existing_secrets
    await encrypt_existing_secrets()
    # Merge DB overrides on top of .env defaults before any client uses settings.
    await apply_overrides_to_settings()
    sophos_client.reload()
    scheduler.add_job(collect_all, "interval", seconds=settings.collector_interval, id="collector")
    # M365 audit-log collector — separate job so missing Sophos credentials
    # never block it (and vice versa). Idles until the O365 app is configured.
    scheduler.add_job(collect_o365, "interval", seconds=settings.collector_interval, id="o365_collector")
    # Keep the heavy dashboard endpoints warm in Redis so the first user after
    # an idle period doesn't pay the cold-query price. Tighter than the lowest
    # @cached TTL (30s) so cache entries always overlap.
    scheduler.add_job(warm_dashboard_cache, "interval", seconds=25, id="cache_warmer")
    scheduler.add_job(warm_dashboard_cache, "date", id="initial_warm")
    # Keep the attack-map daily rollup (fw_map_daily) current — folds newly
    # ingested firewall_logs in by id watermark. max_instances=1 so a slow catch-up
    # never overlaps itself.
    from app.map_rollup import refresh_map_rollup_job
    scheduler.add_job(refresh_map_rollup_job, "interval", seconds=30,
                      id="map_rollup", max_instances=1, coalesce=True)
    # Keep the Tor exit-node list fresh for the OSINT tor check (free, no API key).
    from app.osint import refresh_tor_exit_nodes
    scheduler.add_job(refresh_tor_exit_nodes, "interval", minutes=60, id="tor_exit_refresh")
    scheduler.add_job(refresh_tor_exit_nodes, "date", id="initial_tor_exit_refresh")
    # AI agent — only fires if agent_enabled is set; the function itself
    # is the gate, so we always schedule it.
    from app.agent import (agent_loop, agent_event_loop, agent_waf_loop, agent_ips_loop,
                           agent_anomaly_loop, agent_connection_anomaly_loop,
                           agent_connection_triage_loop,
                           agent_failed_login_loop, agent_user_login_alert_loop)
    scheduler.add_job(
        agent_loop, "interval",
        seconds=max(30, settings.agent_interval_seconds),
        id="agent_loop",
    )
    scheduler.add_job(
        agent_event_loop, "interval",
        seconds=max(30, settings.agent_event_interval_seconds),
        id="agent_event_loop",
    )
    scheduler.add_job(
        agent_waf_loop, "interval",
        seconds=max(30, settings.agent_waf_interval_seconds),
        id="agent_waf_loop",
    )
    scheduler.add_job(
        agent_ips_loop, "interval",
        seconds=max(30, settings.agent_ips_interval_seconds),
        id="agent_ips_loop",
    )
    # FW-anomaly triage: Isolation Forest over NetFlow + OSINT/LLM verdicts.
    scheduler.add_job(
        agent_anomaly_loop, "interval",
        seconds=max(60, settings.agent_anomaly_interval_seconds),
        id="agent_anomaly_loop",
    )
    # Per-connection C2/exfil detection + alarming (notify-only; off by default).
    scheduler.add_job(
        agent_connection_anomaly_loop, "interval",
        seconds=max(60, settings.agent_connanom_interval_seconds),
        id="agent_connection_anomaly_loop",
    )
    # Daily LLM assessment of connection anomalies (source↔destination reasoning).
    scheduler.add_job(
        agent_connection_triage_loop, "interval",
        seconds=max(3600, settings.agent_conntriage_interval_seconds),
        id="agent_connection_triage_loop",
    )
    scheduler.add_job(
        agent_failed_login_loop, "interval",
        seconds=max(30, settings.agent_failed_login_interval_seconds),
        id="agent_failed_login_loop",
    )
    # User-centric brute-force alerting (stores attempts in Redis, classifies via
    # LLM, Telegram-warns when a user is endangered). Notify-only; independent of
    # the blocking failed-login agent. No-op while disabled.
    scheduler.add_job(
        agent_user_login_alert_loop, "interval",
        seconds=max(60, settings.agent_failed_login_interval_seconds),
        id="agent_user_login_alert_loop",
    )
    # OSINT-usage telemetry: flush the in-memory provider-call counter once a minute
    from app.osint_metrics import flush_to_db as flush_osint_metrics
    scheduler.add_job(flush_osint_metrics, "interval", seconds=60, id="osint_metrics_flush")
    # LLM-usage telemetry: flush the in-memory LLM-call counter once a minute
    from app.llm_metrics import flush_to_db as flush_llm_metrics
    scheduler.add_job(flush_llm_metrics, "interval", seconds=60, id="llm_metrics_flush")
    # Email-API snapshot for the Grafana email dashboard (live API isn't
    # persisted otherwise). Every 15 min + once shortly after start.
    from app.email_metrics import collect_email_metrics
    scheduler.add_job(collect_email_metrics, "interval", seconds=900, id="email_metrics")
    scheduler.add_job(collect_email_metrics, "date", id="initial_email_metrics")
    # Telegram approval bot — push prompts for pending decisions + poll for
    # button taps. Both no-op while telegram_enabled is off.
    from app.telegram_client import telegram_push_pending, telegram_poll_updates
    scheduler.add_job(telegram_push_pending, "interval", seconds=15, id="telegram_push")
    scheduler.add_job(
        telegram_poll_updates, "interval",
        seconds=max(2, settings.telegram_poll_interval_seconds),
        id="telegram_poll",
    )
    # Entra ID conditional-access blocklist sync (no-op while disabled).
    from app.entra_client import entra_sync_job
    scheduler.add_job(
        entra_sync_job, "interval",
        minutes=max(1, settings.entra_block_sync_interval_minutes),
        id="entra_sync",
    )
    # Firewall-log retention: prune the fast-growing firewall_logs table
    # (batched deletes). Runs every N hours + once shortly after start.
    from app.firewall_retention import purge_firewall_logs
    scheduler.add_job(
        purge_firewall_logs, "interval",
        hours=max(1, settings.firewall_log_retention_interval_hours),
        id="firewall_retention",
    )
    scheduler.add_job(purge_firewall_logs, "date", id="initial_firewall_retention")
    # Push the blocklists to the firewalls' MDR threat feed (no-op while
    # firewall_mdr_feed_enabled is off). Pull-based feeds need no job — the
    # firewall fetches /ioc_* directly.
    from app.firewall_feed import sync_mdr_threat_feed
    scheduler.add_job(
        sync_mdr_threat_feed, "interval",
        seconds=max(30, settings.firewall_mdr_feed_sync_interval_seconds),
        id="firewall_mdr_feed_sync",
    )
    # Internal-hostname resolver: drains the pending set (DNS/NetBIOS), caching
    # names for internal IPs shown across the UI.
    from app.hostname_service import hostname_resolve_worker
    scheduler.add_job(
        hostname_resolve_worker, "interval",
        seconds=20, id="hostname_resolve_worker",
    )
    # Host-identity monitor: detects IP↔MAC↔hostname changes + alarms. First run
    # seeds the baseline silently.
    from app.host_identity import scan as host_identity_scan
    scheduler.add_job(
        host_identity_scan, "interval",
        seconds=max(60, settings.host_identity_scan_interval_seconds),
        id="host_identity_scan",
    )
    scheduler.add_job(host_identity_scan, "date", id="initial_host_identity_scan")
    # M365 login watch — alerts (with revoke option) on sign-ins from new
    # devices / locations. First pass seeds the baseline silently.
    from app.m365_watch import m365_login_watch
    scheduler.add_job(
        m365_login_watch, "interval",
        seconds=max(30, settings.m365_login_watch_interval_seconds),
        id="m365_login_watch",
    )
    # Connection monitoring for specially-flagged blocklist / watchlist IPs —
    # tracks which internal hosts talk to them and alerts on new sessions.
    from app.ip_monitor import monitor_scan
    scheduler.add_job(
        monitor_scan, "interval",
        seconds=max(15, settings.ip_monitor_interval_seconds),
        id="ip_monitor_scan",
    )
    scheduler.start()
    # Run initial collection after short delay
    scheduler.add_job(collect_all, "date", id="initial_collect")
    scheduler.add_job(collect_o365, "date", id="initial_o365_collect")
    logger.info(f"Collector scheduled every {settings.collector_interval}s")
    # Run the MCP Streamable-HTTP session manager for the lifetime of the app so
    # the /mcp mount can serve requests.
    from app.mcp_server import mcp as _mcp
    async with _mcp.session_manager.run():
        yield
    scheduler.shutdown()
    await sophos_client.aclose()
    await o365_client.aclose()
    from app.entra_client import entra_client
    await entra_client.aclose()
    await close_redis()


app = FastAPI(title="Warroom API", lifespan=lifespan, dependencies=[Depends(verify_api_key)])

# Read-only log-search MCP server at /mcp (Streamable HTTP). Mounted sub-app, so
# it bypasses the global X-API-Key dependency and is guarded by its own bearer
# token + mcp_enabled flag (see app/mcp_server._MCPAuth). Mounting calls
# streamable_http_app(), which lazily creates the session manager the lifespan runs.
from app.mcp_server import mcp_asgi_app
app.mount("/mcp", mcp_asgi_app())


class FirewallLocationIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    ip: str | None = Field(None, max_length=45)
    lat: float = Field(..., ge=-90, le=90)
    lon: float = Field(..., ge=-180, le=180)
    country: str | None = Field(None, max_length=100)
    city: str | None = Field(None, max_length=255)


# --- Dashboard Stats ---

@app.get("/api/stats/summary")
@cached(ttl=60)
async def get_summary(db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    alerts_24h = (await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= day_ago)
    )).scalar() or 0
    total_events = (await db.execute(select(func.count(Event.id)))).scalar() or 0
    events_24h = (await db.execute(
        select(func.count(Event.id)).where(Event.created_at >= day_ago)
    )).scalar() or 0
    # Threat-detections come from the threat-typed rows in `alerts` (XDR/MDR
    # endpoints are 404 for non-licensed tenants — see /api/detections/recent).
    threat_filter = (
        Alert.alert_type.ilike("%threat%")
        | Alert.alert_type.ilike("%detect%")
        | Alert.alert_type.ilike("%malware%")
        | (Alert.category == "runtimeDetections")
    )
    total_detections = (await db.execute(
        select(func.count(Alert.id)).where(threat_filter)
    )).scalar() or 0
    detections_24h = (await db.execute(
        select(func.count(Alert.id)).where(threat_filter, Alert.created_at >= day_ago)
    )).scalar() or 0

    high_severity = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.severity.in_(["high", "critical"]),
            Alert.created_at >= week_ago,
        )
    )).scalar() or 0

    total_fw_logs = (await db.execute(select(func.count(FirewallLog.id)))).scalar() or 0
    fw_logs_24h = (await db.execute(
        select(func.count(FirewallLog.id)).where(FirewallLog.created_at >= day_ago)
    )).scalar() or 0

    return {
        "total_alerts": total_alerts,
        "alerts_24h": alerts_24h,
        "total_events": total_events,
        "events_24h": events_24h,
        "total_detections": total_detections,
        "detections_24h": detections_24h,
        "total_fw_logs": total_fw_logs,
        "fw_logs_24h": fw_logs_24h,
        "high_severity_week": high_severity,
    }


@app.get("/api/stats/severity")
@cached(ttl=60)
async def get_severity_distribution(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.created_at >= since)
        .group_by(Alert.severity)
    )
    return [{"severity": row[0] or "unknown", "count": row[1]} for row in result.all()]


@app.get("/api/stats/timeline")
@cached(ttl=300)
async def get_timeline(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)

    alerts = await db.execute(
        select(
            func.date_trunc("day", Alert.created_at).label("day"),
            func.count(Alert.id),
        )
        .where(Alert.created_at >= since)
        .group_by(text("1"))
        .order_by(text("1"))
    )

    events = await db.execute(
        select(
            func.date_trunc("day", Event.created_at).label("day"),
            func.count(Event.id),
        )
        .where(Event.created_at >= since)
        .group_by(text("1"))
        .order_by(text("1"))
    )

    detection_filter = (
        Alert.alert_type.ilike("%threat%")
        | Alert.alert_type.ilike("%detect%")
        | Alert.alert_type.ilike("%malware%")
        | (Alert.category == "runtimeDetections")
    )
    detections = await db.execute(
        select(
            func.date_trunc("day", Alert.created_at).label("day"),
            func.count(Alert.id),
        )
        .where(Alert.created_at >= since, detection_filter)
        .group_by(text("1"))
        .order_by(text("1"))
    )

    return {
        "alerts": [{"date": row[0].isoformat() if row[0] else None, "count": row[1]} for row in alerts.all()],
        "events": [{"date": row[0].isoformat() if row[0] else None, "count": row[1]} for row in events.all()],
        "detections": [{"date": row[0].isoformat() if row[0] else None, "count": row[1]} for row in detections.all()],
    }


@app.get("/api/stats/categories")
@cached(ttl=60)
async def get_categories(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Alert.category, func.count(Alert.id))
        .where(Alert.created_at >= since)
        .group_by(Alert.category)
        .order_by(func.count(Alert.id).desc())
        .limit(15)
    )
    return [{"category": row[0] or "unknown", "count": row[1]} for row in result.all()]


@app.get("/api/stats/top-attackers")
@cached(ttl=60)
async def get_top_attackers(
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    threat_ip = func.coalesce(Alert.destination_ip, Alert.source_ip)
    result = await db.execute(
        select(
            threat_ip.label("threat_ip"),
            Alert.attacker_country,
            Alert.attacker_city,
            func.count(Alert.id).label("count"),
        )
        .where(Alert.created_at >= since, threat_ip.isnot(None))
        .group_by(threat_ip, Alert.attacker_country, Alert.attacker_city)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
    )
    return [
        {
            "ip": row[0],
            "country": row[1],
            "city": row[2],
            "count": row[3],
        }
        for row in result.all()
    ]


# --- Map Data ---

@app.get("/api/map/attacks")
@cached(ttl=300)
async def get_attack_map(
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)

    def _iso(dt):
        return dt.isoformat() if dt else None

    def _cap(arr, n=8):
        return [x for x in (arr or []) if x][:n]

    # Pick whichever side of the connection is public. Identifies the
    # external attacker even when SFOS reports the internal client as
    # source_ip (typical for outbound ATP/IDP detections, where dst is
    # the C2) or when an inbound alert has the internal target in
    # destination_ip.
    PRIVATE_CIDRS = (
        "'10.0.0.0/8'", "'172.16.0.0/12'", "'192.168.0.0/16'",
        "'127.0.0.0/8'", "'169.254.0.0/16'", "'0.0.0.0/8'",
        "'100.64.0.0/10'",
    )

    def _is_private_sql(col: str) -> str:
        # Guard the inet cast against malformed values via a regex pre-check.
        checks = " OR ".join(
            f"{col}::inet <<= inet {c}" for c in PRIVATE_CIDRS
        )
        return f"({col} ~ '^[0-9.]+$' AND ({checks}))"

    def _threat_ip_sql(src: str, dst: str) -> str:
        return f"""CASE
            WHEN {src} IS NULL THEN {dst}
            WHEN {dst} IS NULL THEN {src}
            WHEN {_is_private_sql(src)} AND NOT {_is_private_sql(dst)} THEN {dst}
            ELSE {src}
        END"""

    def _inbound_sql(src: str, dst: str) -> str:
        # external -> internal: src public, dst private
        return f"({src} IS NOT NULL AND NOT {_is_private_sql(src)} AND {_is_private_sql(dst)})"

    def _outbound_sql(src: str, dst: str) -> str:
        # internal -> external: src private, dst public
        return f"({dst} IS NOT NULL AND {_is_private_sql(src)} AND NOT {_is_private_sql(dst)})"

    alert_threat_expr = _threat_ip_sql("source_ip", "destination_ip")
    fw_threat_expr = _threat_ip_sql("source_ip", "destination_ip")
    alert_in_expr = _inbound_sql("source_ip", "destination_ip")
    alert_out_expr = _outbound_sql("source_ip", "destination_ip")
    fw_in_expr = _inbound_sql("source_ip", "destination_ip")
    fw_out_expr = _outbound_sql("source_ip", "destination_ip")

    # Attackers from Central alerts
    alert_sql = text(f"""
        SELECT
            ({alert_threat_expr}) AS threat_ip,
            attacker_lat, attacker_lon,
            attacker_country, attacker_city,
            COUNT(*) AS cnt,
            MAX(severity) AS max_severity,
            MIN(created_at) AS first_seen,
            MAX(created_at) AS last_seen,
            array_agg(DISTINCT alert_type) FILTER (WHERE alert_type IS NOT NULL) AS alert_types,
            array_agg(DISTINCT category)   FILTER (WHERE category IS NOT NULL)   AS categories,
            array_agg(DISTINCT destination_ip) FILTER (WHERE destination_ip IS NOT NULL) AS dest_ips,
            bool_or({alert_in_expr})  AS has_inbound,
            bool_or({alert_out_expr}) AS has_outbound
        FROM alerts
        WHERE created_at >= :since
          AND attacker_lat IS NOT NULL
          AND attacker_lon IS NOT NULL
          -- M365 logins are fed to the map directly from o365_audit_logs
          -- (split ok/failed); excluding the O365 alerts avoids double counting.
          AND (alert_type IS NULL OR alert_type NOT LIKE 'O365%')
        GROUP BY threat_ip, attacker_lat, attacker_lon, attacker_country, attacker_city
        ORDER BY cnt DESC
        LIMIT 500
    """)
    alert_rows = (await db.execute(alert_sql, {"since": since})).all()

    # Attackers from firewall syslog — read the pre-aggregated daily rollup
    # (app/map_rollup.py) instead of scanning millions of raw firewall_logs rows.
    # Two steps: rank the top-500 attackers over the window, then union each
    # one's per-day metadata. Columns are kept in the exact order the merge loop
    # below reads (r[0]..r[18]). The rollup buckets by day, so the window starts
    # at since's calendar day (a few boundary hours more inclusive than the exact
    # timestamp — negligible for a map).
    fw_sql = text("""
        WITH top AS (
            SELECT threat_ip, lat, lon, sum(cnt) AS c
            FROM fw_map_daily
            WHERE day >= :since_day
            GROUP BY threat_ip, lat, lon
            ORDER BY c DESC
            LIMIT 500
        ),
        merged AS (
            SELECT d.threat_ip, d.lat, d.lon,
                   max(d.country) AS country, max(d.city) AS city,
                   sum(d.cnt) AS cnt, max(d.max_severity) AS max_severity,
                   min(d.first_seen) AS first_seen, max(d.last_seen) AS last_seen,
                   max(d.asn) AS asn, max(d.org) AS org,
                   array_cat_agg(d.threats) AS threats,
                   array_cat_agg(d.actions) AS actions,
                   array_cat_agg(d.log_types) AS log_types,
                   array_cat_agg(d.dest_ports) AS dest_ports,
                   array_cat_agg(d.users) AS users,
                   array_cat_agg(d.firewalls) AS firewalls,
                   bool_or(d.has_inbound) AS has_inbound,
                   bool_or(d.has_outbound) AS has_outbound
            FROM fw_map_daily d
            JOIN top USING (threat_ip, lat, lon)
            WHERE d.day >= :since_day
            GROUP BY d.threat_ip, d.lat, d.lon
        )
        SELECT threat_ip, lat, lon, country, city, cnt, max_severity,
               first_seen, last_seen, asn, org,
               (SELECT array_agg(DISTINCT e) FROM unnest(threats) e)    AS threats,
               (SELECT array_agg(DISTINCT e) FROM unnest(actions) e)    AS actions,
               (SELECT array_agg(DISTINCT e) FROM unnest(log_types) e)  AS log_types,
               (SELECT array_agg(DISTINCT e) FROM unnest(dest_ports) e) AS dest_ports,
               (SELECT array_agg(DISTINCT e) FROM unnest(users) e)      AS users,
               (SELECT array_agg(DISTINCT e) FROM unnest(firewalls) e)  AS firewalls,
               has_inbound, has_outbound
        FROM merged
        ORDER BY cnt DESC
    """)
    fw_rows = (await db.execute(fw_sql, {"since_day": since.date()})).all()

    firewalls = await db.execute(select(FirewallLocation))

    def _direction(has_in, has_out):
        if has_in and has_out:
            return "mixed"
        if has_in:
            return "inbound"
        if has_out:
            return "outbound"
        return "unknown"

    # Merge attackers from both sources
    attacker_map: dict[tuple, dict] = {}
    for r in alert_rows:
        ip, lat, lon, country, city = r[0], r[1], r[2], r[3], r[4]
        key = (ip, lat, lon)
        has_in, has_out = bool(r[12]), bool(r[13])
        attacker_map[key] = {
            "ip": ip, "lat": lat, "lon": lon,
            "country": country, "city": city,
            "count": int(r[5]), "severity": r[6],
            "first_seen": _iso(r[7]), "last_seen": _iso(r[8]),
            "alert_types": _cap(r[9]),
            "categories": _cap(r[10]),
            "dest_ips": _cap(r[11], 5),
            "threats": [], "actions": [], "log_types": [],
            "dest_ports": [], "users": [], "firewalls": [],
            "asn": None, "org": None,
            "source": "central",
            "_has_inbound": has_in, "_has_outbound": has_out,
        }
    for r in fw_rows:
        ip, lat, lon, country, city = r[0], r[1], r[2], r[3], r[4]
        key = (ip, lat, lon)
        cnt = int(r[5])
        threats = _cap(r[11]); actions = _cap(r[12]); log_types = _cap(r[13])
        dest_ports = _cap(r[14], 10); users = _cap(r[15]); fws = _cap(r[16])
        has_in, has_out = bool(r[17]), bool(r[18])
        if key in attacker_map:
            entry = attacker_map[key]
            entry["count"] += cnt
            entry["source"] = "both"
            if r[7] and (not entry["first_seen"] or _iso(r[7]) < entry["first_seen"]):
                entry["first_seen"] = _iso(r[7])
            if r[8] and (not entry["last_seen"] or _iso(r[8]) > entry["last_seen"]):
                entry["last_seen"] = _iso(r[8])
            entry["asn"] = entry["asn"] or r[9]
            entry["org"] = entry["org"] or r[10]
            entry["threats"] = threats
            entry["actions"] = actions
            entry["log_types"] = log_types
            entry["dest_ports"] = dest_ports
            entry["users"] = users
            entry["firewalls"] = fws
            entry["_has_inbound"] = entry["_has_inbound"] or has_in
            entry["_has_outbound"] = entry["_has_outbound"] or has_out
        else:
            attacker_map[key] = {
                "ip": ip, "lat": lat, "lon": lon,
                "country": country, "city": city,
                "count": cnt, "severity": r[6],
                "first_seen": _iso(r[7]), "last_seen": _iso(r[8]),
                "asn": r[9], "org": r[10],
                "threats": threats, "actions": actions, "log_types": log_types,
                "dest_ports": dest_ports, "users": users, "firewalls": fws,
                "alert_types": [], "categories": [], "dest_ips": [],
                "source": "firewall",
                "_has_inbound": has_in, "_has_outbound": has_out,
            }
    for entry in attacker_map.values():
        entry["direction"] = _direction(entry.pop("_has_inbound"), entry.pop("_has_outbound"))

    sorted_attackers = sorted(attacker_map.values(), key=lambda x: -x["count"])[:500]

    # Microsoft 365 logins — own source, grouped per IP and split into
    # successful vs failed so the maps can render them as separate categories
    # (m365_ok / m365_fail). Auth attempts against the tenant are inbound.
    o365_sql = text("""
        SELECT client_ip, attacker_lat, attacker_lon,
               attacker_country, attacker_city,
               (operation = 'UserLoginFailed') AS failed,
               COUNT(*) AS cnt,
               MIN(created_at) AS first_seen,
               MAX(created_at) AS last_seen,
               array_agg(DISTINCT user_id) FILTER (WHERE user_id IS NOT NULL) AS users
        FROM o365_audit_logs
        WHERE created_at >= :since
          AND attacker_lat IS NOT NULL
          AND attacker_lon IS NOT NULL
        GROUP BY client_ip, attacker_lat, attacker_lon,
                 attacker_country, attacker_city, failed
        ORDER BY cnt DESC
        LIMIT 500
    """)
    for r in (await db.execute(o365_sql, {"since": since})).all():
        failed = bool(r[5])
        sorted_attackers.append({
            "ip": r[0], "lat": r[1], "lon": r[2],
            "country": r[3], "city": r[4],
            "count": int(r[6]), "severity": "medium" if failed else "low",
            "first_seen": _iso(r[7]), "last_seen": _iso(r[8]),
            "alert_types": ["O365LoginFailed" if failed else "O365LoginOK"],
            "categories": ["m365_fail" if failed else "m365_ok"],
            "dest_ips": [], "threats": [], "actions": [], "log_types": [],
            "dest_ports": [], "users": _cap(r[9]), "firewalls": [],
            "asn": None, "org": None,
            "source": "o365",
            "direction": "inbound",
        })

    # Annotate each attacker with current block status
    ips = {a["ip"] for a in sorted_attackers if a["ip"]}
    blocked: dict[str, BlockedIp] = {}
    if ips:
        bres = await db.execute(select(BlockedIp).where(BlockedIp.ip.in_(ips)))
        blocked = {b.ip: b for b in bres.scalars().all()}
    for a in sorted_attackers:
        b = blocked.get(a["ip"])
        a["blocked"] = b is not None
        a["blocked_at"] = _iso(b.blocked_at) if b else None

    return {
        "attackers": sorted_attackers,
        "firewalls": [
            {
                "id": fw.id,
                "name": fw.name,
                "ip": fw.ip,
                "lat": fw.lat,
                "lon": fw.lon,
                "country": fw.country,
                "city": fw.city,
            }
            for fw in firewalls.scalars().all()
        ],
    }


# --- Microsoft 365 Logins ---

@app.get("/api/o365/logins")
@cached(ttl=60)
async def get_o365_logins(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=200, ge=1, le=1000),
    status: str = Query(default="all", pattern="^(all|failed|success)$"),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)

    q = select(O365AuditLog).where(O365AuditLog.created_at >= since)
    if status == "failed":
        q = q.where(O365AuditLog.operation == "UserLoginFailed")
    elif status == "success":
        q = q.where(O365AuditLog.operation == "UserLoggedIn")
    rows = (
        (await db.execute(q.order_by(O365AuditLog.created_at.desc()).limit(limit)))
        .scalars()
        .all()
    )

    base = select(O365AuditLog).where(O365AuditLog.created_at >= since).subquery()
    stats_row = (
        await db.execute(
            select(
                func.count(),
                func.count().filter(base.c.operation == "UserLoginFailed"),
                func.count(func.distinct(base.c.user_id)),
                func.count(func.distinct(base.c.client_ip)),
            ).select_from(base)
        )
    ).one()

    top_fail_sql = text("""
        SELECT user_id, COUNT(*) AS cnt
        FROM o365_audit_logs
        WHERE created_at >= :since AND operation = 'UserLoginFailed' AND user_id IS NOT NULL
        GROUP BY user_id ORDER BY cnt DESC LIMIT 10
    """)
    top_failed_users = (await db.execute(top_fail_sql, {"since": since})).all()

    top_country_sql = text("""
        SELECT attacker_country, COUNT(*) AS cnt
        FROM o365_audit_logs
        WHERE created_at >= :since AND attacker_country IS NOT NULL
        GROUP BY attacker_country ORDER BY cnt DESC LIMIT 10
    """)
    top_countries = (await db.execute(top_country_sql, {"since": since})).all()

    # Annotate whitelist status so the UI can hide the block action up front
    # (the block endpoint refuses whitelisted IPs anyway — this is UX).
    ips = {r.client_ip for r in rows if r.client_ip}
    whitelisted: set[str] = set()
    if ips:
        wl_rows = await db.execute(select(WhitelistedIp.ip).where(WhitelistedIp.ip.in_(ips)))
        whitelisted = {w for (w,) in wl_rows.all()}

    def _iso(dt):
        return dt.isoformat() if dt else None

    def _device(raw):
        """Pull device info out of the audit record's DeviceProperties array."""
        props = {p.get("Name"): p.get("Value") for p in (raw or {}).get("DeviceProperties", []) if isinstance(p, dict)}
        if not props:
            return None
        return {
            "name": props.get("DisplayName"),
            "os": props.get("OS"),
            "browser": props.get("BrowserType") if props.get("BrowserType") not in (None, "Other") else None,
            "compliant": {"true": True, "false": False}.get((props.get("IsCompliant") or "").lower()),
            "managed": {"true": True, "false": False}.get((props.get("IsCompliantAndManaged") or "").lower()),
        }

    return {
        "items": [
            {
                "id": r.id,
                "operation": r.operation,
                "user_id": r.user_id,
                "client_ip": r.client_ip,
                "whitelisted": r.client_ip in whitelisted,
                "application_id": r.application_id,
                "application": app_display_name(r.application_id),
                "device": _device(r.raw_data),
                "result_status": r.result_status,
                "logon_error": r.logon_error,
                "user_agent": r.user_agent,
                "country": r.attacker_country,
                "city": r.attacker_city,
                "created_at": _iso(r.created_at),
            }
            for r in rows
        ],
        "stats": {
            "total": int(stats_row[0]),
            "failed": int(stats_row[1]),
            "unique_users": int(stats_row[2]),
            "unique_ips": int(stats_row[3]),
            "top_failed_users": [{"user": r[0], "count": int(r[1])} for r in top_failed_users],
            "top_countries": [{"country": r[0], "count": int(r[1])} for r in top_countries],
        },
        "configured": o365_client.configured,
    }


# --- M365 login watch (new device / new location alerts + session revoke) ---

@app.get("/api/o365/login-profiles")
async def get_m365_login_profiles(db: AsyncSession = Depends(get_db)):
    """Per-user baseline of known devices/locations plus the recent
    new-device/location alerts (agent decisions, source_type='m365_login')."""
    profiles = (await db.execute(
        select(M365LoginProfile).order_by(M365LoginProfile.user_id, M365LoginProfile.kind,
                                          M365LoginProfile.last_seen.desc())
    )).scalars().all()

    users: dict[str, dict] = {}
    for p in profiles:
        u = users.setdefault(p.user_id, {"user": p.user_id, "devices": [], "locations": []})
        entry = {
            "value": p.value, "label": p.label,
            "first_seen": p.first_seen.isoformat() if p.first_seen else None,
            "last_seen": p.last_seen.isoformat() if p.last_seen else None,
            "seen_count": int(p.seen_count or 0),
        }
        (u["devices"] if p.kind == "device" else u["locations"]).append(entry)

    decisions = (await db.execute(
        select(AgentDecision)
        .where(AgentDecision.source_type == "m365_login")
        .order_by(AgentDecision.created_at.desc())
        .limit(100)
    )).scalars().all()

    return {
        "enabled": settings.m365_login_watch_enabled,
        "seeded": bool(profiles),
        "users": sorted(users.values(), key=lambda u: u["user"]),
        "alerts": [
            {
                "id": d.id,
                "user": (d.action_args or {}).get("target_user"),
                "ip": d.source_ip,
                "status": d.status,
                "reasoning": d.reasoning,
                "context": (d.action_args or {}).get("context") or {},
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "error": d.error,
            }
            for d in decisions
        ],
    }


class RevokeSessionsIn(BaseModel):
    user: str = Field(..., min_length=3, max_length=255)


@app.post("/api/o365/revoke-sessions")
async def o365_revoke_sessions(body: RevokeSessionsIn):
    """Operator-initiated: revoke ALL sessions of a user immediately (Graph
    revokeSignInSessions). The UI confirms before calling."""
    from app.entra_client import entra_client
    try:
        result = await entra_client.revoke_sign_in_sessions(body.user.strip())
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e)[:300])
    return result


@app.post("/api/o365/login-watch/run-now")
async def m365_login_watch_run_now():
    """Run one watch pass immediately (synchronous — also used to seed the
    baseline on first setup). Runs even while the watch is disabled."""
    from app.m365_watch import m365_login_watch
    return await m365_login_watch(force=True)


# --- Internal hostname resolution ---

class HostnamesIn(BaseModel):
    ips: list[str] = Field(..., min_length=1, max_length=1000)


@app.post("/api/hostnames")
async def resolve_hostnames(body: HostnamesIn):
    """Bulk resolve hostnames for internal IPs. Returns everything already known
    (Sophos inventory + cache) immediately and queues the rest for background
    resolution (reverse DNS / NetBIOS) — poll again to pick those up. Only
    internal/private IPs are considered."""
    from app.hostname_service import lookup_cached, queue_for_resolution, is_internal
    ips = [ip for ip in (body.ips or []) if isinstance(ip, str)]
    known = await lookup_cached(ips)
    # Queue the internal IPs we couldn't answer from cache/inventory.
    misses = [ip for ip in ips if is_internal(ip) and ip not in known]
    if misses:
        await queue_for_resolution(misses)
    return {"hostnames": known, "pending": misses}


# Private-IPv4 SQL guard (regex first so the ::inet cast only sees IPv4 literals).
_PRIV_SQL = (
    "{c} ~ '^[0-9.]+$' AND ({c}::inet << inet '10.0.0.0/8' "
    "OR {c}::inet << inet '172.16.0.0/12' OR {c}::inet << inet '192.168.0.0/16')"
)


@cached(ttl=120)
async def _internal_netflow_agg(days: int) -> list[dict]:
    """Distinct internal IPs seen in NetFlow (both directions) over the window,
    with last/first activity and traffic totals. Heavy (multi-million-row scan)
    so it is cached; the hostname join happens live on top."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    sql = text(f"""
        SELECT ip, MAX(last_seen) AS last_seen, MIN(first_seen) AS first_seen,
               SUM(bytes) AS bytes, SUM(flows) AS flows
        FROM (
            SELECT src_ip AS ip, MAX(bucket_start) AS last_seen, MIN(bucket_start) AS first_seen,
                   SUM(bytes) AS bytes, SUM(flows) AS flows
            FROM netflow_buckets
            WHERE bucket_start >= :since AND {_PRIV_SQL.format(c='src_ip')}
            GROUP BY src_ip
            UNION ALL
            SELECT dst_ip AS ip, MAX(bucket_start), MIN(bucket_start), SUM(bytes), SUM(flows)
            FROM netflow_buckets
            WHERE bucket_start >= :since AND {_PRIV_SQL.format(c='dst_ip')}
            GROUP BY dst_ip
        ) t
        GROUP BY ip
        ORDER BY MAX(last_seen) DESC
        LIMIT 3000
    """)
    async with async_session() as db:
        rows = (await db.execute(sql, {"since": since})).all()
    return [
        {"ip": r[0],
         "last_seen": r[1].isoformat() if r[1] else None,
         "first_seen": r[2].isoformat() if r[2] else None,
         "bytes": int(r[3] or 0), "flows": int(r[4] or 0)}
        for r in rows
    ]


@app.get("/api/hosts/internal")
async def list_internal_hosts(
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Auto-fed inventory of internal hosts: every private IP seen in NetFlow
    (plus managed Sophos endpoints), enriched with its resolved hostname
    (Sophos / DNS / NetBIOS / manual). Unresolved IPs are queued for background
    resolution — poll again to pick up names as they arrive."""
    from app.hostname_service import lookup_cached, queue_for_resolution, is_internal

    agg = await _internal_netflow_agg(days)
    by_ip: dict[str, dict] = {a["ip"]: dict(a) for a in agg if is_internal(a["ip"])}

    # Fold in managed endpoints so known devices show even without recent NetFlow.
    ep_rows = (await db.execute(
        select(Endpoint.ipv4, Endpoint.hostname, Endpoint.endpoint_type,
               Endpoint.os_name, Endpoint.last_seen_at)
        .where(Endpoint.ipv4.isnot(None))
    )).all()
    ep_meta: dict[str, dict] = {}
    for ipv4, hn, etype, osn, seen in ep_rows:
        if not ipv4 or not is_internal(ipv4):
            continue
        ep_meta[ipv4] = {"os": osn, "device_type": etype}
        by_ip.setdefault(ipv4, {"ip": ipv4, "last_seen": None, "first_seen": None,
                                "bytes": 0, "flows": 0})

    ips = list(by_ip.keys())
    names = await lookup_cached(ips)
    misses = [ip for ip in ips if ip not in names]
    if misses:
        await queue_for_resolution(misses)

    items = []
    for ip, base in by_ip.items():
        nm = names.get(ip) or {}
        meta = ep_meta.get(ip) or {}
        items.append({
            **base,
            "hostname": nm.get("hostname"),
            "source": nm.get("source"),
            "mac": nm.get("mac"),
            "os": meta.get("os"),
            "device_type": meta.get("device_type"),
        })
    # Named first, then by recent activity.
    items.sort(key=lambda x: (x["hostname"] is not None, x["last_seen"] or ""), reverse=True)
    return {"items": items, "resolving": len(misses), "window_days": days}


class HostnameSetIn(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)
    hostname: str | None = Field(None, max_length=255)


@app.post("/api/hosts/internal/hostname")
async def set_internal_hostname(body: HostnameSetIn):
    """Operator override: name an internal IP manually (empty hostname clears it
    so automatic resolution takes over again). Manual names are never overwritten
    by the auto-resolver."""
    from app.hostname_service import set_manual
    try:
        return await set_manual(body.ip.strip(), body.hostname)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/hosts/internal/resolve")
async def resolve_internal_hosts_now(
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Re-resolve the hostnames of every internal host now (the 'reconcile names'
    button). Re-runs DNS / NetBIOS / Sophos-inventory / DHCP-lease resolution for
    all internal IPs in the inventory, refreshing even already-named ones —
    operator-set (manual) names are still preserved."""
    import asyncio
    from app.hostname_service import _resolve_one, _upsert, is_internal, get_dhcp_map

    # Pull a fresh DHCP map from the firewall so new leases are picked up now.
    if settings.firewall_api_enabled:
        try:
            await get_dhcp_map(force=True)
        except Exception:
            pass

    agg = await _internal_netflow_agg(days)
    ips = {a["ip"] for a in agg if is_internal(a["ip"])}
    ep = (await db.execute(select(Endpoint.ipv4).where(Endpoint.ipv4.isnot(None)))).scalars().all()
    ips |= {i for i in ep if i and is_internal(i)}
    ips = sorted(ips)[:1000]   # bound the work per click

    sem = asyncio.Semaphore(16)

    async def _do(ip):
        async with sem:
            try:
                hn, src, mac = await _resolve_one(ip)
                await _upsert(ip, hn, src, mac)
                return 1 if hn else 0
            except Exception:
                return 0

    results = await asyncio.gather(*[_do(ip) for ip in ips]) if ips else []
    # Check for identity changes right after refreshing the bindings.
    try:
        from app.host_identity import scan as _hi_scan
        await _hi_scan()
    except Exception:
        pass
    return {"ok": True, "processed": len(ips), "resolved": sum(results)}


@app.get("/api/hosts/identity/events")
async def list_host_identity_events(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Recent host-identity changes (IP↔MAC↔hostname), newest first."""
    from app.models import HostIdentityEvent
    rows = (await db.execute(
        select(HostIdentityEvent).order_by(HostIdentityEvent.detected_at.desc()).limit(limit)
    )).scalars().all()
    return {"events": [
        {"id": e.id, "ip": e.ip, "mac": e.mac, "hostname": e.hostname,
         "event_type": e.event_type, "severity": e.severity, "detail": e.detail,
         "detected_at": e.detected_at.isoformat() if e.detected_at else None}
        for e in rows
    ]}


@app.post("/api/firewall/dhcp/test")
async def test_firewall_dhcp(debug: bool = Query(default=False)):
    """Test the Sophos Firewall XML API DHCP read with the saved settings.
    Returns how many IP↔hostname mappings were found + a small sample, or the
    error. ``debug=1`` also returns the firewall's raw response so the entity /
    schema can be diagnosed (it may contain credentials-adjacent config — keep it
    to troubleshooting)."""
    if not settings.firewall_api_enabled:
        return {"ok": False, "error": "firewall API is disabled (enable it in Admin)"}
    from app.sfos_client import fetch_dhcp_map, fetch_dhcp_raw, probe_entities
    raw_info = {}
    if debug:
        try:
            status, text = await fetch_dhcp_raw()
            raw_info = {"http_status": status, "raw": text[:4000],
                        "entity": settings.firewall_dhcp_entity,
                        "entities": probe_entities(text)}
        except Exception as e:
            return {"ok": False, "error": str(e)[:400]}
    try:
        m = await fetch_dhcp_map()
    except Exception as e:
        return {"ok": False, "error": str(e)[:400], **raw_info}
    sample = [{"ip": ip, "hostname": hn} for ip, hn in list(m.items())[:10]]
    return {"ok": True, "count": len(m), "sample": sample,
            "entity": settings.firewall_dhcp_entity, **raw_info}


# --- Honeypot: remote decoy pods managed by Warroom -------------------------

def _client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


# --- agent-facing (token auth, exempt from the global X-API-Key) ---

@app.post("/api/honeypot/agent/heartbeat")
async def honeypot_heartbeat(request: Request):
    from app import honeypot as hp
    body = await request.json()
    pod = await hp.authenticate(_bearer(request) or body.get("token"))
    if pod is None:
        raise HTTPException(status_code=401, detail="invalid honeypot token")
    return await hp.touch(pod.id, _client_ip(request), body.get("host_info"))


@app.post("/api/honeypot/agent/events")
async def honeypot_ingest(request: Request):
    from app import honeypot as hp
    body = await request.json()
    pod = await hp.authenticate(_bearer(request) or body.get("token"))
    if pod is None:
        raise HTTPException(status_code=401, detail="invalid honeypot token")
    # Stamp the transport source IP when the agent couldn't determine the peer.
    src = _client_ip(request)
    events = body.get("events") or []
    for e in events:
        if not e.get("source_ip"):
            e["source_ip"] = src
    stored = await hp.ingest_events(pod, events)
    return {"ok": True, "stored": stored}


@app.get("/api/honeypot/agent/download")
async def honeypot_agent_download():
    """Serve the deployable agent script so a pod can be bootstrapped with a
    single curl. No secret in the file — the token is passed at runtime."""
    from fastapi.responses import FileResponse
    import os
    path = os.path.join(os.path.dirname(__file__), "deploy", "honeypot_agent.py")
    return FileResponse(path, media_type="text/x-python", filename="honeypot_agent.py")


@app.get("/api/honeypot/agent/install")
async def honeypot_agent_install():
    """Serve the installer script that sets up the agent as a systemd service
    (install / update / uninstall). No secret in the file — WARROOM_URL + token
    are passed at runtime."""
    from fastapi.responses import FileResponse
    import os
    path = os.path.join(os.path.dirname(__file__), "deploy", "honeypot_install.sh")
    return FileResponse(path, media_type="text/x-shellscript", filename="honeypot_install.sh")


# --- management (normal auth, used by the UI) ---

class HoneypotIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    services: list[str] | None = None
    files: list[dict] | None = None


class HoneypotPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=120)
    enabled: bool | None = None
    services: list[str] | None = None
    files: list[dict] | None = None


def _pod_online(pod: Honeypot) -> bool:
    if not pod.last_seen:
        return False
    return (datetime.now(timezone.utc) - pod.last_seen) < timedelta(seconds=90)


def _deploy_snippet(request: Request, token: str, reinstall: bool = False) -> str:
    # Prefer the externally-visible host (behind nginx the backend sees localhost),
    # so the deploy command shows the URL the operator actually reaches Warroom at.
    fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    fwd_proto = request.headers.get("x-forwarded-proto")
    if fwd_host:
        base = f"{fwd_proto or 'https'}://{fwd_host}".rstrip("/")
    else:
        base = str(request.base_url).rstrip("/")
    if reinstall:
        header = (
            "# RE-DEPLOY — run on the honeypot host to (re)install this pod with the new\n"
            "# token. Safe to re-run where it's already installed: the 'install' command\n"
            "# overwrites the token and restarts the service. The old token is now invalid.\n"
        )
    else:
        header = "# Install as a service (recommended) — on the remote Linux honeypot host:\n"
    return (
        header +
        f"curl -fsSL {base}/api/honeypot/agent/install -o honeypot_install.sh\n"
        f"sudo WARROOM_URL={base} HONEYPOT_TOKEN={token} bash honeypot_install.sh install\n"
        f"# later:  sudo bash honeypot_install.sh update   |   sudo bash honeypot_install.sh uninstall\n"
        f"# Self-signed reverse proxy? append --pin auto (pins the cert — secure, no valid CA needed)\n"
        f"#\n"
        f"# Or run once in the foreground instead:\n"
        f"# curl -fsSL {base}/api/honeypot/agent/download -o honeypot_agent.py\n"
        f"# sudo WARROOM_URL={base} HONEYPOT_TOKEN={token} python3 honeypot_agent.py"
    )


@app.get("/api/honeypot/pods")
async def list_honeypots(request: Request, db: AsyncSession = Depends(get_db)):
    from app import honeypot as hp
    pods = (await db.execute(select(Honeypot).order_by(Honeypot.created_at.desc()))).scalars().all()
    # Recent event counts per pod (last 24h).
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    counts = {r[0]: r[1] for r in (await db.execute(text(
        "SELECT honeypot_id, COUNT(*) FROM honeypot_events WHERE created_at >= :s GROUP BY honeypot_id"
    ), {"s": since})).all()}
    return {
        "services": hp.SERVICES,
        "file_templates": hp.FILE_TEMPLATES,
        "items": [
            {
                "id": p.id, "name": p.name, "enabled": bool(p.enabled),
                "online": _pod_online(p),
                "services": hp.normalize_services(p.services),
                "files": hp.normalize_files(p.files),
                "host_ip": p.host_ip, "host_info": p.host_info,
                "last_seen": p.last_seen.isoformat() if p.last_seen else None,
                "events_24h": int(counts.get(p.id, 0)),
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in pods
        ],
    }


@app.post("/api/honeypot/pods")
async def create_honeypot(body: HoneypotIn, request: Request, db: AsyncSession = Depends(get_db)):
    from app import honeypot as hp
    token, token_hash = hp.new_token()
    svc = hp.normalize_services(body.services if body.services is not None else hp.DEFAULT_SERVICES)
    pod = Honeypot(id=str(uuid.uuid4()), name=body.name.strip(), token_hash=token_hash,
                   enabled=True, services=svc, files=hp.normalize_files(body.files or []))
    db.add(pod)
    await db.commit()
    # The clear token is returned exactly once.
    return {"id": pod.id, "name": pod.name, "token": token,
            "deploy": _deploy_snippet(request, token)}


@app.patch("/api/honeypot/pods/{pod_id}")
async def update_honeypot(pod_id: str, body: HoneypotPatch, db: AsyncSession = Depends(get_db)):
    from app import honeypot as hp
    pod = await db.get(Honeypot, pod_id)
    if pod is None:
        raise HTTPException(status_code=404, detail="honeypot not found")
    if body.name is not None:
        pod.name = body.name.strip()
    if body.enabled is not None:
        pod.enabled = body.enabled
    if body.services is not None:
        pod.services = hp.normalize_services(body.services)
    if body.files is not None:
        pod.files = hp.normalize_files(body.files)
    await db.commit()
    return {"ok": True}


@app.post("/api/honeypot/pods/{pod_id}/redeploy")
async def redeploy_honeypot(pod_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Rotate the pod's token and return a fresh deploy command, so an existing
    pod can be re-deployed (rebuilt/new host, lost token/command). The previous
    token stops working immediately — re-run the command on the host."""
    from app import honeypot as hp
    pod = await db.get(Honeypot, pod_id)
    if pod is None:
        raise HTTPException(status_code=404, detail="honeypot not found")
    token, token_hash = hp.new_token()
    pod.token_hash = token_hash
    await db.commit()
    return {"id": pod.id, "name": pod.name, "token": token,
            "deploy": _deploy_snippet(request, token, reinstall=True)}


@app.delete("/api/honeypot/pods/{pod_id}")
async def delete_honeypot(pod_id: str, db: AsyncSession = Depends(get_db)):
    pod = await db.get(Honeypot, pod_id)
    if pod is None:
        raise HTTPException(status_code=404, detail="honeypot not found")
    await db.delete(pod)
    await db.execute(text("DELETE FROM honeypot_events WHERE honeypot_id = :id"), {"id": pod_id})
    await db.commit()
    return {"ok": True}


@app.get("/api/honeypot/sources")
async def list_honeypot_sources(
    limit: int = Query(default=500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
):
    """Honeypot accesses grouped by source IP — the collapsed alert list. Each
    row expands (via /api/honeypot/events?source_ip=…) to its connections."""
    rows = (await db.execute(text("""
        SELECT e.source_ip,
               COUNT(*)                                              AS hits,
               MIN(e.created_at)                                     AS first_seen,
               MAX(e.created_at)                                     AS last_seen,
               array_agg(DISTINCT e.service) FILTER (WHERE e.service IS NOT NULL) AS services,
               array_agg(DISTINCT e.honeypot_id)                     AS pods,
               MAX(e.attacker_country)                               AS country,
               MAX(e.attacker_city)                                  AS city,
               MAX(e.attacker_org)                                   AS org,
               COUNT(*) FILTER (WHERE e.event_type = 'login')        AS logins,
               MAX(a.acknowledged_at)                                AS acked_at
        FROM honeypot_events e
        LEFT JOIN honeypot_acks a ON a.source_ip = e.source_ip
        WHERE e.source_ip IS NOT NULL
        GROUP BY e.source_ip
        ORDER BY MAX(e.created_at) DESC
        LIMIT :lim
    """), {"lim": limit})).all()
    pod_names = {p.id: p.name for p in (await db.execute(select(Honeypot))).scalars().all()}
    sources = []
    for r in rows:
        last_seen, acked_at = r[3], r[10]
        # Acknowledged only while the ack is at/after the newest event — later
        # activity from the same IP re-opens the alert.
        acknowledged = acked_at is not None and last_seen is not None and acked_at >= last_seen
        sources.append({
            "source_ip": r[0], "hits": int(r[1]),
            "first_seen": r[2].isoformat() if r[2] else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "services": list(r[4] or []),
            "pods": [pod_names.get(pid, pid) for pid in (r[5] or [])],
            "country": r[6], "city": r[7], "org": r[8],
            "logins": int(r[9] or 0),
            "acknowledged": acknowledged,
            "acknowledged_at": acked_at.isoformat() if acked_at else None,
        })
    return {"sources": sources}


@app.post("/api/honeypot/sources/{source_ip}/ack")
async def ack_honeypot_source(source_ip: str, db: AsyncSession = Depends(get_db)):
    """Acknowledge all current honeypot alerts from one source IP. Upserts an ack
    timestamp; the source re-surfaces if it hits a decoy again afterwards."""
    import ipaddress
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    await db.execute(text("""
        INSERT INTO honeypot_acks (source_ip, acknowledged_at, acknowledged_by)
        VALUES (:ip, NOW(), 'human')
        ON CONFLICT (source_ip)
        DO UPDATE SET acknowledged_at = NOW(), acknowledged_by = 'human'
    """), {"ip": source_ip})
    await db.commit()
    return {"ok": True, "source_ip": source_ip}


@app.delete("/api/honeypot/sources/{source_ip}/ack")
async def unack_honeypot_source(source_ip: str, db: AsyncSession = Depends(get_db)):
    """Remove the acknowledgement for one source IP (re-open the alert)."""
    await db.execute(text("DELETE FROM honeypot_acks WHERE source_ip = :ip"), {"ip": source_ip})
    await db.commit()
    return {"ok": True, "source_ip": source_ip}


@app.post("/api/honeypot/sources/ack-all")
async def ack_all_honeypot_sources(db: AsyncSession = Depends(get_db)):
    """Acknowledge every source IP that currently has honeypot events."""
    res = await db.execute(text("""
        INSERT INTO honeypot_acks (source_ip, acknowledged_at, acknowledged_by)
        SELECT DISTINCT source_ip, NOW(), 'human'
        FROM honeypot_events WHERE source_ip IS NOT NULL
        ON CONFLICT (source_ip)
        DO UPDATE SET acknowledged_at = NOW(), acknowledged_by = 'human'
    """))
    await db.commit()
    return {"ok": True, "acknowledged": res.rowcount}


@app.get("/api/honeypot/events")
async def list_honeypot_events(
    limit: int = Query(default=200, ge=1, le=1000),
    honeypot_id: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    q = select(HoneypotEvent).order_by(HoneypotEvent.created_at.desc())
    if honeypot_id:
        q = q.where(HoneypotEvent.honeypot_id == honeypot_id)
    if source_ip:
        q = q.where(HoneypotEvent.source_ip == source_ip)
    rows = (await db.execute(q.limit(limit))).scalars().all()
    names = {p.id: p.name for p in (await db.execute(select(Honeypot))).scalars().all()}
    return {"events": [
        {
            "id": e.id, "honeypot_id": e.honeypot_id, "honeypot": names.get(e.honeypot_id),
            "service": e.service, "event_type": e.event_type,
            "source_ip": e.source_ip, "source_port": e.source_port, "dest_port": e.dest_port,
            "payload": e.payload,
            "country": e.attacker_country, "city": e.attacker_city, "org": e.attacker_org,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in rows
    ]}


# --- Shodan host intelligence (ports + CVEs) ---

@app.get("/api/shodan/hosts")
@cached(ttl=60)
async def get_shodan_hosts(
    days: int = Query(default=90, ge=1, le=365),
    only_vulns: bool = Query(default=False),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
):
    """Geolocated Shodan hosts harvested via OSINT lookups, for the map layers."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = (
        select(ShodanHost)
        .where(ShodanHost.last_seen >= since, ShodanHost.lat.isnot(None), ShodanHost.lon.isnot(None))
        .order_by(ShodanHost.last_seen.desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()

    def _iso(dt):
        return dt.isoformat() if dt else None

    items = []
    for r in rows:
        vulns = r.vulns or []
        ports = r.ports or []
        if only_vulns and not vulns:
            continue
        items.append({
            "ip": r.ip, "lat": r.lat, "lon": r.lon,
            "country": r.country, "city": r.city, "org": r.org, "asn": r.asn, "os": r.os,
            "ports": ports, "port_count": len(ports),
            "vulns": vulns, "cve_count": len(vulns),
            "hostnames": r.hostnames or [], "tags": r.tags or [],
            "last_seen": _iso(r.last_seen), "shodan_last_update": r.shodan_last_update,
        })
    total_cves = sum(i["cve_count"] for i in items)
    return {
        "hosts": items,
        "stats": {
            "hosts": len(items),
            "with_cves": sum(1 for i in items if i["cve_count"]),
            "total_cves": total_cves,
        },
    }


# --- Firewall Stats ---

@app.get("/api/stats/firewall-events")
@cached(ttl=300)
async def get_firewall_event_stats(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Alerts by firewall (managedAgent name)
    by_firewall = await db.execute(
        select(Alert.managed_agent_name, func.count(Alert.id))
        .where(Alert.created_at >= since, Alert.managed_agent_name.isnot(None))
        .group_by(Alert.managed_agent_name)
        .order_by(func.count(Alert.id).desc())
    )

    # Firewall alert types breakdown
    by_type = await db.execute(
        select(Alert.alert_type, func.count(Alert.id))
        .where(
            Alert.created_at >= since,
            Alert.alert_type.like("%Firewall%"),
        )
        .group_by(Alert.alert_type)
        .order_by(func.count(Alert.id).desc())
    )

    # SIEM events by location (firewall name)
    events_by_location = await db.execute(
        select(
            Event.raw_data["location"].astext.label("location"),
            func.count(Event.id),
        )
        .where(Event.created_at >= since)
        .group_by(text("1"))
        .order_by(func.count(Event.id).desc())
    )

    # SIEM events by group (SECURITY, POLICY, etc.)
    events_by_group = await db.execute(
        select(Event.group_name, func.count(Event.id))
        .where(Event.created_at >= since, Event.group_name.isnot(None))
        .group_by(Event.group_name)
        .order_by(func.count(Event.id).desc())
    )

    return {
        "by_firewall": [{"firewall": row[0], "count": row[1]} for row in by_firewall.all()],
        "by_type": [{"type": row[0], "count": row[1]} for row in by_type.all()],
        "by_location": [{"location": row[0] or "unknown", "count": row[1]} for row in events_by_location.all()],
        "by_group": [{"group": row[0] or "unknown", "count": row[1]} for row in events_by_group.all()],
    }


# --- Recent Alerts, Events & Detections ---

@app.get("/api/events/recent")
@cached(ttl=60)
async def get_recent_events(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Event)
        .order_by(Event.created_at.desc())
        .limit(limit)
    )
    events = result.scalars().all()
    def _device_type(ev):
        raw = ev.raw_data or {}
        et = raw.get("endpoint_type")
        if et:
            return et
        if ev.event_type and ev.event_type.startswith("Event::Firewall::"):
            return "firewall"
        return None

    return [
        {
            "id": e.id,
            "type": e.event_type,
            "severity": e.severity,
            "name": e.name,
            "source_ip": e.source_ip,
            "device": e.raw_data.get("location") if e.raw_data else None,
            "device_type": _device_type(e),
            "group": e.group_name,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in events
    ]


@app.get("/api/alerts/recent")
@cached(ttl=60)
async def get_recent_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    alerts = result.scalars().all()
    return [
        {
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "category": a.category,
            "description": a.description,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "agent": a.managed_agent_name,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "country": a.attacker_country,
            "city": a.attacker_city,
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
            "acknowledged_action": a.acknowledged_action,
        }
        for a in alerts
    ]


@app.get("/api/alerts/{alert_id}")
async def get_alert_detail(alert_id: str, db: AsyncSession = Depends(get_db)):
    """Full single-alert payload incl. raw_data from Sophos for the detail modal."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    a = result.scalar_one_or_none()
    if a is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return {
        "id": a.id,
        "type": a.alert_type,
        "severity": a.severity,
        "category": a.category,
        "description": a.description,
        "source_ip": a.source_ip,
        "destination_ip": a.destination_ip,
        "tenant_id": a.tenant_id,
        "agent": a.managed_agent_name,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "ingested_at": a.ingested_at.isoformat() if a.ingested_at else None,
        "country": a.attacker_country,
        "city": a.attacker_city,
        "lat": a.attacker_lat,
        "lon": a.attacker_lon,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "acknowledged_action": a.acknowledged_action,
        "raw_data": a.raw_data,
    }


_ALLOWED_ALERT_ACTIONS = {
    "acknowledge", "clearThreat", "cleanPua", "authPua",
    "sendMsgPua", "sendMsgHmpa", "clearHmpa",
}


class AlertActionIn(BaseModel):
    action: str = Field("acknowledge", min_length=1, max_length=50)
    message: str | None = Field(None, max_length=500)


@app.post("/api/alerts/{alert_id}/action")
async def perform_alert_action(
    alert_id: str,
    body: AlertActionIn,
    db: AsyncSession = Depends(get_db),
):
    if body.action not in _ALLOWED_ALERT_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"action must be one of {sorted(_ALLOWED_ALERT_ACTIONS)}",
        )

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")

    try:
        sophos_resp = await sophos_client.perform_alert_action(
            alert_id, body.action, body.message
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Sophos API rejected action: {e.response.status_code}",
        )

    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_action = body.action
    await db.commit()

    return {"ok": True, "sophos": sophos_resp}


@app.get("/api/endpoints/list")
@cached(ttl=60)
async def get_endpoints_list(
    limit: int = Query(default=200, ge=1, le=1000),
    health: str | None = Query(default=None),
    isolation: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Endpoint)
    if health:
        stmt = stmt.where(Endpoint.health_overall == health)
    if isolation:
        stmt = stmt.where(Endpoint.isolation_status == isolation)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(Endpoint.hostname.ilike(like))
    stmt = stmt.order_by(Endpoint.last_seen_at.desc().nullslast()).limit(limit)

    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": e.id,
            "hostname": e.hostname,
            "type": e.endpoint_type,
            "os": " ".join(filter(None, [e.os_name, e.os_major_version])) or None,
            "os_platform": e.os_platform,
            "ipv4": e.ipv4,
            "last_seen_at": e.last_seen_at.isoformat() if e.last_seen_at else None,
            "health": e.health_overall,
            "health_threats": e.health_threats,
            "health_services": e.health_services,
            "isolation": e.isolation_status,
            "isolation_last_enabled_at": e.isolation_last_enabled_at.isoformat() if e.isolation_last_enabled_at else None,
            "tamper_protection": e.tamper_protection_enabled,
            "online": e.online,
        }
        for e in rows
    ]


@app.get("/api/endpoints/stats")
@cached(ttl=60)
async def get_endpoints_stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count(Endpoint.id)))).scalar() or 0

    by_health = (await db.execute(
        select(Endpoint.health_overall, func.count(Endpoint.id))
        .group_by(Endpoint.health_overall)
    )).all()

    by_isolation = (await db.execute(
        select(Endpoint.isolation_status, func.count(Endpoint.id))
        .group_by(Endpoint.isolation_status)
    )).all()

    online = (await db.execute(
        select(func.count(Endpoint.id)).where(Endpoint.online.is_(True))
    )).scalar() or 0

    return {
        "total": total,
        "online": online,
        "by_health": {(k or "unknown"): v for k, v in by_health},
        "by_isolation": {(k or "unknown"): v for k, v in by_isolation},
    }


class EndpointIsolationIn(BaseModel):
    comment: str | None = Field(None, max_length=500)


@app.post("/api/endpoints/{endpoint_id}/isolate")
async def isolate_endpoint(
    endpoint_id: str,
    body: EndpointIsolationIn,
    db: AsyncSession = Depends(get_db),
):
    return await _set_endpoint_isolation(endpoint_id, True, body.comment, db)


@app.post("/api/endpoints/{endpoint_id}/restore")
async def restore_endpoint(
    endpoint_id: str,
    body: EndpointIsolationIn,
    db: AsyncSession = Depends(get_db),
):
    return await _set_endpoint_isolation(endpoint_id, False, body.comment, db)


async def _set_endpoint_isolation(
    endpoint_id: str, enabled: bool, comment: str | None, db: AsyncSession
):
    result = await db.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
    ep = result.scalar_one_or_none()
    if ep is None:
        raise HTTPException(status_code=404, detail="endpoint not found")

    try:
        sophos_resp = await sophos_client.set_isolation([endpoint_id], enabled, comment)
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Sophos rejected isolation change: {e.response.status_code}",
        )

    # Optimistic local update — full state refreshes on next collector run.
    ep.isolation_status = "isolated" if enabled else "notIsolated"
    if enabled:
        ep.isolation_last_enabled_at = datetime.now(timezone.utc)
    await db.commit()

    return {"ok": True, "enabled": enabled, "sophos": sophos_resp}


# --- Endpoint Management API proxy (/endpoint/v1) ---------------------------
# NOTE: the literal GET routes (downloads, groups) MUST be declared before the
# catch-all GET /{endpoint_id}, or FastAPI would treat "downloads" as an id.

@app.get("/api/endpoints/downloads")
async def endpoints_downloads():
    """Available installer packages + licensed products (Endpoint API
    /downloads). Returns {available, licensedProducts, installers}."""
    try:
        data = await sophos_client.get_endpoint_downloads()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API error: {e.response.status_code}")
    except Exception as e:
        logger.warning(f"endpoint downloads failed: {e}")
        return {"available": False, "error": str(e)[:200]}
    if data is None:
        return {"available": False}
    return {"available": True, **data}


@app.get("/api/endpoints/groups")
async def endpoints_groups():
    try:
        groups = await sophos_client.get_endpoint_groups()
    except Exception as e:
        logger.warning(f"endpoint groups failed: {e}")
        return {"available": False, "items": [], "error": str(e)[:200]}
    return {"available": True, "items": groups, "count": len(groups)}


# Endpoint settings collections that share the list/create/delete shape.
_EP_COLLECTIONS = {
    "allowed-items": "/endpoint/v1/settings/allowed-items",
    "blocked-items": "/endpoint/v1/settings/blocked-items",
    "exclusions":    "/endpoint/v1/settings/exclusions/scanning",
    "local-sites":   "/endpoint/v1/settings/web-control/local-sites",
}


async def _ep_list_envelope(coro_factory, label: str) -> dict:
    try:
        items = await coro_factory()
    except httpx.HTTPStatusError as e:
        return {"available": False, "items": [], "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        logger.warning(f"endpoint {label} failed: {e}")
        return {"available": False, "items": [], "error": str(e)[:200]}
    return {"available": True, "items": items, "count": len(items)}


@app.get("/api/endpoints/policies")
async def endpoint_policies():
    return await _ep_list_envelope(lambda: sophos_client.endpoint_list("/endpoint/v1/policies"), "policies")


@app.get("/api/endpoints/policies/{policy_id}")
async def endpoint_policy_detail(policy_id: str):
    try:
        p = await sophos_client.endpoint_get_raw(f"/endpoint/v1/policies/{policy_id}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API error: {e.response.status_code}")
    if p is None:
        raise HTTPException(status_code=404, detail="policy not found")
    return p


@app.get("/api/endpoints/migrations")
async def endpoint_migrations():
    return await _ep_list_envelope(lambda: sophos_client.endpoint_list("/endpoint/v1/migrations"), "migrations")


@app.get("/api/endpoints/detected-exploits")
async def endpoint_detected_exploits():
    """Exploit-mitigation detections (CryptoGuard / WipeGuard / exploit blocks)."""
    return await _ep_list_envelope(
        lambda: sophos_client.endpoint_list(
            "/endpoint/v1/settings/exploit-mitigation/detected-exploits", page_size=100
        ),
        "detected-exploits",
    )


@app.get("/api/endpoints/settings/tamper-protection")
async def endpoint_tamper_get():
    try:
        d = await sophos_client.endpoint_get_raw("/endpoint/v1/settings/tamper-protection")
    except Exception as e:
        logger.warning(f"endpoint tamper-protection failed: {e}")
        return {"available": False, "error": str(e)[:200]}
    return {"available": True, **(d or {})} if d is not None else {"available": False}


class TamperIn(BaseModel):
    enabled: bool


@app.patch("/api/endpoints/settings/tamper-protection")
async def endpoint_tamper_set(body: TamperIn):
    try:
        return await sophos_client.endpoint_patch(
            "/endpoint/v1/settings/tamper-protection", {"enabled": body.enabled}
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos rejected change: {e.response.status_code}")


@app.get("/api/endpoints/settings/{collection}")
async def endpoint_setting_list(collection: str):
    path = _EP_COLLECTIONS.get(collection)
    if not path:
        raise HTTPException(status_code=404, detail="unknown settings collection")
    # Settings collections cap pageSize lower than the 200 default → use 100
    # and let _paginate follow pages.nextKey for the rest.
    return await _ep_list_envelope(lambda: sophos_client.endpoint_list(path, page_size=100), f"settings/{collection}")


@app.post("/api/endpoints/settings/{collection}")
async def endpoint_setting_create(collection: str, body: dict = Body(...)):
    path = _EP_COLLECTIONS.get(collection)
    if not path:
        raise HTTPException(status_code=404, detail="unknown settings collection")
    if not body:
        raise HTTPException(status_code=400, detail="empty body")
    try:
        return await sophos_client.endpoint_create(path, body)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos rejected create: {e.response.status_code}")


@app.delete("/api/endpoints/settings/{collection}/{item_id}")
async def endpoint_setting_delete(collection: str, item_id: str):
    path = _EP_COLLECTIONS.get(collection)
    if not path:
        raise HTTPException(status_code=404, detail="unknown settings collection")
    try:
        return await sophos_client.endpoint_delete_path(f"{path}/{item_id}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos rejected delete: {e.response.status_code}")


class EndpointGroupIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field("computer", max_length=20)  # computer | server


@app.post("/api/endpoints/groups")
async def endpoint_group_create(body: EndpointGroupIn):
    try:
        return await sophos_client.endpoint_create(
            "/endpoint/v1/endpoint-groups", {"name": body.name, "type": body.type}
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos rejected create: {e.response.status_code}")


@app.get("/api/endpoints/groups/{group_id}")
async def endpoint_group_detail(group_id: str):
    try:
        g = await sophos_client.endpoint_get_raw(f"/endpoint/v1/endpoint-groups/{group_id}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API error: {e.response.status_code}")
    if g is None:
        raise HTTPException(status_code=404, detail="group not found")
    return g


@app.delete("/api/endpoints/groups/{group_id}")
async def endpoint_group_delete(group_id: str):
    try:
        return await sophos_client.endpoint_delete_path(f"/endpoint/v1/endpoint-groups/{group_id}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos rejected delete: {e.response.status_code}")


@app.get("/api/endpoints/{endpoint_id}")
async def endpoint_detail(endpoint_id: str):
    """Live full endpoint record from Sophos (health, services, tamper, …)."""
    try:
        ep = await sophos_client.get_endpoint(endpoint_id)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API error: {e.response.status_code}")
    if ep is None:
        raise HTTPException(status_code=404, detail="endpoint not found")
    return ep


@app.post("/api/endpoints/{endpoint_id}/scan")
async def endpoint_scan(endpoint_id: str):
    """Trigger an on-demand scan on the endpoint."""
    try:
        result = await sophos_client.scan_endpoint(endpoint_id)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos rejected scan: {e.response.status_code}")
    return {"ok": True, "sophos": result}


@app.delete("/api/endpoints/{endpoint_id}")
async def endpoint_delete(endpoint_id: str, db: AsyncSession = Depends(get_db)):
    """De-register the endpoint from Sophos Central and drop the local row."""
    try:
        result = await sophos_client.delete_endpoint(endpoint_id)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos rejected delete: {e.response.status_code}")
    row = await db.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
    ep = row.scalar_one_or_none()
    if ep is not None:
        await db.delete(ep)
        await db.commit()
    return {"ok": True, "sophos": result}


class BlockIpIn(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)
    comment: str | None = Field(None, max_length=500)


class BlockIpsIn(BaseModel):
    ips: list[str] = Field(..., min_length=1, max_length=500)
    comment: str | None = Field(None, max_length=500)


@app.get("/api/firewall/blocked-ips")
async def list_blocked_ips(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BlockedIp).order_by(BlockedIp.blocked_at.desc()))
    rows = result.scalars().all()
    return {
        "items": [
            {
                "ip": b.ip,
                "comment": b.comment,
                "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
                "monitored": bool(b.monitored),
                "blocked_by": b.blocked_by or "human",
                "source": b.source or "manual",
            }
            for b in rows
        ],
    }


async def _is_whitelisted(db: AsyncSession, ip: str) -> bool:
    """Single source of truth for the block-allowed check. Used by every path
    that writes into ``blocked_ips`` — manual UI, bulk endpoint, and the AI
    agent's execute_decision."""
    if not ip:
        return False
    res = await db.execute(select(WhitelistedIp.ip).where(WhitelistedIp.ip == ip))
    return res.first() is not None


@app.post("/api/firewall/block-ip")
async def block_ip(body: BlockIpIn, db: AsyncSession = Depends(get_db)):
    import ipaddress
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")

    if await _is_whitelisted(db, body.ip):
        raise HTTPException(status_code=409, detail=f"IP {body.ip} is whitelisted — block refused")

    existing = await db.execute(select(BlockedIp).where(BlockedIp.ip == body.ip))
    entry = existing.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if entry is None:
        entry = BlockedIp(ip=body.ip, comment=body.comment, blocked_at=now,
                          blocked_by="human", source="manual")
        db.add(entry)
    elif body.comment is not None:
        entry.comment = body.comment
    await db.commit()

    return {"ok": True, "ip": body.ip}


@app.post("/api/firewall/block-ips")
async def block_ips_bulk(body: BlockIpsIn, db: AsyncSession = Depends(get_db)):
    """Block many IPs in one go."""
    import ipaddress
    invalid: list[str] = []
    valid: list[str] = []
    for raw in body.ips:
        ip = (raw or "").strip()
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            invalid.append(ip)

    if not valid:
        raise HTTPException(status_code=400, detail="no valid IP addresses provided")

    # Drop whitelisted IPs up front so we never even consider blocking them
    wl_rows = (await db.execute(
        select(WhitelistedIp.ip).where(WhitelistedIp.ip.in_(valid))
    )).scalars().all()
    whitelisted = set(wl_rows)
    valid = [ip for ip in valid if ip not in whitelisted]

    existing_rows = (await db.execute(
        select(BlockedIp).where(BlockedIp.ip.in_(valid))
    )).scalars().all()
    existing_ips = {r.ip for r in existing_rows}

    now = datetime.now(timezone.utc)
    added: list[str] = []
    skipped: list[str] = []
    for ip in valid:
        if ip in existing_ips:
            skipped.append(ip)
            continue
        if ip in added:
            continue
        db.add(BlockedIp(ip=ip, comment=body.comment, blocked_at=now,
                         blocked_by="human", source="manual"))
        added.append(ip)
    await db.commit()

    return {
        "ok": True,
        "added": added,
        "skipped": skipped,
        "invalid": invalid,
        "whitelisted": sorted(whitelisted),
    }


@app.post("/api/firewall/unblock-ip")
async def unblock_ip(body: BlockIpIn, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(BlockedIp).where(BlockedIp.ip == body.ip))
    entry = existing.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=404, detail="IP is not in the blocklist")
    await db.delete(entry)
    await db.commit()
    return {"ok": True}


@app.get("/ioc_IP", response_class=PlainTextResponse)
async def ioc_ip_list(db: AsyncSession = Depends(get_db)):
    """Plain-text IOC feed for firewalls: one IP per line, sorted.

    The firewall must send the X-API-Key header (same auth as /api/*).
    Updates are immediate — the list is read live from the DB on every request.
    """
    # When the pull-based threat feed is disabled, serve an empty body so a
    # firewall still polling this URL clears its third-party feed.
    rows = (
        (await db.execute(select(BlockedIp.ip).order_by(BlockedIp.ip))).scalars().all()
        if settings.firewall_threat_feed_enabled else []
    )
    body = "\n".join(rows)
    if body:
        body += "\n"
    return PlainTextResponse(
        body,
        headers={
            "Content-Disposition": 'inline; filename="ioc_IP"',
            "Cache-Control": "no-store",
        },
    )


# --- Blocked Domains / URLs ---

# Accept both a bare domain and a full URL (http(s)://…/path?q=…). We normalise
# anything callers send through one entrypoint so the rest of the code only has
# to deal with lowercase host strings. Wildcards (`*.example.com`) are kept as-is.
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _normalize_domain(value: str) -> str:
    """Return a normalised host string for the domain blocklist.

    Strict — rejects anything that isn't a bare host. URLs (with scheme or
    path) go to the URL blocklist via ``_normalize_url`` instead. Port is
    stripped, host is lowercased, trailing dot dropped. Leading ``*.``
    wildcards are preserved (firewalls support that in IOC feeds).
    """
    if not value:
        raise ValueError("empty value")
    raw = value.strip()
    if not raw:
        raise ValueError("empty value")

    if "://" in raw:
        raise ValueError("looks like a URL — use the URL blocklist instead")
    if "/" in raw or "?" in raw or "#" in raw:
        raise ValueError("contains path/query — use the URL blocklist instead")
    if "@" in raw:
        raise ValueError("contains userinfo — drop the user@ prefix")

    # host[:port] — strip port if exactly one colon and the rest is digits
    if raw.count(":") == 1:
        host_part, port_part = raw.rsplit(":", 1)
        if port_part.isdigit():
            host = host_part
        else:
            host = raw
    else:
        host = raw

    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError("could not extract host")

    wildcard = False
    if host.startswith("*."):
        wildcard = True
        host = host[2:]

    if len(host) > 253:
        raise ValueError("host too long")

    labels = host.split(".")
    if len(labels) < 2:
        raise ValueError("not a fully-qualified domain")
    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            raise ValueError(f"invalid label: {label!r}")

    return ("*." + host) if wildcard else host


def _normalize_url(value: str) -> str:
    """Return a normalised URL for the URL blocklist.

    Requires a scheme (http/https). Lowercases scheme + host, strips
    trailing whitespace. Keeps path/query/fragment as-is. Use the domain
    blocklist for bare hosts.
    """
    if not value:
        raise ValueError("empty value")
    raw = value.strip()
    if not raw:
        raise ValueError("empty value")
    if "://" not in raw:
        raise ValueError("missing scheme — use the domain blocklist for bare hosts")

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme: {scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("missing host")
    if len(raw) > 2048:
        raise ValueError("url too long")

    # Reassemble: lowercase scheme + host, keep port/path/query/fragment intact.
    netloc = host
    if parsed.port is not None:
        # Drop default ports for the canonical form.
        if not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
            netloc = f"{host}:{parsed.port}"
    rest = parsed.path or ""
    if parsed.query:
        rest += "?" + parsed.query
    if parsed.fragment:
        rest += "#" + parsed.fragment
    return f"{scheme}://{netloc}{rest}"


class BlockDomainIn(BaseModel):
    domain: str = Field(..., min_length=3, max_length=2048)
    comment: str | None = Field(None, max_length=500)


class BlockDomainsIn(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=500)
    comment: str | None = Field(None, max_length=500)


@app.get("/api/firewall/blocked-domains")
async def list_blocked_domains(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BlockedDomain).order_by(BlockedDomain.blocked_at.desc()))
    rows = result.scalars().all()
    return {
        "items": [
            {
                "domain": d.domain,
                "comment": d.comment,
                "blocked_at": d.blocked_at.isoformat() if d.blocked_at else None,
            }
            for d in rows
        ],
    }


@app.post("/api/firewall/block-domain")
async def block_domain(body: BlockDomainIn, db: AsyncSession = Depends(get_db)):
    try:
        domain = _normalize_domain(body.domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid domain: {e}")

    existing = await db.execute(select(BlockedDomain).where(BlockedDomain.domain == domain))
    entry = existing.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if entry is None:
        entry = BlockedDomain(domain=domain, comment=body.comment, blocked_at=now)
        db.add(entry)
    elif body.comment is not None:
        entry.comment = body.comment
    await db.commit()

    return {"ok": True, "domain": domain}


@app.post("/api/firewall/block-domains")
async def block_domains_bulk(body: BlockDomainsIn, db: AsyncSession = Depends(get_db)):
    invalid: list[str] = []
    valid: list[str] = []
    for raw in body.domains:
        try:
            valid.append(_normalize_domain(raw))
        except ValueError:
            invalid.append(raw)

    if not valid:
        raise HTTPException(status_code=400, detail="no valid domains provided")

    existing_rows = (await db.execute(
        select(BlockedDomain).where(BlockedDomain.domain.in_(valid))
    )).scalars().all()
    existing_domains = {r.domain for r in existing_rows}

    now = datetime.now(timezone.utc)
    added: list[str] = []
    skipped: list[str] = []
    for domain in valid:
        if domain in existing_domains:
            skipped.append(domain)
            continue
        if domain in added:
            continue
        db.add(BlockedDomain(domain=domain, comment=body.comment, blocked_at=now))
        added.append(domain)
    await db.commit()

    return {
        "ok": True,
        "added": added,
        "skipped": skipped,
        "invalid": invalid,
    }


@app.post("/api/firewall/unblock-domain")
async def unblock_domain(body: BlockDomainIn, db: AsyncSession = Depends(get_db)):
    try:
        domain = _normalize_domain(body.domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid domain: {e}")

    existing = await db.execute(select(BlockedDomain).where(BlockedDomain.domain == domain))
    entry = existing.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=404, detail="domain is not in the blocklist")
    await db.delete(entry)
    await db.commit()
    return {"ok": True}


@app.get("/ioc_domain", response_class=PlainTextResponse)
async def ioc_domain_list(db: AsyncSession = Depends(get_db)):
    """Plain-text IOC feed for firewalls: one domain per line, sorted.

    Same auth as /ioc_IP — X-API-Key required. Read live from the DB on every
    request, so block/unblock takes effect immediately.
    """
    rows = (
        (await db.execute(select(BlockedDomain.domain).order_by(BlockedDomain.domain))).scalars().all()
        if settings.firewall_threat_feed_enabled else []
    )
    body = "\n".join(rows)
    if body:
        body += "\n"
    return PlainTextResponse(
        body,
        headers={
            "Content-Disposition": 'inline; filename="ioc_domain"',
            "Cache-Control": "no-store",
        },
    )


# --- Blocked URLs ---


class BlockUrlIn(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)
    comment: str | None = Field(None, max_length=500)


class BlockUrlsIn(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=500)
    comment: str | None = Field(None, max_length=500)


@app.get("/api/firewall/blocked-urls")
async def list_blocked_urls(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BlockedUrl).order_by(BlockedUrl.blocked_at.desc()))
    rows = result.scalars().all()
    return {
        "items": [
            {
                "url": u.url,
                "comment": u.comment,
                "blocked_at": u.blocked_at.isoformat() if u.blocked_at else None,
            }
            for u in rows
        ],
    }


@app.post("/api/firewall/block-url")
async def block_url(body: BlockUrlIn, db: AsyncSession = Depends(get_db)):
    try:
        url = _normalize_url(body.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid url: {e}")

    existing = await db.execute(select(BlockedUrl).where(BlockedUrl.url == url))
    entry = existing.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if entry is None:
        entry = BlockedUrl(url=url, comment=body.comment, blocked_at=now)
        db.add(entry)
    elif body.comment is not None:
        entry.comment = body.comment
    await db.commit()

    return {"ok": True, "url": url}


@app.post("/api/firewall/block-urls")
async def block_urls_bulk(body: BlockUrlsIn, db: AsyncSession = Depends(get_db)):
    invalid: list[str] = []
    valid: list[str] = []
    for raw in body.urls:
        try:
            valid.append(_normalize_url(raw))
        except ValueError:
            invalid.append(raw)

    if not valid:
        raise HTTPException(status_code=400, detail="no valid urls provided")

    existing_rows = (await db.execute(
        select(BlockedUrl).where(BlockedUrl.url.in_(valid))
    )).scalars().all()
    existing_urls = {r.url for r in existing_rows}

    now = datetime.now(timezone.utc)
    added: list[str] = []
    skipped: list[str] = []
    for url in valid:
        if url in existing_urls:
            skipped.append(url)
            continue
        if url in added:
            continue
        db.add(BlockedUrl(url=url, comment=body.comment, blocked_at=now))
        added.append(url)
    await db.commit()

    return {
        "ok": True,
        "added": added,
        "skipped": skipped,
        "invalid": invalid,
    }


@app.post("/api/firewall/unblock-url")
async def unblock_url(body: BlockUrlIn, db: AsyncSession = Depends(get_db)):
    try:
        url = _normalize_url(body.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid url: {e}")

    existing = await db.execute(select(BlockedUrl).where(BlockedUrl.url == url))
    entry = existing.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=404, detail="url is not in the blocklist")
    await db.delete(entry)
    await db.commit()
    return {"ok": True}


@app.get("/ioc_url", response_class=PlainTextResponse)
async def ioc_url_list(db: AsyncSession = Depends(get_db)):
    """Plain-text IOC feed for firewalls: one URL per line, sorted.

    Same auth as /ioc_IP — X-API-Key required. Read live from the DB on every
    request, so block/unblock takes effect immediately.
    """
    rows = (
        (await db.execute(select(BlockedUrl.url).order_by(BlockedUrl.url))).scalars().all()
        if settings.firewall_threat_feed_enabled else []
    )
    body = "\n".join(rows)
    if body:
        body += "\n"
    return PlainTextResponse(
        body,
        headers={
            "Content-Disposition": 'inline; filename="ioc_url"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/firewall/mdr-feed/sync")
async def mdr_feed_sync_now():
    """Push the current blocklists to the firewalls' MDR threat feed right now.
    Runs even when firewall_mdr_feed_enabled is off (admin-initiated test).
    Returns the per-firewall push result so the admin can verify it worked."""
    from app.firewall_feed import sync_mdr_threat_feed
    return await sync_mdr_threat_feed(force=True)


@app.post("/api/firewall/mdr-feed/verify")
async def mdr_feed_verify():
    """Poll the transactions from the most recent MDR push and report whether
    each firewall has actually applied the indicators (completed vs pending)."""
    from app.firewall_feed import verify_last_push
    return await verify_last_push()


# --- Whitelist (IPs that may never be blocked) ---


class WhitelistIn(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)
    comment: str | None = Field(None, max_length=500)


@app.get("/api/firewall/whitelist")
async def list_whitelist(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(WhitelistedIp).order_by(WhitelistedIp.source, WhitelistedIp.ip)
    )).scalars().all()
    return {"items": [
        {
            "ip": w.ip,
            "source": w.source,
            "comment": w.comment,
            "created_at": w.created_at.isoformat() if w.created_at else None,
            "last_seen_at": w.last_seen_at.isoformat() if w.last_seen_at else None,
        }
        for w in rows
    ]}


@app.post("/api/firewall/whitelist")
async def add_whitelist(body: WhitelistIn, db: AsyncSession = Depends(get_db)):
    import ipaddress
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")

    existing = await db.get(WhitelistedIp, body.ip)
    if existing is None:
        db.add(WhitelistedIp(ip=body.ip, source="manual", comment=body.comment))
    else:
        # Upgrade to manual so a refresh doesn't remove it
        existing.source = "manual"
        if body.comment is not None:
            existing.comment = body.comment
        existing.last_seen_at = datetime.now(timezone.utc)
    # If the IP is already in the blocklist, drop it — whitelist takes precedence
    bl = await db.get(BlockedIp, body.ip)
    if bl is not None:
        await db.delete(bl)
    await db.commit()
    return {"ok": True}


@app.delete("/api/firewall/whitelist/{ip}")
async def remove_whitelist(ip: str, db: AsyncSession = Depends(get_db)):
    rec = await db.get(WhitelistedIp, ip)
    if rec is None:
        raise HTTPException(status_code=404, detail="not in whitelist")
    await db.delete(rec)
    await db.commit()
    return {"ok": True}


# --- Watchlist (observe-only IPs) ---

class WatchlistIn(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)
    comment: str | None = Field(None, max_length=500)


@app.get("/api/firewall/watchlist")
async def list_watchlist(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(WatchlistIp).order_by(WatchlistIp.added_at.desc())
    )).scalars().all()
    return {"items": [
        {
            "ip": w.ip,
            "comment": w.comment,
            "monitored": bool(w.monitored),
            "added_at": w.added_at.isoformat() if w.added_at else None,
        }
        for w in rows
    ]}


@app.post("/api/firewall/watchlist")
async def add_watchlist(body: WatchlistIn, db: AsyncSession = Depends(get_db)):
    import ipaddress
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    existing = await db.get(WatchlistIp, body.ip)
    if existing is None:
        db.add(WatchlistIp(ip=body.ip, comment=body.comment))
    elif body.comment is not None:
        existing.comment = body.comment
    await db.commit()
    return {"ok": True, "ip": body.ip}


@app.delete("/api/firewall/watchlist/{ip}")
async def remove_watchlist(ip: str, db: AsyncSession = Depends(get_db)):
    rec = await db.get(WatchlistIp, ip)
    if rec is None:
        raise HTTPException(status_code=404, detail="not in watchlist")
    await db.delete(rec)
    await db.commit()
    return {"ok": True}


# --- Monitoring flag (special mark on a blocklist / watchlist IP) ---

class MonitorToggleIn(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)
    monitored: bool = True


@app.post("/api/firewall/monitor")
async def set_monitor_flag(body: MonitorToggleIn, db: AsyncSession = Depends(get_db)):
    """Flag / unflag an IP for connection monitoring. Applies to whichever list
    the IP is on (blocklist and/or watchlist)."""
    import ipaddress
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")

    touched: list[str] = []
    bl = await db.get(BlockedIp, body.ip)
    if bl is not None:
        bl.monitored = body.monitored
        touched.append("blocked")
    wl = await db.get(WatchlistIp, body.ip)
    if wl is not None:
        wl.monitored = body.monitored
        touched.append("watchlist")

    if not touched:
        raise HTTPException(status_code=404, detail="IP is not on the blocklist or watchlist")
    await db.commit()
    return {"ok": True, "ip": body.ip, "monitored": body.monitored, "lists": touched}


# --- Monitoring analysis (which hosts talk to monitored IPs, and when) ---

@app.get("/api/firewall/monitored")
async def list_monitored_ips(db: AsyncSession = Depends(get_db)):
    """Every IP flagged for monitoring (from either list) with a connection
    summary: how many internal hosts talk to it and when it was last seen."""
    lists: dict[str, set[str]] = {}
    comments: dict[str, str] = {}
    for ip, comment in (await db.execute(
        select(BlockedIp.ip, BlockedIp.comment).where(BlockedIp.monitored.is_(True))
    )).all():
        lists.setdefault(ip, set()).add("blocked")
        comments.setdefault(ip, comment)
    for ip, comment in (await db.execute(
        select(WatchlistIp.ip, WatchlistIp.comment).where(WatchlistIp.monitored.is_(True))
    )).all():
        lists.setdefault(ip, set()).add("watchlist")
        comments.setdefault(ip, comment)

    ips = list(lists.keys())
    if not ips:
        return {"items": [], "monitor_enabled": settings.ip_monitor_enabled}

    summary = {r[0]: r for r in (await db.execute(text("""
        SELECT monitored_ip, COUNT(DISTINCT host_ip) AS hosts, MAX(last_seen) AS last_seen
        FROM monitored_connections WHERE monitored_ip = ANY(:ips) GROUP BY monitored_ip
    """), {"ips": ips})).all()}
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    recent = {r[0]: r[1] for r in (await db.execute(text("""
        SELECT monitored_ip, COUNT(*) FROM monitored_events
        WHERE monitored_ip = ANY(:ips) AND detected_at >= :since GROUP BY monitored_ip
    """), {"ips": ips, "since": day_ago})).all()}
    geo = {r[0]: r[1] for r in (await db.execute(
        text("SELECT ip, country FROM geoip_cache WHERE ip = ANY(:ips)"), {"ips": ips}
    )).all()}

    items = []
    for ip in ips:
        s = summary.get(ip)
        items.append({
            "ip": ip,
            "lists": sorted(lists[ip]),
            "comment": comments.get(ip),
            "country": geo.get(ip),
            "host_count": int(s[1]) if s else 0,
            "last_activity": s[2].isoformat() if s and s[2] else None,
            "new_events_24h": int(recent.get(ip, 0)),
        })
    items.sort(key=lambda x: (x["new_events_24h"], x["host_count"]), reverse=True)
    return {"items": items, "monitor_enabled": settings.ip_monitor_enabled}


@app.get("/api/firewall/monitored/events")
async def list_monitored_events(
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        select(MonitoredEvent).order_by(MonitoredEvent.detected_at.desc()).limit(limit)
    )).scalars().all()
    return {"events": [
        {
            "id": e.id,
            "monitored_ip": e.monitored_ip,
            "host": e.host_ip,
            "direction": e.direction,
            "event_type": e.event_type,
            "port": e.dst_port,
            "protocol": _PROTO_NAMES.get(e.protocol or 0, str(e.protocol)) if e.protocol is not None else None,
            "country": e.country,
            "source_list": e.source_list,
            "detected_at": e.detected_at.isoformat() if e.detected_at else None,
            "notified": bool(e.notified),
            "notify_error": e.notify_error,
        }
        for e in rows
    ]}


@app.get("/api/firewall/monitored/{ip}/connections")
async def monitored_ip_connections(ip: str, db: AsyncSession = Depends(get_db)):
    """The internal hosts talking to one monitored IP, from the persistent
    baseline (survives NetFlow's 30-day window)."""
    rows = (await db.execute(
        select(MonitoredConnection)
        .where(MonitoredConnection.monitored_ip == ip)
        .order_by(MonitoredConnection.last_seen.desc())
    )).scalars().all()
    return {"ip": ip, "connections": [
        {
            "host": c.host_ip,
            "direction": c.direction,
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            "flows": int(c.flows or 0),
            "bytes": int(c.bytes or 0),
            "port": c.dst_port,
            "protocol": _PROTO_NAMES.get(c.protocol or 0, str(c.protocol)) if c.protocol is not None else None,
            "country": c.country,
            "notify_count": int(c.notify_count or 0),
        }
        for c in rows
    ]}


@app.post("/api/firewall/monitored/scan")
async def trigger_monitor_scan():
    """Run a monitoring scan immediately (also used by the UI refresh button)."""
    from app.ip_monitor import monitor_scan
    return await monitor_scan()


_AUTO_SOURCES = {"firewall_location", "firewall_log", "netflow", "sophos"}


@app.post("/api/firewall/whitelist/refresh")
async def refresh_whitelist(db: AsyncSession = Depends(get_db)):
    """Auto-populate the whitelist from every place the system already knows
    about firewalls. Manual entries are never touched."""
    discovered: dict[str, str] = {}  # ip -> source label

    # 1) firewall_locations (manual user entries with explicit IP)
    fl_rows = (await db.execute(
        select(FirewallLocation.ip, FirewallLocation.name).where(FirewallLocation.ip.isnot(None))
    )).all()
    for ip, name in fl_rows:
        discovered.setdefault(ip, f"firewall_location · {name}")

    # 2) firewall_logs.firewall_ip — IPs that actively send syslog to us
    fl_log = (await db.execute(
        select(FirewallLog.firewall_ip, func.max(FirewallLog.firewall_name))
        .where(FirewallLog.firewall_ip.isnot(None))
        .group_by(FirewallLog.firewall_ip)
    )).all()
    for ip, name in fl_log:
        discovered.setdefault(ip, f"firewall_log · {name or '?'}")

    # 3) netflow_buckets.firewall_ip — exporters
    nf_rows = (await db.execute(
        select(NetflowBucket.firewall_ip).where(NetflowBucket.firewall_ip.isnot(None)).distinct()
    )).scalars().all()
    for ip in nf_rows:
        discovered.setdefault(ip, "netflow · exporter")

    # 4) Sophos firewalls API (best-effort, may not be available)
    try:
        sophos_fws = await sophos_client.get_firewalls()
        for fw in sophos_fws or []:
            for key in ("ip", "externalIpv4Addresses", "internalIpv4Addresses"):
                v = fw.get(key)
                if isinstance(v, str):
                    discovered.setdefault(v, f"sophos · {fw.get('name', '?')}")
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            discovered.setdefault(item, f"sophos · {fw.get('name', '?')}")
    except Exception as e:
        logger.warning(f"whitelist refresh: sophos lookup failed: {e}")

    # Apply: keep manual entries untouched, sync auto entries
    now = datetime.now(timezone.utc)
    added: list[str] = []
    refreshed: list[str] = []
    auto_existing = (await db.execute(
        select(WhitelistedIp).where(WhitelistedIp.source != "manual")
    )).scalars().all()
    auto_by_ip = {w.ip: w for w in auto_existing}

    for ip, label in discovered.items():
        if ip in auto_by_ip:
            w = auto_by_ip[ip]
            w.source = label
            w.last_seen_at = now
            refreshed.append(ip)
        elif (await db.get(WhitelistedIp, ip)) is None:
            db.add(WhitelistedIp(ip=ip, source=label, comment="auto-discovered", created_at=now, last_seen_at=now))
            added.append(ip)
        else:
            # Already exists as manual — leave alone
            pass

    # Remove auto entries that are no longer discovered (firewall rotated IP, etc.)
    stale: list[str] = []
    for ip, w in auto_by_ip.items():
        if ip not in discovered:
            await db.delete(w)
            stale.append(ip)

    # And drop any of these IPs from blocked_ips, just in case
    all_ips = list(discovered.keys())
    if all_ips:
        bl_rows = (await db.execute(
            select(BlockedIp).where(BlockedIp.ip.in_(all_ips))
        )).scalars().all()
        for b in bl_rows:
            await db.delete(b)

    await db.commit()
    return {
        "ok": True,
        "added": added,
        "refreshed": refreshed,
        "removed_stale_auto": stale,
        "removed_from_blocklist": [b.ip for b in bl_rows] if all_ips else [],
        "total_now": len(discovered) + sum(1 for w in (await db.execute(
            select(WhitelistedIp).where(WhitelistedIp.source == "manual")
        )).scalars().all()),
    }


# --- Firewall overview (extended with interfaces + log/flow counts) ---


@app.get("/api/firewalls/extended")
@cached(ttl=120)
async def list_firewalls_extended(db: AsyncSession = Depends(get_db)):
    """One row per known firewall (grouped by name), not per IP. A firewall
    that's both manually configured AND sends syslog from a different IP
    shows up once with both IPs listed underneath.

    The per-firewall log aggregation scans the whole firewall_logs table, so the
    result is cached (120s) and relies on the covering index
    idx_fw_logs_ip_created (firewall_ip, created_at) INCLUDE (firewall_name) to
    stay an index-only scan instead of a 40GB heap scan — see
    db/migrations/003_fw_ip_index.sql."""
    locs = (await db.execute(select(FirewallLocation))).scalars().all()

    log_stats = (await db.execute(
        select(
            FirewallLog.firewall_ip,
            func.max(FirewallLog.firewall_name).label("name"),
            func.count(FirewallLog.id).label("log_count"),
            func.max(FirewallLog.created_at).label("last_log"),
        )
        .where(FirewallLog.firewall_ip.isnot(None))
        .group_by(FirewallLog.firewall_ip)
    )).all()

    iface_stats = (await db.execute(
        select(
            NetflowIfaceBucket.firewall_ip,
            func.count(func.distinct(NetflowIfaceBucket.iface_idx)).label("iface_count"),
            func.max(NetflowIfaceBucket.bucket_start).label("last_flow"),
        )
        .group_by(NetflowIfaceBucket.firewall_ip)
    )).all()

    wl_rows = (await db.execute(select(WhitelistedIp.ip))).scalars().all()
    whitelisted = set(wl_rows)

    # --- Step 1: build per-IP records (still indexed by IP) ---
    by_ip: dict[str, dict] = {}
    for loc in locs:
        if not loc.ip:
            continue
        by_ip[loc.ip] = {
            "ip": loc.ip,
            "name": loc.name,
            "location_id": loc.id,
            "sources": ["location"],
            "lat": loc.lat, "lon": loc.lon,
            "country": loc.country, "city": loc.city,
            "log_count": 0, "last_log": None,
            "iface_count": 0, "last_flow": None,
            "whitelisted": loc.ip in whitelisted,
        }

    for r in log_stats:
        ip, name, cnt, last = r
        rec = by_ip.setdefault(ip, {
            "ip": ip, "name": name, "location_id": None, "sources": [],
            "lat": None, "lon": None, "country": None, "city": None,
            "log_count": 0, "last_log": None,
            "iface_count": 0, "last_flow": None,
            "whitelisted": ip in whitelisted,
        })
        rec["log_count"] = int(cnt or 0)
        rec["last_log"] = last.isoformat() if last else None
        rec["name"] = rec.get("name") or name
        rec["sources"] = list(set((rec.get("sources") or []) + ["syslog"]))

    for r in iface_stats:
        ip, count, last = r
        rec = by_ip.setdefault(ip, {
            "ip": ip, "name": None, "location_id": None, "sources": [],
            "lat": None, "lon": None, "country": None, "city": None,
            "log_count": 0, "last_log": None,
            "whitelisted": ip in whitelisted,
        })
        rec["iface_count"] = int(count or 0)
        rec["last_flow"] = last.isoformat() if last else None
        rec["sources"] = list(set((rec.get("sources") or []) + ["netflow"]))

    # Ask the firewall itself (XML API) which IPs are its own interfaces/VLANs,
    # so every one of them collapses into a SINGLE firewall keyed by the device
    # hostname — instead of one "firewall" per interface IP. Best-effort: if the
    # API is unreachable we fall back to the previous name/IP grouping.
    device_hostname: str | None = None
    device_ip_set: set[str] = set()
    device_iface_by_ip: dict[str, dict] = {}
    try:
        from app.sfos_client import fetch_device_info, device_ips
        dev = await fetch_device_info()
        device_hostname = (dev.get("hostname") or "").strip() or None
        device_ip_set = device_ips(dev)
        for i in dev.get("interfaces", []):
            if i.get("ip"):
                device_iface_by_ip[i["ip"]] = {"name": i.get("name"), "zone": i.get("zone")}
    except Exception as e:
        logger.warning(f"extended firewalls: device info unavailable: {e}")

    # Seed EVERY interface/VLAN IP the firewall reports, so the overview lists all
    # of the firewall's IPs — not only the few that happen to appear in syslog /
    # netflow / a manual pin. IPs with no traffic just show 0 logs / 0 flows.
    for ip in device_ip_set:
        rec = by_ip.setdefault(ip, {
            "ip": ip, "name": device_hostname, "location_id": None, "sources": [],
            "lat": None, "lon": None, "country": None, "city": None,
            "log_count": 0, "last_log": None,
            "iface_count": 0, "last_flow": None,
            "whitelisted": ip in whitelisted,
        })
        rec["sources"] = list(set((rec.get("sources") or []) + ["device"]))
        info = device_iface_by_ip.get(ip) or {}
        rec["iface_name"] = info.get("name")
        rec["zone"] = info.get("zone")

    # --- Step 2: collapse per IP records into firewalls (keyed by name) ---
    grouped: dict[str, dict] = {}
    for ip, rec in by_ip.items():
        name = (rec.get("name") or "").strip()
        # Any IP that belongs to the physical firewall groups under its hostname.
        if device_hostname and ip in device_ip_set:
            name = device_hostname
        # Firewalls without a name (only seen in NetFlow) get bucketed under
        # their IP so the user can still see + name them later.
        key = name.lower() if name else f"__ip__{ip}"
        fw = grouped.setdefault(key, {
            "name": name or None,
            "ips": [],
            "location_id": None,
            "log_count": 0, "last_log": None,
            "iface_count": 0, "last_flow": None,
            "country": None, "city": None,
            "lat": None, "lon": None,
            "whitelisted_count": 0,
            "ip_count": 0,
        })
        fw["ips"].append({
            "ip": ip,
            "sources": rec.get("sources") or [],
            "whitelisted": rec["whitelisted"],
            "log_count": rec["log_count"],
            "iface_count": rec["iface_count"],
            "last_log": rec["last_log"],
            "last_flow": rec["last_flow"],
            "iface_name": rec.get("iface_name"),
            "zone": rec.get("zone"),
        })
        fw["log_count"] += rec["log_count"]
        fw["iface_count"] += rec["iface_count"]
        fw["ip_count"] += 1
        if rec["whitelisted"]:
            fw["whitelisted_count"] += 1
        if rec["last_log"] and (fw["last_log"] is None or rec["last_log"] > fw["last_log"]):
            fw["last_log"] = rec["last_log"]
        if rec["last_flow"] and (fw["last_flow"] is None or rec["last_flow"] > fw["last_flow"]):
            fw["last_flow"] = rec["last_flow"]
        # First firewall_location wins as the display location
        if rec.get("location_id") and not fw["location_id"]:
            fw["location_id"] = rec["location_id"]
            fw["country"] = rec["country"]; fw["city"] = rec["city"]
            fw["lat"] = rec["lat"]; fw["lon"] = rec["lon"]

    # Sort each firewall's IP list: WAN IPs first, then by numeric IP address.
    def _ip_octets(ip: str) -> tuple:
        try:
            return tuple(int(o) for o in str(ip).split("."))
        except Exception:
            return (999, 999, 999, 999)

    for fw in grouped.values():
        fw["ips"].sort(key=lambda x: (
            0 if (x.get("zone") or "").upper() == "WAN" else 1,
            _ip_octets(x["ip"]),
        ))

    items = sorted(grouped.values(), key=lambda r: r["log_count"] + r["iface_count"], reverse=True)
    return {"items": items}


# Selectable dimensions for the firewall-anomaly analysis. The user picks any 3;
# the Isolation Forest scores IPs in exactly that 3-D space and the dashboard
# plots those three axes. Each IP gets, per dimension, a "raw" value (the human
# number shown on the axis / hover) and an Isolation-Forest "feature" value
# (oriented so higher = more anomalous, log-scaled where the metric is
# heavy-tailed). "axis" hints the chart at a log vs linear scale.
ANOMALY_DIMENSIONS = [
    {"key": "volume",  "label": "Volumen (Bytes)",   "axis": "log"},
    {"key": "ports",   "label": "Ziel-Ports",        "axis": "linear"},
    {"key": "dst_ips", "label": "Ziel-IPs",          "axis": "linear"},
    {"key": "flows",   "label": "Flows",             "axis": "log"},
    {"key": "packets", "label": "Pakete",            "axis": "log"},
    {"key": "night",   "label": "Tageszeit (Nacht)", "axis": "linear"},
    {"key": "country", "label": "Land-Seltenheit",   "axis": "linear"},
]
_ANOMALY_DIM_KEYS = {d["key"] for d in ANOMALY_DIMENSIONS}
_ANOMALY_DEFAULT_DIMS = ["volume", "ports", "night"]


@app.get("/api/firewall/anomalies")
@cached(ttl=300)
async def firewall_anomalies(
    hours: int = Query(default=24, ge=1, le=720),
    min_flows: int = Query(default=5, ge=1, le=1000000),
    max_ips: int = Query(default=4000, ge=100, le=12000),
    limit: int = Query(default=80, ge=1, le=500),
    dims: str = Query(default="volume,ports,night",
                      description="Comma-separated keys of the 3 dimensions to "
                                  "analyse, e.g. 'volume,ports,night'. See "
                                  "ANOMALY_DIMENSIONS for valid keys."),
    ip: str | None = Query(default=None,
                           description="Optional focus IP. Drills into this IP's "
                                       "counterparts instead of the whole network."),
    role: str = Query(default="src",
                      description="'src' or 'dst'. Without ip: score all source "
                                  "(src) or all destination (dst) IPs. With ip: "
                                  "the focus IP's role — 'src' scores the "
                                  "destinations it contacts, 'dst' scores the "
                                  "sources that contact it."),
    db: AsyncSession = Depends(get_db),
):
    """Isolation Forest anomaly detection over NetFlow IPs in a **freely chosen
    3-dimensional space**, for the whole network or **focused on a single IP**.

    The caller picks any 3 of the available dimensions (``dims=`` — Volumen,
    Ziel-Ports, Ziel-/Quell-IPs, Flows, Pakete, Tageszeit, Land-Seltenheit); the
    forest scores every IP in exactly that 3-D space and the dashboard plots those
    three axes. An IP is anomalous when it is easy to isolate from the crowd —
    e.g. exfil hosts with unusual volume, scanners hitting many ports/IPs,
    off-hours activity, or sources from rare countries.

    Scope is controlled by ``ip`` + ``role``:

    * no ``ip`` → global: score **all source IPs** (``role=src``, default) or
      **all destination IPs** (``role=dst``).
    * ``ip`` set → drill into that IP's peers: ``role=src`` treats the IP as the
      source and scores the **destinations it contacts**; ``role=dst`` treats it
      as the destination and scores the **sources that contact it**.

    Built on netflow_buckets (the only source with real byte volume) with a
    geoip_cache join for country. The aggregation + CPU scoring is cached (300s,
    keyed incl. dimensions + focus) and runs off-thread."""
    import asyncio
    import math
    import ipaddress as _ipaddr
    from collections import Counter

    # Resolve the 3 chosen dimensions: keep valid, distinct, order-preserved keys;
    # fall back to the default trio if the request doesn't yield exactly three.
    selected: list[str] = []
    for k in (dims or "").split(","):
        k = k.strip()
        if k in _ANOMALY_DIM_KEYS and k not in selected:
            selected.append(k)
    if len(selected) != 3:
        selected = list(_ANOMALY_DEFAULT_DIMS)

    role = role if role in ("src", "dst") else "src"
    focus_ip = (ip or "").strip() or None
    if focus_ip:
        try:
            _ipaddr.ip_address(focus_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="ungültige IP")

    # Decide which IP column is the scored entity, which is the peer (counterpart)
    # used for the distinct-peer dimension, and which column the focus IP filters.
    # Column names come from a fixed whitelist, so they are safe to interpolate.
    if focus_ip:
        # Drill into one IP's peers: role = the focus IP's own side; the entity we
        # score is the opposite side (its counterparts), filtered to that IP.
        if role == "src":            # focus IP is source → score its destinations
            entity_col, peer_col = "dst_ip", "src_ip"
        else:                        # focus IP is destination → score its sources
            entity_col, peer_col = "src_ip", "dst_ip"
        filter_col = peer_col        # = the focus IP's own column
    else:
        entity_col = "src_ip" if role == "src" else "dst_ip"
        peer_col = "dst_ip" if role == "src" else "src_ip"
        filter_col = None

    where = ["n.bucket_start >= :since", f"n.{entity_col} IS NOT NULL"]
    params = {"since": datetime.now(timezone.utc) - timedelta(hours=hours),
              "min_flows": min_flows, "max_ips": max_ips}
    if focus_ip:
        where.append(f"n.{filter_col} = :focus_ip")
        params["focus_ip"] = focus_ip

    rows = (await db.execute(text(f"""
        SELECT n.{entity_col} AS entity,
               SUM(n.bytes)   AS bytes,
               SUM(n.flows)   AS flows,
               SUM(n.packets) AS packets,
               COUNT(DISTINCT n.dst_port)   AS dports,
               COUNT(DISTINCT n.{peer_col}) AS dips,
               SUM(CASE WHEN EXTRACT(hour FROM n.bucket_start) < 6 THEN n.flows ELSE 0 END) AS night_flows,
               MAX(n.bucket_start) AS last_seen,
               MAX(g.country) AS country
        FROM netflow_buckets n
        LEFT JOIN geoip_cache g ON g.ip = n.{entity_col}
        WHERE {" AND ".join(where)}
        GROUP BY n.{entity_col}
        HAVING SUM(n.flows) >= :min_flows
        ORDER BY SUM(n.bytes) DESC
        LIMIT :max_ips
    """), params)).all()

    # Country-rarity encoding: a source from a country that rarely appears among
    # the observed sources is easier to isolate. NULL country (internal/unknown)
    # is its own bucket so internal hosts aren't flagged just for being internal.
    counts = Counter((r[8] or "(intern)") for r in rows)
    total = max(1, len(rows))

    items = []
    for r in rows:
        entity, byts, flows, pkts, dports, dips, night_flows, last_seen, country = r
        byts = int(byts or 0)
        flows = int(flows or 0) or 1
        pkts = int(pkts or 0)
        dports = int(dports or 0)
        dips = int(dips or 0)
        share = counts[country or "(intern)"] / total
        rarity = -math.log(share)
        night_ratio = int(night_flows or 0) / flows

        # raw = the human value shown on each axis / hover; feat = the
        # Isolation-Forest input (higher = more anomalous, log-scaled for the
        # heavy-tailed count/volume metrics).
        raw = {"volume": byts, "ports": dports, "dst_ips": dips,
               "flows": flows, "packets": pkts,
               "night": round(night_ratio, 3), "country": round(rarity, 3)}
        feat = {"volume": math.log1p(byts), "ports": math.log1p(dports),
                "dst_ips": math.log1p(dips), "flows": math.log1p(flows),
                "packets": math.log1p(pkts), "night": night_ratio,
                "country": rarity}

        it = {
            "ip": entity,
            "country": country or None,
            "bytes": byts,
            "flows": flows,
            "packets": pkts,
            "distinct_dst_ports": dports,
            "distinct_dst_ips": dips,
            "night_ratio": round(night_ratio, 3),
            "country_rarity": round(rarity, 3),
            "last_seen": last_seen.isoformat() if last_seen else None,
            # Raw values for every dimension so the chart can plot any chosen 3.
            "vals": raw,
        }
        # Only the chosen dimensions feed the forest.
        for k in selected:
            it[f"f_{k}"] = feat[k]
        items.append(it)

    # Language-neutral payload: emit dimension KEYS and let the frontend
    # translate them (i18n). The peer dimension's contextual label
    # (destinations when source IPs are scored, sources otherwise) is derived
    # client-side from `focus.entity`.
    available = [{"key": d["key"], "axis": d["axis"]} for d in ANOMALY_DIMENSIONS]

    from app import anomaly
    feature_keys = [f"f_{k}" for k in selected]
    # Map feature column -> bare dimension key so `drivers[].dim` carries the
    # key (e.g. "volume"), which the frontend resolves to a localized label.
    dim_keys = {f"f_{k}": k for k in selected}

    def _score():
        res = anomaly.score_items(items, feature_keys)
        return anomaly.attribute_drivers(res, feature_keys, dim_keys)

    result = await asyncio.to_thread(_score)
    ranked = result["items"]

    # Per-point raw values for the chosen dimensions so the dashboard can render
    # the rotatable 3-D point cloud + bubble view on the selected axes.
    scatter = [{"ip": it["ip"], "vals": it["vals"], "country": it["country"],
                "score": it["score"], "anom": it["is_anomaly"]} for it in ranked]
    # Drop internal scoring helpers from the table payload.
    table = [{k: v for k, v in it.items() if not (k.startswith("f_") or k == "vals")}
             for it in ranked[:limit]]

    # Top counterpart (by volume) per displayed entity — the "Ziel-IP" column.
    # Bounded to just the shown rows, so it stays cheap; the full per-peer
    # breakdown is available on row-click via /api/ip/{ip}/connections.
    entity_ips = [it["ip"] for it in table]
    if entity_ips:
        peer_where = ["n.bucket_start >= :since", f"n.{entity_col} = ANY(:ips)"]
        peer_params = {"since": params["since"], "ips": entity_ips}
        if focus_ip:
            peer_where.append(f"n.{filter_col} = :focus_ip")
            peer_params["focus_ip"] = focus_ip
        peer_rows = (await db.execute(text(f"""
            SELECT DISTINCT ON (e) e, peer FROM (
                SELECT n.{entity_col} AS e, n.{peer_col} AS peer, SUM(n.bytes) AS b
                FROM netflow_buckets n
                WHERE {" AND ".join(peer_where)}
                GROUP BY n.{entity_col}, n.{peer_col}
            ) t
            ORDER BY e, b DESC
        """), peer_params)).all()
        top_peer = {r[0]: r[1] for r in peer_rows}
        for it in table:
            it["top_peer"] = top_peer.get(it["ip"])

    return {
        "as_of": datetime.now(timezone.utc).isoformat(),
        "window_hours": hours,
        "source": "netflow",
        "selected_dims": selected,
        "dimensions": selected,
        "available_dimensions": available,
        # Language-neutral context; the frontend builds the human description
        # via i18n from these fields (entity + scope + ip/role).
        "focus": {"ip": focus_ip, "role": role, "entity": entity_col,
                  "scope": "focus" if focus_ip else "global"},
        "params": {"min_flows": min_flows, "max_ips": max_ips,
                   "threshold": result["threshold"]},
        "analyzed": result["analyzed"],
        "anomaly_count": result["anomaly_count"],
        "anomalies": table,
        "scatter": scatter,
    }


@app.get("/api/firewall/connection-anomalies")
@cached(ttl=300)
async def firewall_connection_anomalies(
    hours: int = Query(default=24, ge=1, le=168),
    min_flows: int = Query(default=5, ge=1, le=100000),
    min_score: float = Query(default=0.5, ge=0.0, le=1.0),
    kind: str = Query(default="", description="Filter: 'c2', 'exfil', 'new' or empty for all."),
    limit: int = Query(default=200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Per-connection NetFlow anomaly detection (see ``connection_anomaly``).

    Unlike ``/api/firewall/anomalies`` (Isolation Forest over whole IPs), this
    scores **individual src→dst connections** — one internal host to one external
    IP — against a 30-day baseline of the same pairs, targeting **C2 beaconing**
    (regular small flows to a rare/new destination) and **atypical uploads /
    exfiltration** (large, upload-skewed volume to a new/rare destination).
    Normality comes from how many days the exact pair recurred and how many
    internal hosts share the destination. Result is cached (300s)."""
    from app import connection_anomaly as conn_anom
    res = await conn_anom.analyze(
        db, hours=hours, min_flows=min_flows, limit=limit,
        overrides={"min_score": min_score},
    )
    if kind in ("c2", "exfil", "new"):
        res["anomalies"] = [a for a in res["anomalies"] if a["kind"] == kind]
    return res


@app.post("/api/firewall/connection-anomalies/scan-now")
async def firewall_connection_anomalies_scan_now():
    """Run the per-connection C2/exfil agent once now (force). Marks the external
    destinations of high-confidence C2/exfil connections and **raises the
    configured Telegram/Teams alarms** — same as the scheduled sweep."""
    from app.agent import agent_connection_anomaly_loop
    await agent_connection_anomaly_loop(force=True)
    return {"ok": True}


@app.post("/api/firewall/connection-anomalies/triage-now")
async def firewall_connection_anomalies_triage_now():
    """Run the daily LLM connection-assessment agent once now (force). Enriches
    source + destination, reasons what each connection is, and writes a reasoned
    verdict on the destination IP (alarming on malicious/suspicious per settings)."""
    from app.agent import agent_connection_triage_loop
    await agent_connection_triage_loop(force=True)
    return {"ok": True}


# --- Analyst verdicts on anomalous IPs (schädlich / unschädlich + comment) ---

_ANOMALY_VERDICTS = {"malicious", "suspicious", "benign"}


class AnomalyVerdictIn(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)
    # 'malicious' | 'suspicious' | 'benign' | '' (empty clears the verdict)
    verdict: str = Field(default="", max_length=20)
    comment: str | None = Field(None, max_length=1000)


@app.get("/api/firewall/anomaly-verdicts")
async def list_anomaly_verdicts(db: AsyncSession = Depends(get_db)):
    """All analyst verdicts, keyed by IP. The table only holds manually-marked
    IPs, so this stays small; the anomaly page merges it into the live rows."""
    rows = (await db.execute(select(AnomalyVerdict))).scalars().all()
    return {
        "verdicts": {
            v.ip: {
                "verdict": v.verdict,
                "comment": v.comment,
                "created_by": v.created_by or "human",
                "updated_at": v.updated_at.isoformat() if v.updated_at else None,
            }
            for v in rows
        }
    }


@app.post("/api/firewall/anomaly-verdict")
async def set_anomaly_verdict(body: AnomalyVerdictIn, db: AsyncSession = Depends(get_db)):
    """Upsert (or clear) an analyst verdict for one anomalous IP."""
    import ipaddress
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")

    verdict = (body.verdict or "").strip().lower()
    existing = (await db.execute(
        select(AnomalyVerdict).where(AnomalyVerdict.ip == body.ip)
    )).scalar_one_or_none()

    # An empty verdict clears the entry (removes the mark entirely).
    if not verdict:
        if existing is not None:
            await db.delete(existing)
            await db.commit()
        return {"ok": True, "ip": body.ip, "verdict": None, "comment": None}

    if verdict not in _ANOMALY_VERDICTS:
        raise HTTPException(status_code=400, detail="verdict must be 'malicious', 'suspicious' or 'benign'")

    comment = (body.comment or "").strip() or None
    now = datetime.now(timezone.utc)
    if existing is None:
        db.add(AnomalyVerdict(ip=body.ip, verdict=verdict, comment=comment,
                              created_by="human", updated_at=now))
    else:
        existing.verdict = verdict
        existing.comment = comment
        # A human saving over an agent verdict takes ownership — the agent
        # never touches human verdicts again.
        existing.created_by = "human"
        existing.updated_at = now
    await db.commit()

    return {"ok": True, "ip": body.ip, "verdict": verdict, "comment": comment,
            "created_by": "human", "updated_at": now.isoformat()}


@app.get("/api/ip/{ip}/connections")
@cached(ttl=120)
async def ip_connections(
    ip: str,
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """All known past connections from and to an IP, from the NetFlow ledger.

    Outbound = the IP as source (IP → peer), inbound = the IP as destination
    (peer → IP). Aggregated per (peer, server-port, protocol) with bytes/flows
    and first/last seen, plus the peer's country. Powers the 'Bekannte
    Verbindungen' section of the OSINT panel. Cached 120s."""
    import asyncio
    import ipaddress as _ip
    try:
        _ip.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP")

    since = datetime.now(timezone.utc) - timedelta(days=days)

    def _empty_nf() -> dict:
        return {"connections": [], "truncated": False, "peers": 0, "bytes": 0, "flows": 0}

    def _empty_fw() -> dict:
        return {"connections": [], "truncated": False, "peers": 0, "events": 0}

    async def _nf_side(sess, self_col: str, peer_col: str) -> dict:
        rows = (await sess.execute(text(f"""
            SELECT n.{peer_col} AS peer, n.dst_port AS port, n.protocol AS proto,
                   SUM(n.bytes) AS bytes, SUM(n.packets) AS packets, SUM(n.flows) AS flows,
                   MIN(n.bucket_start) AS first_seen, MAX(n.bucket_start) AS last_seen,
                   MAX(g.country) AS country
            FROM netflow_buckets n
            LEFT JOIN geoip_cache g ON g.ip = n.{peer_col}
            WHERE n.{self_col} = :ip AND n.bucket_start >= :since
            GROUP BY n.{peer_col}, n.dst_port, n.protocol
            ORDER BY SUM(n.bytes) DESC
            LIMIT :lim
        """), {"ip": ip, "since": since, "lim": limit + 1})).all()
        truncated = len(rows) > limit
        rows = rows[:limit]
        conns = [{
            "peer": r[0], "port": r[1], "protocol": r[2],
            "bytes": int(r[3] or 0), "packets": int(r[4] or 0), "flows": int(r[5] or 0),
            "first_seen": r[6].isoformat() if r[6] else None,
            "last_seen": r[7].isoformat() if r[7] else None,
            "country": r[8],
        } for r in rows]
        # Headline derived from the shown rows (a '≥' lower bound when truncated)
        # — avoids a second full aggregation that's expensive for very busy IPs.
        return {
            "connections": conns, "truncated": truncated,
            "peers": len({c["peer"] for c in conns}),
            "bytes": sum(c["bytes"] for c in conns),
            "flows": sum(c["flows"] for c in conns),
        }

    # Blocked/denied attempts from the firewall logs — connections NetFlow never
    # records as a flow (the packet was dropped). Denied actions only.
    _deny = ("(f.action ILIKE 'den%' OR f.action ILIKE 'drop%' "
             "OR f.action ILIKE 'block%' OR f.action ILIKE 'rej%')")

    async def _fw_side(sess, self_col: str, peer_col: str) -> dict:
        rows = (await sess.execute(text(f"""
            SELECT f.{peer_col} AS peer, f.destination_port AS port, f.protocol AS proto,
                   f.action AS action, COUNT(*) AS events, MAX(f.created_at) AS last_seen,
                   MAX(g.country) AS country
            FROM firewall_logs f
            LEFT JOIN geoip_cache g ON g.ip = f.{peer_col}
            WHERE f.{self_col} = :ip AND f.created_at >= :since AND {_deny}
            GROUP BY f.{peer_col}, f.destination_port, f.protocol, f.action
            ORDER BY COUNT(*) DESC
            LIMIT :lim
        """), {"ip": ip, "since": since, "lim": limit + 1})).all()
        truncated = len(rows) > limit
        rows = rows[:limit]
        conns = [{
            "peer": r[0], "port": r[1], "protocol": r[2], "action": r[3],
            "events": int(r[4] or 0),
            "last_seen": r[5].isoformat() if r[5] else None,
            "country": r[6],
        } for r in rows]
        return {
            "connections": conns, "truncated": truncated,
            "peers": len({c["peer"] for c in conns}),
            "events": sum(c["events"] for c in conns),
        }

    # Each source runs in its own isolated session, bounded by both a server-side
    # statement_timeout and a wall-clock wait_for, so a very busy IP (NetFlow) or a
    # non-selective destination (firewall logs) degrades to "unavailable" instead
    # of hanging the panel. The two run concurrently → worst case ≈ max of the caps.
    async def _run_side(stmt_timeout_ms: int, wall_s: float, runner,
                        cols_out: tuple, cols_in: tuple, empty, reason: str) -> dict:
        async def _go():
            async with async_session() as sess:
                await sess.execute(text(f"SET statement_timeout = {stmt_timeout_ms}"))
                out = await runner(sess, *cols_out)
                inb = await runner(sess, *cols_in)
                return {"outbound": out, "inbound": inb, "available": True}
        try:
            return await asyncio.wait_for(_go(), wall_s)
        except Exception as e:
            logger.warning(f"ip_connections: {reason} for {ip}: {str(e)[:120]}")
            return {"outbound": empty(), "inbound": empty(), "available": False, "reason": reason}

    nf, firewall_blocked = await asyncio.gather(
        _run_side(7000, 8.0, _nf_side, ("src_ip", "dst_ip"), ("dst_ip", "src_ip"), _empty_nf,
                  "NetFlow-Abfrage zu langsam (sehr aktive IP — kleineres Zeitfenster wählen)"),
        _run_side(4500, 5.0, _fw_side, ("source_ip", "destination_ip"), ("destination_ip", "source_ip"), _empty_fw,
                  "Firewall-Log-Abfrage zu langsam (Index fehlt oder im Aufbau)"),
    )

    return {
        "ip": ip, "days": days,
        "outbound": nf["outbound"], "inbound": nf["inbound"],
        "netflow_available": nf.get("available", True),
        "netflow_reason": nf.get("reason"),
        "firewall_blocked": firewall_blocked,
    }


@app.get("/api/firewalls/{fw_ip}/interfaces")
async def firewall_interfaces(fw_ip: str, db: AsyncSession = Depends(get_db)):
    """Per-interface stats for one firewall (last 24h)."""
    since = datetime.now(timezone.utc) - timedelta(days=1)
    rows = (await db.execute(
        select(
            NetflowIfaceBucket.iface_idx,
            NetflowIfaceBucket.direction,
            func.sum(NetflowIfaceBucket.bytes).label("b"),
            func.sum(NetflowIfaceBucket.flows).label("f"),
            func.max(NetflowIfaceBucket.bucket_start).label("last_seen"),
        )
        .where(NetflowIfaceBucket.firewall_ip == fw_ip, NetflowIfaceBucket.bucket_start >= since)
        .group_by(NetflowIfaceBucket.iface_idx, NetflowIfaceBucket.direction)
    )).all()

    # Resolve interface names from app_settings.iface_names
    name_setting = await db.get(AppSetting, "iface_names")
    names: dict = {}
    if name_setting and name_setting.value:
        try:
            names = json.loads(name_setting.value).get(fw_ip, {}) or {}
        except (ValueError, TypeError):
            names = {}

    pivot: dict[int, dict] = {}
    for idx, direction, b, f, last in rows:
        cell = pivot.setdefault(idx, {
            "iface_idx": idx,
            "name": names.get(str(idx)),
            "bytes_in": 0, "bytes_out": 0,
            "flows_in": 0, "flows_out": 0,
            "last_seen": None,
        })
        if direction == "in":
            cell["bytes_in"] = int(b or 0); cell["flows_in"] = int(f or 0)
        else:
            cell["bytes_out"] = int(b or 0); cell["flows_out"] = int(f or 0)
        if last and (cell["last_seen"] is None or last.isoformat() > cell["last_seen"]):
            cell["last_seen"] = last.isoformat()
    return {"items": sorted(pivot.values(), key=lambda r: -(r["bytes_in"] + r["bytes_out"]))}


@app.get("/api/sophos/health-check")
async def sophos_health_check():
    """Account health score with 5-minute Redis cache to avoid hammering Sophos."""
    cache_key = "sophos:health-check"
    r = await get_redis()
    if r:
        try:
            cached = await r.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass

    try:
        data = await sophos_client.get_account_health()
    except Exception as e:
        logger.warning(f"Health check failed: {e}")
        return {"available": False, "error": str(e)}

    if data is None:
        return {"available": False}

    payload = {"available": True, "data": data}
    if r:
        try:
            await r.setex(cache_key, 300, json.dumps(payload))
        except Exception:
            pass
    return payload


# ---------------------------------------------------------------------------
# Email Management API proxy  (/api/email/*)
#
# Thin pass-through to the Sophos Email Security API (/email/v1) via
# SophosClient. List endpoints return {"available": bool, "items": [...]} so
# the frontend can distinguish "no Email license / not reachable" from "licensed
# but empty". Write actions hit the live mail tenant — they release/delete real
# quarantined mail and create/delete real mailboxes — so they confirm on the
# frontend and surface Sophos rejections as 502.
# ---------------------------------------------------------------------------


async def _email_list(coro_factory, label: str) -> dict:
    """Run an Email-API list coroutine, normalising errors into the
    {"available": ...} envelope instead of bubbling a 500."""
    try:
        items = await coro_factory()
    except httpx.HTTPStatusError as e:
        logger.warning(f"Email {label} HTTP error: {e.response.status_code}")
        return {"available": False, "items": [], "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        logger.warning(f"Email {label} failed: {e}")
        return {"available": False, "items": [], "error": str(e)}
    return {"available": True, "items": items, "count": len(items)}


class QuarantineActionIn(BaseModel):
    ids: list[str] = Field(..., min_length=1, max_length=500)
    post_delivery: bool = False
    # release -> optionally allowlist the sender; delete -> optionally blocklist.
    allow_sender: bool = False
    block_sender: bool = False


# ---- Mailboxes ----

@app.get("/api/email/mailboxes")
async def email_mailboxes(search: str | None = Query(default=None, max_length=200)):
    return await _email_list(
        lambda: sophos_client.email_list_mailboxes(search=search), "mailboxes"
    )


@app.get("/api/email/mailboxes/{mailbox_id}")
async def email_mailbox_detail(mailbox_id: str):
    try:
        mb = await sophos_client.email_get_mailbox(mailbox_id)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API error: {e.response.status_code}")
    if mb is None:
        raise HTTPException(status_code=404, detail="mailbox not found or Email API unavailable")
    return mb


@app.post("/api/email/mailboxes")
async def email_mailbox_create(body: dict = Body(...)):
    if not body:
        raise HTTPException(status_code=400, detail="empty mailbox body")
    try:
        return await sophos_client.email_create_mailbox(body)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API rejected create: {e.response.status_code}")


@app.patch("/api/email/mailboxes/{mailbox_id}")
async def email_mailbox_update(mailbox_id: str, body: dict = Body(...)):
    if not body:
        raise HTTPException(status_code=400, detail="empty mailbox body")
    try:
        return await sophos_client.email_update_mailbox(mailbox_id, body)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API rejected update: {e.response.status_code}")


@app.delete("/api/email/mailboxes/{mailbox_id}")
async def email_mailbox_delete(mailbox_id: str):
    try:
        return await sophos_client.email_delete_mailbox(mailbox_id)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API rejected delete: {e.response.status_code}")


# ---- Quarantine + Post-Delivery Quarantine ----

@app.get("/api/email/quarantine")
async def email_quarantine(
    post_delivery: bool = Query(default=False),
    hours: int = Query(default=168, ge=1, le=8760),
):
    begin_date = datetime.now(timezone.utc) - timedelta(hours=hours)
    label = "post-delivery quarantine" if post_delivery else "quarantine"
    return await _email_list(
        lambda: sophos_client.email_list_quarantine(
            post_delivery=post_delivery, begin_date=begin_date
        ),
        label,
    )


@app.get("/api/email/quarantine/{message_id}/attachments")
async def email_quarantine_attachments(
    message_id: str, post_delivery: bool = Query(default=False)
):
    # The Email API has no single-message GET (returns 404); the search result
    # already carries the full message, so the detail view only needs the
    # separately-paged attachment list.
    try:
        attachments = await sophos_client.email_quarantine_attachments(message_id, post_delivery)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API error: {e.response.status_code}")
    return {"attachments": attachments or {}}


@app.post("/api/email/quarantine/release")
async def email_quarantine_release(body: QuarantineActionIn):
    try:
        result = await sophos_client.email_release_quarantine(
            body.ids, allow_sender=body.allow_sender, post_delivery=body.post_delivery
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API rejected release: {e.response.status_code}")
    return {"ok": True, "released": len(body.ids), "sophos": result}


@app.post("/api/email/quarantine/delete")
async def email_quarantine_delete(body: QuarantineActionIn):
    try:
        result = await sophos_client.email_delete_quarantine(
            body.ids, block_sender=body.block_sender, post_delivery=body.post_delivery
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Sophos API rejected delete: {e.response.status_code}")
    return {"ok": True, "deleted": len(body.ids), "sophos": result}


@app.get("/api/detections/recent")
@cached(ttl=60)
async def get_recent_detections(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Threat-detections view. Sophos XDR/MDR endpoints (which would feed the
    `detections` table) are 404 for tenants without that license, so we
    surface threat-related rows from `alerts` instead — these are what the
    Central UI labels as 'Detections'."""
    threat_filter = (
        Alert.alert_type.ilike("%threat%")
        | Alert.alert_type.ilike("%detect%")
        | Alert.alert_type.ilike("%malware%")
        | (Alert.category == "runtimeDetections")
    )
    result = await db.execute(
        select(Alert).where(threat_filter).order_by(Alert.created_at.desc()).limit(limit)
    )
    alerts = result.scalars().all()
    return [
        {
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "description": a.description,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "device": a.managed_agent_name,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "country": a.attacker_country,
            "city": a.attacker_city,
        }
        for a in alerts
    ]


# --- Firewall Locations ---

@app.get("/api/firewall/device")
@cached(ttl=300)
async def get_firewall_device():
    """The firewall's own identity + interfaces, read live from its XML API.

    This is the authoritative source of truth about the physical device: one
    firewall (its hostname) and the IPs configured on its interfaces/VLANs —
    unlike the log/netflow-derived overview, which used to show each interface
    IP as a separate 'firewall'."""
    from app.sfos_client import fetch_device_info
    try:
        info = await fetch_device_info()
        return {"ok": True, **info}
    except Exception as e:
        return {"ok": False, "error": str(e), "hostname": None, "interfaces": []}


@app.get("/api/firewalls")
async def get_firewalls(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FirewallLocation))
    return [
        {
            "id": fw.id,
            "name": fw.name,
            "ip": fw.ip,
            "lat": fw.lat,
            "lon": fw.lon,
            "country": fw.country,
            "city": fw.city,
        }
        for fw in result.scalars().all()
    ]


@app.post("/api/firewalls")
async def add_firewall(
    data: FirewallLocationIn,
    db: AsyncSession = Depends(get_db),
):
    fw = FirewallLocation(
        name=data.name,
        ip=data.ip,
        lat=data.lat,
        lon=data.lon,
        country=data.country,
        city=data.city,
    )
    db.add(fw)
    await db.commit()
    await db.refresh(fw)
    return {"id": fw.id, "name": fw.name}


@app.patch("/api/firewalls/{fw_id}")
async def update_firewall(fw_id: int, data: FirewallLocationIn, db: AsyncSession = Depends(get_db)):
    fw = (await db.execute(
        select(FirewallLocation).where(FirewallLocation.id == fw_id)
    )).scalar_one_or_none()
    if fw is None:
        raise HTTPException(status_code=404, detail="firewall not found")
    fw.name, fw.ip = data.name, data.ip
    fw.lat, fw.lon = data.lat, data.lon
    fw.country, fw.city = data.country, data.city
    await db.commit()
    return {"ok": True, "id": fw.id, "name": fw.name}


@app.delete("/api/firewalls/{fw_id}")
async def delete_firewall(fw_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FirewallLocation).where(FirewallLocation.id == fw_id))
    fw = result.scalar_one_or_none()
    if fw:
        await db.delete(fw)
        await db.commit()
    return {"ok": True}


# --- Firewall Logs (Syslog) ---

@app.get("/api/firewall-logs/recent")
@cached(ttl=60)
async def get_recent_fw_logs(
    limit: int = Query(default=50, ge=1, le=500),
    log_type: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    query = select(FirewallLog).order_by(FirewallLog.created_at.desc())
    if log_type:
        query = query.where(FirewallLog.log_type == log_type)
    result = await db.execute(query.limit(limit))
    logs = result.scalars().all()

    blocked_set: set[str] = set()
    if logs:
        ips = {l.source_ip for l in logs if l.source_ip}
        if ips:
            rows = await db.execute(select(BlockedIp.ip).where(BlockedIp.ip.in_(ips)))
            blocked_set = {r[0] for r in rows.all()}

    return [
        {
            "id": l.id,
            "log_type": l.log_type,
            "log_subtype": l.log_subtype,
            "severity": l.severity,
            "firewall": l.firewall_name,
            "source_ip": l.source_ip,
            "source_blocked": l.source_ip in blocked_set if l.source_ip else False,
            "source_port": l.source_port,
            "destination_ip": l.destination_ip,
            "destination_port": l.destination_port,
            "protocol": l.protocol,
            "action": l.action,
            "threat": l.threat_name,
            "message": l.message,
            "user": l.user_name,
            "created_at": l.created_at.isoformat() if l.created_at else None,
            "country": l.attacker_country,
            "city": l.attacker_city,
            "asn": l.attacker_asn,
            "org": l.attacker_org,
        }
        for l in logs
    ]


@app.get("/api/firewall-logs/top-attackers")
async def get_fw_log_top_attackers(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(
            FirewallLog.source_ip,
            FirewallLog.attacker_country,
            FirewallLog.attacker_city,
            FirewallLog.attacker_asn,
            FirewallLog.attacker_org,
            func.count(FirewallLog.id).label("count"),
        )
        .where(
            FirewallLog.created_at >= since,
            FirewallLog.attacker_lat.isnot(None),
        )
        .group_by(
            FirewallLog.source_ip,
            FirewallLog.attacker_country,
            FirewallLog.attacker_city,
            FirewallLog.attacker_asn,
            FirewallLog.attacker_org,
        )
        .order_by(func.count(FirewallLog.id).desc())
        .limit(limit)
    )
    return [
        {
            "ip": row[0], "country": row[1], "city": row[2],
            "asn": row[3], "org": row[4], "count": row[5],
        }
        for row in result.all()
    ]


@app.get("/api/firewall-logs/failed-logins")
@cached(ttl=300)
async def get_failed_logins(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated failed-login attempts grouped by source IP. Sophos sends
    auth failures across several categories — log_type='Authentication',
    log_component='Admin', log_component='SSL VPN' etc. — so we cast a
    wide net via raw_data fields and the message body."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)

    # Heuristic filter: an entry is a failed-login if either
    #   - log_type/log_component points at auth/login, AND
    #   - status/result/message contains "fail"
    # We use raw_data->>... since SFOS naming varies between firmware versions.
    sql = text("""
        WITH failed AS (
            SELECT
                source_ip,
                created_at,
                user_name,
                attacker_country,
                attacker_city,
                message,
                raw_data,
                log_type,
                log_subtype
            FROM firewall_logs
            WHERE created_at >= :since
              AND source_ip IS NOT NULL
              AND (
                    log_type IN ('Authentication', 'Event')
                    OR (raw_data->>'log_component') ILIKE ANY (ARRAY['%auth%','%admin%','%ssl vpn%','%ipsec%','%user portal%'])
              )
              AND (
                    (raw_data->>'status') ILIKE 'fail%'
                    OR (raw_data->>'auth_status') ILIKE 'fail%'
                    OR (raw_data->>'log_subtype') ILIKE '%failed%'
                    OR COALESCE(message, '') ILIKE '%fail%'
                    OR COALESCE(message, '') ILIKE '%denied%'
                    OR COALESCE(message, '') ILIKE '%invalid%'
              )
        )
        SELECT
            source_ip,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE created_at >= :day_ago) AS last24h,
            MAX(created_at) AS last_attempt,
            MIN(created_at) AS first_attempt,
            MAX(message) AS last_message,
            (array_agg(user_name ORDER BY created_at DESC) FILTER (WHERE user_name IS NOT NULL))[1:5] AS recent_users,
            MAX(attacker_country) AS country,
            MAX(attacker_city) AS city,
            MAX(raw_data->>'log_component') AS component,
            MAX(raw_data->>'auth_mechanism') AS mechanism
        FROM failed
        GROUP BY source_ip
        ORDER BY MAX(created_at) DESC
        LIMIT :lim
    """)
    rows = (await db.execute(sql, {"since": since, "day_ago": day_ago, "lim": limit})).all()

    blocked_set: dict[str, BlockedIp] = {}
    whitelisted_set: dict[str, WhitelistedIp] = {}
    ips = {r[0] for r in rows if r[0]}
    if ips:
        bres = await db.execute(select(BlockedIp).where(BlockedIp.ip.in_(ips)))
        blocked_set = {b.ip: b for b in bres.scalars().all()}
        wres = await db.execute(select(WhitelistedIp).where(WhitelistedIp.ip.in_(ips)))
        whitelisted_set = {w.ip: w for w in wres.scalars().all()}

    return [
        {
            "source_ip": r[0],
            "attempts_total": int(r[1]),
            "attempts_24h": int(r[2]),
            "last_attempt": r[3].isoformat() if r[3] else None,
            "first_attempt": r[4].isoformat() if r[4] else None,
            "last_message": r[5],
            "recent_users": list(r[6]) if r[6] else [],
            "country": r[7],
            "city": r[8],
            "component": r[9],
            "mechanism": r[10],
            "blocked": r[0] in blocked_set,
            "blocked_at": (
                blocked_set[r[0]].blocked_at.isoformat()
                if r[0] in blocked_set and blocked_set[r[0]].blocked_at
                else None
            ),
            "whitelisted": r[0] in whitelisted_set,
            "whitelist_source": whitelisted_set[r[0]].source if r[0] in whitelisted_set else None,
        }
        for r in rows
    ]


# --- WAF (Web Application Firewall) ---

# A row qualifies as a WAF event if its log_type is "WAF" or its
# log_component string indicates Web Application Firewall / Web Server
# Protection (Sophos firmware naming varies between versions).
_WAF_FILTER_SQL = """(
    log_type = 'WAF'
    OR (raw_data->>'log_component') ILIKE '%waf%'
    OR (raw_data->>'log_component') ILIKE '%web app%'
    OR (raw_data->>'log_component') ILIKE '%web server protection%'
    OR (raw_data->>'log_subtype')   ILIKE '%waf%'
)"""

# Of those WAF rows, only the ones that actually represent a detected
# attack — Sophos also logs allowed/clean requests via the same log_type,
# so without this filter the widget shows mostly normal traffic.
_WAF_ATTACK_FILTER_SQL = """(
    threat_name IS NOT NULL
    OR (raw_data->>'reason') IS NOT NULL
    OR (raw_data->>'attack') IS NOT NULL
    OR (raw_data->>'attack_type') IS NOT NULL
    OR LOWER(COALESCE(action, '')) IN ('deny','denied','drop','dropped','block','blocked','reject','rejected','warn','warned')
    OR (raw_data->>'log_subtype') ILIKE '%attack%'
    OR (raw_data->>'log_subtype') ILIKE '%violat%'
    OR (raw_data->>'log_subtype') ILIKE '%denied%'
    OR (raw_data->>'log_subtype') ILIKE '%blocked%'
)"""


@app.get("/api/firewall-logs/waf/stats")
@cached(ttl=300)
async def get_waf_stats(
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)

    # Stats focus on detected attacks; allowed traffic would drown them out.
    sql = text(f"""
        SELECT
            COUNT(*) FILTER (WHERE {_WAF_ATTACK_FILTER_SQL}) AS total,
            COUNT(*) FILTER (WHERE {_WAF_ATTACK_FILTER_SQL} AND created_at >= :day_ago) AS last_24h,
            COUNT(*) FILTER (
                WHERE {_WAF_ATTACK_FILTER_SQL}
                  AND LOWER(COALESCE(action, '')) IN ('deny','denied','drop','dropped','block','blocked','reject','rejected')
            ) AS blocked,
            COUNT(DISTINCT source_ip) FILTER (WHERE {_WAF_ATTACK_FILTER_SQL} AND source_ip IS NOT NULL) AS unique_sources,
            COUNT(DISTINCT COALESCE(raw_data->>'domain', raw_data->>'website', raw_data->>'host')) FILTER (
                WHERE {_WAF_ATTACK_FILTER_SQL}
                  AND COALESCE(raw_data->>'domain', raw_data->>'website', raw_data->>'host') IS NOT NULL
            ) AS unique_hosts,
            COUNT(*) AS total_all
        FROM firewall_logs
        WHERE created_at >= :since AND {_WAF_FILTER_SQL}
    """)
    row = (await db.execute(sql, {"since": since, "day_ago": day_ago})).first()

    top_attackers_sql = text(f"""
        SELECT source_ip, attacker_country, attacker_city, COUNT(*) AS cnt
        FROM firewall_logs
        WHERE created_at >= :since AND {_WAF_FILTER_SQL} AND {_WAF_ATTACK_FILTER_SQL} AND source_ip IS NOT NULL
        GROUP BY source_ip, attacker_country, attacker_city
        ORDER BY cnt DESC
        LIMIT 10
    """)
    attackers = (await db.execute(top_attackers_sql, {"since": since})).all()

    top_hosts_sql = text(f"""
        SELECT COALESCE(raw_data->>'domain', raw_data->>'website', raw_data->>'host') AS host, COUNT(*) AS cnt
        FROM firewall_logs
        WHERE created_at >= :since AND {_WAF_FILTER_SQL} AND {_WAF_ATTACK_FILTER_SQL}
          AND COALESCE(raw_data->>'domain', raw_data->>'website', raw_data->>'host') IS NOT NULL
        GROUP BY host
        ORDER BY cnt DESC
        LIMIT 10
    """)
    hosts = (await db.execute(top_hosts_sql, {"since": since})).all()

    # Treat SFOS placeholders ('-', '') as missing so they don't clutter the
    # 'top attacks' chart with a fake "attack" called '-'.
    top_attacks_sql = text(f"""
        WITH src AS (
            SELECT COALESCE(
                       NULLIF(NULLIF(threat_name, ''), '-'),
                       NULLIF(NULLIF(raw_data->>'attack', ''), '-'),
                       NULLIF(NULLIF(raw_data->>'attack_type', ''), '-'),
                       NULLIF(NULLIF(raw_data->>'reason', ''), '-'),
                       NULLIF(NULLIF(raw_data->>'log_subtype', ''), '-'),
                       CASE WHEN (raw_data->>'http_status') LIKE '4%' OR (raw_data->>'http_status') LIKE '5%'
                            THEN 'HTTP ' || (raw_data->>'http_status') END
                   ) AS attack
            FROM firewall_logs
            WHERE created_at >= :since AND {_WAF_FILTER_SQL} AND {_WAF_ATTACK_FILTER_SQL}
        )
        SELECT attack, COUNT(*) AS cnt FROM src
        WHERE attack IS NOT NULL
        GROUP BY attack ORDER BY cnt DESC LIMIT 10
    """)
    attacks = (await db.execute(top_attacks_sql, {"since": since})).all()

    # Per-IP 4xx / 5xx breakdown across the whole WAF dataset (not just
    # attack-filtered) — useful for spotting noisy scanners that get a lot
    # of 4xx but might not trigger Sophos' attack heuristics.
    error_sources_sql = text(f"""
        SELECT source_ip, attacker_country, attacker_city,
               COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '4%') AS count_4xx,
               COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '5%') AS count_5xx,
               MAX(created_at) AS last_seen
        FROM firewall_logs
        WHERE created_at >= :since AND {_WAF_FILTER_SQL}
          AND source_ip IS NOT NULL
          AND (raw_data->>'http_status') ~ '^[45][0-9][0-9]$'
        GROUP BY source_ip, attacker_country, attacker_city
        ORDER BY (COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '4%')
                  + COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '5%')) DESC
        LIMIT 15
    """)
    error_sources = (await db.execute(error_sources_sql, {"since": since})).all()

    # Also a flat total for the summary tile
    error_totals_sql = text(f"""
        SELECT
            COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '4%') AS total_4xx,
            COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '5%') AS total_5xx
        FROM firewall_logs
        WHERE created_at >= :since AND {_WAF_FILTER_SQL}
    """)
    error_totals = (await db.execute(error_totals_sql, {"since": since})).first()

    return {
        "total": int(row[0] or 0),
        "last_24h": int(row[1] or 0),
        "blocked": int(row[2] or 0),
        "unique_sources": int(row[3] or 0),
        "unique_hosts": int(row[4] or 0),
        "total_all": int(row[5] or 0),
        "allowed_all": int(row[5] or 0) - int(row[0] or 0),
        "total_4xx": int(error_totals[0] or 0) if error_totals else 0,
        "total_5xx": int(error_totals[1] or 0) if error_totals else 0,
        "top_attackers": [
            {"ip": r[0], "country": r[1], "city": r[2], "count": int(r[3])}
            for r in attackers
        ],
        "top_hosts": [{"host": r[0], "count": int(r[1])} for r in hosts],
        "top_attacks": [{"attack": r[0], "count": int(r[1])} for r in attacks],
        "top_error_sources": [
            {
                "ip": r[0], "country": r[1], "city": r[2],
                "count_4xx": int(r[3] or 0),
                "count_5xx": int(r[4] or 0),
                "last_seen": r[5].isoformat() if r[5] else None,
            }
            for r in error_sources
        ],
    }


@app.get("/api/firewall-logs/waf/recent")
@cached(ttl=60)
async def get_waf_recent(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=200, ge=1, le=1000),
    status_class: str = Query(default="4xx_5xx"),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    # Status-class filter based directly on the http_status field (which
    # SFOS actually populates). Far more reliable than the old attack
    # heuristic, which over-matched because '-' placeholders for reason/
    # attack passed the IS NOT NULL test.
    status_map = {
        "all":     "",
        "4xx_5xx": "AND (fl.raw_data->>'http_status') ~ '^[45][0-9][0-9]$'",
        "5xx":     "AND (fl.raw_data->>'http_status') ~ '^5[0-9][0-9]$'",
        "4xx":     "AND (fl.raw_data->>'http_status') ~ '^4[0-9][0-9]$'",
        "2xx_3xx": "AND (fl.raw_data->>'http_status') ~ '^[23][0-9][0-9]$'",
    }
    attack_filter_clause = status_map.get(status_class, status_map["4xx_5xx"])
    # CTE per_ip computes 4xx / 5xx counts ACROSS the whole time window
    # per source_ip. We LEFT JOIN it onto each row so the table can show
    # the running total of error responses caused by the IP.
    sql = text(f"""
        WITH per_ip AS (
            SELECT source_ip,
                   COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '4%') AS src_4xx,
                   COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '5%') AS src_5xx
            FROM firewall_logs
            WHERE created_at >= :since AND {_WAF_FILTER_SQL}
              AND source_ip IS NOT NULL
              AND (raw_data->>'http_status') ~ '^[45][0-9][0-9]$'
            GROUP BY source_ip
        )
        SELECT
            fl.id,
            fl.created_at,
            fl.severity,
            fl.firewall_name,
            fl.source_ip,
            fl.source_port,
            fl.destination_ip,
            fl.destination_port,
            fl.action,
            fl.message,
            fl.threat_name,
            fl.attacker_country,
            fl.attacker_city,
            COALESCE(fl.raw_data->>'domain', fl.raw_data->>'website', fl.raw_data->>'host') AS host,
            COALESCE(fl.raw_data->>'httpmethod', fl.raw_data->>'method') AS http_method,
            COALESCE(fl.raw_data->>'httpquery', fl.raw_data->>'url', fl.raw_data->>'querystring', fl.raw_data->>'request') AS http_query,
            COALESCE(fl.raw_data->>'http_status', fl.raw_data->>'httpresp_code', fl.raw_data->>'status_code', fl.raw_data->>'response_code') AS http_status,
            NULLIF(NULLIF(NULLIF(COALESCE(fl.raw_data->>'reason', fl.raw_data->>'attack', fl.raw_data->>'attack_type'), ''), '-'), 'n/a') AS reason,
            COALESCE(fl.raw_data->>'useragent', fl.raw_data->>'user_agent') AS user_agent,
            COALESCE(fl.raw_data->>'referer', fl.raw_data->>'referrer') AS referer,
            fl.raw_data->>'log_component' AS log_component,
            fl.raw_data->>'log_subtype' AS log_subtype,
            COALESCE(p.src_4xx, 0) AS src_4xx,
            COALESCE(p.src_5xx, 0) AS src_5xx
        FROM firewall_logs fl
        LEFT JOIN per_ip p ON p.source_ip = fl.source_ip
        WHERE fl.created_at >= :since AND {_WAF_FILTER_SQL} {attack_filter_clause}
        ORDER BY fl.created_at DESC
        LIMIT :lim
    """)
    rows = (await db.execute(sql, {"since": since, "lim": limit})).all()

    ips = {r[4] for r in rows if r[4]}
    blocked: set[str] = set()
    if ips:
        bres = await db.execute(select(BlockedIp.ip).where(BlockedIp.ip.in_(ips)))
        blocked = {b[0] for b in bres.all()}

    return [
        {
            "id": r[0],
            "created_at": r[1].isoformat() if r[1] else None,
            "severity": r[2],
            "firewall": r[3],
            "source_ip": r[4],
            "source_blocked": (r[4] in blocked) if r[4] else False,
            "source_port": r[5],
            "destination_ip": r[6],
            "destination_port": r[7],
            "action": r[8],
            "message": r[9],
            "threat": r[10],
            "country": r[11],
            "city": r[12],
            "host": r[13],
            "http_method": r[14],
            "http_query": r[15],
            "http_status": r[16],
            "reason": r[17],
            "user_agent": r[18],
            "referer": r[19],
            "log_component": r[20],
            "log_subtype": r[21],
            "src_4xx": int(r[22] or 0),
            "src_5xx": int(r[23] or 0),
        }
        for r in rows
    ]


# --- IPS / IDP (Intrusion Prevention System) ---

# Sophos firmware names this subsystem inconsistently — log_type is usually
# "IDP" (the Sophos term for IPS), but log_component may say "Intrusion
# Prevention" or similar. Cast a wide enough net.
_IPS_FILTER_SQL = """(
    log_type IN ('IDP', 'IPS')
    OR (raw_data->>'log_component') ILIKE '%intrusion%'
    OR (raw_data->>'log_component') ILIKE '%idp%'
    OR (raw_data->>'log_component') = 'IPS'
)"""


@app.get("/api/firewall-logs/ips/stats")
@cached(ttl=300)
async def get_ips_stats(
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)

    sql = text(f"""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE created_at >= :day_ago) AS last_24h,
            COUNT(*) FILTER (
                WHERE LOWER(COALESCE(action, '')) IN ('drop','dropped','deny','denied','block','blocked','reject','rejected')
            ) AS dropped,
            COUNT(*) FILTER (WHERE LOWER(severity) IN ('high','critical')) AS high_severity,
            COUNT(DISTINCT source_ip) FILTER (WHERE source_ip IS NOT NULL) AS unique_sources,
            COUNT(DISTINCT COALESCE(threat_name, raw_data->>'signature_msg', raw_data->>'signature_id')) FILTER (
                WHERE COALESCE(threat_name, raw_data->>'signature_msg', raw_data->>'signature_id') IS NOT NULL
            ) AS unique_signatures
        FROM firewall_logs
        WHERE created_at >= :since AND {_IPS_FILTER_SQL}
    """)
    row = (await db.execute(sql, {"since": since, "day_ago": day_ago})).first()

    top_attackers_sql = text(f"""
        SELECT source_ip, attacker_country, attacker_city, COUNT(*) AS cnt
        FROM firewall_logs
        WHERE created_at >= :since AND {_IPS_FILTER_SQL} AND source_ip IS NOT NULL
        GROUP BY source_ip, attacker_country, attacker_city
        ORDER BY cnt DESC
        LIMIT 10
    """)
    attackers = (await db.execute(top_attackers_sql, {"since": since})).all()

    top_signatures_sql = text(f"""
        SELECT COALESCE(threat_name, raw_data->>'signature_msg') AS sig,
               raw_data->>'signature_id' AS sig_id,
               COUNT(*) AS cnt
        FROM firewall_logs
        WHERE created_at >= :since AND {_IPS_FILTER_SQL}
          AND COALESCE(threat_name, raw_data->>'signature_msg') IS NOT NULL
        GROUP BY sig, sig_id
        ORDER BY cnt DESC
        LIMIT 10
    """)
    signatures = (await db.execute(top_signatures_sql, {"since": since})).all()

    top_categories_sql = text(f"""
        SELECT COALESCE(raw_data->>'category', raw_data->>'classification', raw_data->>'log_subtype') AS cat,
               COUNT(*) AS cnt
        FROM firewall_logs
        WHERE created_at >= :since AND {_IPS_FILTER_SQL}
          AND COALESCE(raw_data->>'category', raw_data->>'classification', raw_data->>'log_subtype') IS NOT NULL
        GROUP BY cat
        ORDER BY cnt DESC
        LIMIT 10
    """)
    categories = (await db.execute(top_categories_sql, {"since": since})).all()

    return {
        "total": int(row[0] or 0),
        "last_24h": int(row[1] or 0),
        "dropped": int(row[2] or 0),
        "high_severity": int(row[3] or 0),
        "unique_sources": int(row[4] or 0),
        "unique_signatures": int(row[5] or 0),
        "top_attackers": [
            {"ip": r[0], "country": r[1], "city": r[2], "count": int(r[3])}
            for r in attackers
        ],
        "top_signatures": [
            {"signature": r[0], "signature_id": r[1], "count": int(r[2])}
            for r in signatures
        ],
        "top_categories": [{"category": r[0], "count": int(r[1])} for r in categories],
    }


@app.get("/api/firewall-logs/ips/recent")
@cached(ttl=60)
async def get_ips_recent(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    sql = text(f"""
        SELECT
            id,
            created_at,
            severity,
            firewall_name,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
            action,
            message,
            threat_name,
            attacker_country,
            attacker_city,
            raw_data->>'signature_id' AS signature_id,
            raw_data->>'signature_msg' AS signature_msg,
            COALESCE(raw_data->>'category', raw_data->>'classification') AS category,
            raw_data->>'rule_priority' AS rule_priority,
            COALESCE(raw_data->>'platform', raw_data->>'application') AS platform,
            raw_data->>'log_subtype' AS log_subtype
        FROM firewall_logs
        WHERE created_at >= :since AND {_IPS_FILTER_SQL}
        ORDER BY created_at DESC
        LIMIT :lim
    """)
    rows = (await db.execute(sql, {"since": since, "lim": limit})).all()

    ips = {r[4] for r in rows if r[4]}
    blocked: set[str] = set()
    if ips:
        bres = await db.execute(select(BlockedIp.ip).where(BlockedIp.ip.in_(ips)))
        blocked = {b[0] for b in bres.all()}

    return [
        {
            "id": r[0],
            "created_at": r[1].isoformat() if r[1] else None,
            "severity": r[2],
            "firewall": r[3],
            "source_ip": r[4],
            "source_blocked": (r[4] in blocked) if r[4] else False,
            "source_port": r[5],
            "destination_ip": r[6],
            "destination_port": r[7],
            "protocol": r[8],
            "action": r[9],
            "message": r[10],
            "threat": r[11],
            "country": r[12],
            "city": r[13],
            "signature_id": r[14],
            "signature_msg": r[15],
            "category": r[16],
            "rule_priority": r[17],
            "platform": r[18],
            "log_subtype": r[19],
        }
        for r in rows
    ]


# --- Blocked outbound connections to blocklisted IPs ---

# Which firewall actions count as "the connection was blocked". Sophos writes
# multi-word phrases into firewall_logs.action (e.g. "Drop destination match",
# "Deny Session"), so match on substrings rather than an exact value list.
# Deliberately excludes non-block outcomes like "Allowed", "Expire", "Failed".
_BLOCK_ACTION_SQL = (
    "(fl.action ILIKE '%drop%' OR fl.action ILIKE '%deny%' "
    "OR fl.action ILIKE '%block%' OR fl.action ILIKE '%reject%')"
)

# firewall_logs has ~16M rows; a plain JOIN against blocked_ips makes the
# planner seq-scan the whole created_at window (millions of rows). Feeding the
# blocklist in as an InitPlan array (`destination_ip = ANY(ARRAY(SELECT ...))`)
# instead drives the (destination_ip, created_at DESC) index and stays <200ms.
_BLOCKED_OUTBOUND_WHERE = (
    "fl.destination_ip = ANY(ARRAY(SELECT ip FROM blocked_ips)) "
    f"AND fl.created_at >= :since AND {_BLOCK_ACTION_SQL}"
)


@app.get("/api/firewall-logs/blocked-outbound/stats")
@cached(ttl=300)
async def get_blocked_outbound_stats(
    days: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate stats for outbound connections the firewall blocked because
    their destination sits on our IOC blocklist (blocked_ips). Proves the feed
    is catching real callbacks to known-bad IPs."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)

    # Comment lookup — enriched in Python so the hot query never joins the
    # 16M-row firewall_logs table against blocked_ips.
    comment_rows = await db.execute(select(BlockedIp.ip, BlockedIp.comment))
    comments = {r[0]: r[1] for r in comment_rows.all()}

    sql = text(f"""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE fl.created_at >= :day_ago) AS last_24h,
            COUNT(DISTINCT fl.destination_ip) AS unique_dests,
            COUNT(DISTINCT fl.source_ip) FILTER (WHERE fl.source_ip IS NOT NULL) AS unique_sources
        FROM firewall_logs fl
        WHERE {_BLOCKED_OUTBOUND_WHERE}
    """)
    row = (await db.execute(sql, {"since": since, "day_ago": day_ago})).first()

    top_dests_sql = text(f"""
        SELECT fl.destination_ip, fl.attacker_country, fl.attacker_city, COUNT(*) AS cnt
        FROM firewall_logs fl
        WHERE {_BLOCKED_OUTBOUND_WHERE}
        GROUP BY fl.destination_ip, fl.attacker_country, fl.attacker_city
        ORDER BY cnt DESC
        LIMIT 10
    """)
    dests = (await db.execute(top_dests_sql, {"since": since})).all()

    top_sources_sql = text(f"""
        SELECT fl.source_ip,
               COUNT(*) AS cnt,
               COUNT(DISTINCT fl.destination_ip) AS dests
        FROM firewall_logs fl
        WHERE {_BLOCKED_OUTBOUND_WHERE} AND fl.source_ip IS NOT NULL
        GROUP BY fl.source_ip
        ORDER BY cnt DESC
        LIMIT 10
    """)
    sources = (await db.execute(top_sources_sql, {"since": since})).all()

    return {
        "total": int(row[0] or 0),
        "last_24h": int(row[1] or 0),
        "unique_dests": int(row[2] or 0),
        "unique_sources": int(row[3] or 0),
        "top_destinations": [
            {"ip": r[0], "country": r[1], "city": r[2],
             "comment": comments.get(r[0]), "count": int(r[3])}
            for r in dests
        ],
        "top_sources": [
            {"ip": r[0], "count": int(r[1]), "destinations": int(r[2])}
            for r in sources
        ],
    }


@app.get("/api/firewall-logs/blocked-outbound/recent")
@cached(ttl=60)
async def get_blocked_outbound_recent(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=300, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Recent outbound connections that were blocked because the destination is
    on the IOC blocklist. Source is the internal host, destination is the
    known-bad IP we listed."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    sql = text(f"""
        SELECT
            fl.id,
            fl.created_at,
            fl.severity,
            fl.firewall_name,
            fl.source_ip,
            fl.source_port,
            fl.destination_ip,
            fl.destination_port,
            fl.protocol,
            fl.action,
            fl.message,
            fl.threat_name,
            fl.attacker_country,
            fl.attacker_city,
            fl.attacker_asn,
            fl.attacker_org
        FROM firewall_logs fl
        WHERE {_BLOCKED_OUTBOUND_WHERE}
        ORDER BY fl.created_at DESC
        LIMIT :lim
    """)
    rows = (await db.execute(sql, {"since": since, "lim": limit})).all()

    # Enrich blocklist comment / listing date in Python (see _BLOCKED_OUTBOUND_WHERE).
    dest_ips = {r[6] for r in rows if r[6]}
    block_meta: dict[str, tuple] = {}
    if dest_ips:
        meta_rows = await db.execute(
            select(BlockedIp.ip, BlockedIp.comment, BlockedIp.blocked_at)
            .where(BlockedIp.ip.in_(dest_ips))
        )
        block_meta = {m[0]: (m[1], m[2]) for m in meta_rows.all()}

    return [
        {
            "id": r[0],
            "created_at": r[1].isoformat() if r[1] else None,
            "severity": r[2],
            "firewall": r[3],
            "source_ip": r[4],
            "source_port": r[5],
            "destination_ip": r[6],
            "destination_port": r[7],
            "protocol": r[8],
            "action": r[9],
            "message": r[10],
            "threat": r[11],
            "country": r[12],
            "city": r[13],
            "asn": r[14],
            "org": r[15],
            "block_comment": block_meta.get(r[6], (None, None))[0],
            "block_added_at": (block_meta.get(r[6], (None, None))[1].isoformat()
                               if block_meta.get(r[6], (None, None))[1] else None),
        }
        for r in rows
    ]


# --- Manual Collection Trigger ---

@app.post("/api/collect")
async def trigger_collection():
    scheduler.add_job(collect_all, "date", id="manual_collect", replace_existing=True)
    return {"status": "collection triggered"}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


# --- OSINT lookup ---


# Order matters: the more specific /api/osint/url and /api/osint/domain/...
# routes must be declared BEFORE the catch-all /api/osint/{ip}, otherwise
# FastAPI matches the catch-all first and treats "url" / "domain" as IP
# values.
@app.get("/api/osint/url")
async def osint_lookup_url(
    u: str = Query(..., min_length=8, max_length=2048),
    force: bool = Query(default=False),
):
    """VirusTotal + Sophos Intelix lookup for a URL. URL is passed as the
    ``u`` query parameter so callers don't have to fight path-encoding."""
    try:
        normalised = _normalize_url(u)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid url: {e}")
    from app.osint import lookup_url as osint_url_fn
    return await osint_url_fn(normalised, force=force)


@app.get("/api/osint/domain/{domain}")
async def osint_lookup_domain(domain: str, force: bool = Query(default=False)):
    """VirusTotal + Sophos Intelix + DNS A-record lookup for a domain.
    Wildcards (`*.foo.tld`) are accepted and the bare host is queried."""
    try:
        normalised = _normalize_domain(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid domain: {e}")
    from app.osint import lookup_domain as osint_domain_fn
    return await osint_domain_fn(normalised, force=force)


@app.get("/api/osint/history")
async def osint_history(
    days: int = Query(default=90, ge=1, le=3650),
    q: str = Query(default=""),
    indicator_type: str = Query(default="all", pattern="^(all|ip|domain|url)$"),
    min_abuse: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=200, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
):
    """Persistent OSINT lookup history (survives the 1h Redis cache)."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = select(OsintResult).where(OsintResult.last_seen >= since)
    if indicator_type != "all":
        stmt = stmt.where(OsintResult.indicator_type == indicator_type)
    if q:
        stmt = stmt.where(OsintResult.value.ilike(f"%{q}%"))
    if min_abuse:
        stmt = stmt.where(OsintResult.abuse_score >= min_abuse)
    rows = (await db.execute(stmt.order_by(OsintResult.last_seen.desc()).limit(limit))).scalars().all()
    total = (await db.execute(select(func.count(OsintResult.value)))).scalar() or 0

    def _iso(dt):
        return dt.isoformat() if dt else None

    return {
        "total": total,
        "items": [
            {
                "value": r.value, "type": r.indicator_type,
                "abuse_score": r.abuse_score, "vt_malicious": r.vt_malicious,
                "greynoise": r.greynoise, "intelix_category": r.intelix_category,
                "country": r.country, "city": r.city, "org": r.org, "asn": r.asn,
                "lookup_count": r.lookup_count,
                "first_seen": _iso(r.first_seen), "last_seen": _iso(r.last_seen),
            }
            for r in rows
        ],
    }


@app.post("/api/osint/shodan/{ip}")
async def osint_shodan_ondemand(ip: str):
    """Explicit, human-triggered Shodan lookup (the 'Shodan abfragen' button).
    Shodan is never run automatically — this is the only human entry point and
    it spends one Shodan credit. Queries + persists ports/CVEs for the layers."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    from app.osint import shodan_on_demand
    return await shodan_on_demand(ip)


@app.get("/api/osint/{ip}")
async def osint_lookup(ip: str, force: bool = Query(default=False)):
    """Run AbuseIPDB / VirusTotal / GreyNoise / ipinfo / Intelix in parallel for
    a given IP (Shodan is NOT included — trigger it explicitly via the button →
    /api/osint/shodan/{ip}). Cached in Redis for 1h. Pass ?force=true to bypass."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")

    from app.osint import lookup as osint_lookup_fn
    return await osint_lookup_fn(ip, force=force)


# --- AI command interface (chat + Teams) ---

class ChatCommandIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    # Persisted-session id. When omitted a new session (fresh context) is created;
    # its history is loaded server-side, so the client no longer sends `history`.
    session_id: int | None = None
    # Legacy: an optional client-side history (used only when no session_id).
    history: list[dict] | None = None


@app.post("/api/chat/command")
async def chat_command(body: ChatCommandIn, db: AsyncSession = Depends(get_db)):
    """Natural-language input from the in-app chat: a recognised command (block /
    isolate / quarantine / OSINT / stats) is executed, otherwise it's a free
    conversation with the analyst-persona LLM.

    Conversations are persisted as sessions. With a `session_id` the turn is
    appended to that session and its stored messages provide the LLM context;
    without one a new session (fresh, empty context) is created."""
    from app.command_service import run_command
    from app.models import ChatSession, ChatMessage

    session = None
    if body.session_id:
        session = (await db.execute(
            select(ChatSession).where(ChatSession.id == body.session_id)
        )).scalar_one_or_none()
    if session is None:
        session = ChatSession(title=(body.message or "").strip()[:80] or "Chat")
        db.add(session)
        await db.flush()  # assign id

    # LLM context = THIS session's prior messages only (fresh context per session).
    # Include user turns and conversational assistant turns (not command outputs).
    prior = (await db.execute(
        select(ChatMessage).where(ChatMessage.session_id == session.id).order_by(ChatMessage.id)
    )).scalars().all()
    history = [{"role": m.role, "content": m.content} for m in prior
               if m.role == "user" or (m.role == "assistant" and (m.tool or "chat") == "chat")]

    result = await run_command(body.message, actor="chat", history=history[-16:])
    reply = result.get("reply") or ""

    db.add(ChatMessage(session_id=session.id, role="user", content=body.message[:8000]))
    db.add(ChatMessage(session_id=session.id, role="assistant",
                       content=reply[:16000], tool=result.get("tool")))
    session.updated_at = datetime.now(timezone.utc)
    if not session.title:
        session.title = (body.message or "").strip()[:80] or "Chat"
    await db.commit()

    result["session_id"] = session.id
    return result


@app.get("/api/chat/sessions")
async def list_chat_sessions(db: AsyncSession = Depends(get_db)):
    """Saved chat sessions, newest first, with their message count."""
    from app.models import ChatSession, ChatMessage
    rows = (await db.execute(
        select(ChatSession.id, ChatSession.title, ChatSession.updated_at,
               func.count(ChatMessage.id).label("n"))
        .outerjoin(ChatMessage, ChatMessage.session_id == ChatSession.id)
        .group_by(ChatSession.id)
        .order_by(ChatSession.updated_at.desc())
        .limit(200)
    )).all()
    return {"sessions": [
        {"id": r[0], "title": r[1] or "Chat",
         "updated_at": r[2].isoformat() if r[2] else None, "messages": int(r[3] or 0)}
        for r in rows
    ]}


@app.get("/api/chat/sessions/{session_id}")
async def get_chat_session(session_id: int, db: AsyncSession = Depends(get_db)):
    """A session's full message history, to resume it."""
    from app.models import ChatSession, ChatMessage
    s = (await db.execute(
        select(ChatSession).where(ChatSession.id == session_id)
    )).scalar_one_or_none()
    if s is None:
        raise HTTPException(status_code=404, detail="session not found")
    msgs = (await db.execute(
        select(ChatMessage).where(ChatMessage.session_id == session_id).order_by(ChatMessage.id)
    )).scalars().all()
    return {
        "id": s.id, "title": s.title or "Chat",
        "messages": [{"role": m.role, "content": m.content, "tool": m.tool} for m in msgs],
    }


class ChatSessionRenameIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)


@app.patch("/api/chat/sessions/{session_id}")
async def rename_chat_session(session_id: int, body: ChatSessionRenameIn,
                              db: AsyncSession = Depends(get_db)):
    """Rename a chat session."""
    from app.models import ChatSession
    s = (await db.execute(
        select(ChatSession).where(ChatSession.id == session_id)
    )).scalar_one_or_none()
    if s is None:
        raise HTTPException(status_code=404, detail="session not found")
    s.title = body.title.strip()[:200] or s.title
    await db.commit()
    return {"ok": True, "id": s.id, "title": s.title}


@app.delete("/api/chat/sessions/{session_id}")
async def delete_chat_session(session_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a chat session (its messages cascade)."""
    from app.models import ChatSession
    s = (await db.execute(
        select(ChatSession).where(ChatSession.id == session_id)
    )).scalar_one_or_none()
    if s:
        await db.delete(s)
        await db.commit()
    return {"ok": True}


@app.get("/api/chat/default-persona")
async def chat_default_persona(lang: str | None = Query(default=None, pattern="^(en|de)$")):
    """The bundled analyst-persona prompt, for the admin 'reset to default'.
    Language follows ``lang`` if given, else the configured agent_language."""
    from app.command_service import DEFAULT_ANALYST_PROMPT, DEFAULT_ANALYST_PROMPT_EN
    use = lang if lang in ("en", "de") else ("de" if getattr(settings, "agent_language", "en") == "de" else "en")
    return {"prompt": DEFAULT_ANALYST_PROMPT_EN if use == "en" else DEFAULT_ANALYST_PROMPT}


def _verify_teams_hmac(raw: bytes, auth_header: str | None) -> bool:
    """Teams Outgoing Webhooks sign the request body with HMAC-SHA256 using the
    base64 secret Teams shows at creation; the header is 'HMAC <base64sig>'."""
    secret = settings.teams_outgoing_secret
    if not secret:
        return False
    if not auth_header or not auth_header.startswith("HMAC "):
        return False
    try:
        import base64
        digest = hmac.new(base64.b64decode(secret), raw, hashlib.sha256).digest()
        expected = base64.b64encode(digest).decode()
        return hmac.compare_digest(expected, auth_header[5:].strip())
    except Exception:
        return False


@app.post("/api/teams/command")
async def teams_command(request: Request):
    """Microsoft Teams Outgoing Webhook entry point. Verifies the HMAC
    signature, runs the command, and replies with a Teams message card."""
    raw = await request.body()
    if not _verify_teams_hmac(raw, request.headers.get("Authorization")):
        raise HTTPException(status_code=401, detail="invalid HMAC signature")
    try:
        activity = json.loads(raw or b"{}")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    text = (activity.get("text") or "").strip()
    # Strip the bot @mention Teams prepends (plain text or <at>…</at>).
    text = re.sub(r"<at>.*?</at>", "", text)
    text = re.sub(r"^\s*@?\w+\s*", "", text) if text.lower().startswith("@") else text
    actor = ((activity.get("from") or {}).get("name")) or "teams"
    from app.command_service import run_command
    result = await run_command(text.strip(), actor=actor)
    return {"type": "message", "text": result["reply"]}


# --- NetFlow analytics ---

# Map of common ports/protocols → human-readable label, used in chart legends.
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6"}
_PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
    143: "imap", 161: "snmp", 162: "snmp-trap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1812: "radius", 1813: "radius-acct", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 5985: "winrm", 5986: "winrm-https",
    8080: "http-alt", 8443: "https-alt", 6379: "redis", 11211: "memcached",
    27017: "mongodb",
}


def _netflow_filter(since: datetime, firewall: str | None):
    conds = [NetflowBucket.bucket_start >= since]
    if firewall and firewall != "all":
        conds.append(NetflowBucket.firewall_ip == firewall)
    return conds


async def _load_firewall_aliases(db: AsyncSession) -> dict[str, str]:
    """Map of firewall_ip -> human-readable hostname. Stored in app_settings."""
    setting = await db.get(AppSetting, "firewall_aliases")
    if not setting or not setting.value:
        return {}
    try:
        return json.loads(setting.value)
    except (ValueError, TypeError):
        return {}


@app.get("/api/netflow/firewalls")
async def netflow_firewalls(db: AsyncSession = Depends(get_db)):
    """Distinct exporter IPs (= firewalls) seen in netflow data."""
    rows = await db.execute(
        select(NetflowBucket.firewall_ip, func.count(NetflowBucket.id))
        .where(NetflowBucket.firewall_ip.isnot(None))
        .group_by(NetflowBucket.firewall_ip)
        .order_by(func.count(NetflowBucket.id).desc())
    )
    aliases = await _load_firewall_aliases(db)
    return [
        {"ip": r[0], "name": aliases.get(r[0]) or r[0], "buckets": r[1]}
        for r in rows.all()
    ]


@app.get("/api/netflow/summary")
async def netflow_summary(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    totals = (await db.execute(
        select(
            func.coalesce(func.sum(NetflowBucket.bytes), 0),
            func.coalesce(func.sum(NetflowBucket.packets), 0),
            func.coalesce(func.sum(NetflowBucket.flows), 0),
            func.count(func.distinct(NetflowBucket.src_ip)),
            func.count(func.distinct(NetflowBucket.dst_ip)),
        ).where(*conds)
    )).one()

    return {
        "bytes": int(totals[0]),
        "packets": int(totals[1]),
        "flows": int(totals[2]),
        "unique_sources": int(totals[3]),
        "unique_destinations": int(totals[4]),
        "since": since.isoformat(),
    }


@app.get("/api/netflow/timeline")
async def netflow_timeline(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Bytes / packets / flows per time bucket. Granularity scales with range
    so the response stays under ~1000 points for the chart."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    if days <= 1:
        trunc = "minute"
    elif days <= 7:
        trunc = "hour"
    else:
        trunc = "day"

    rows = await db.execute(
        select(
            func.date_trunc(trunc, NetflowBucket.bucket_start).label("ts"),
            func.coalesce(func.sum(NetflowBucket.bytes), 0),
            func.coalesce(func.sum(NetflowBucket.packets), 0),
            func.coalesce(func.sum(NetflowBucket.flows), 0),
        )
        .where(*conds)
        .group_by(text("1"))
        .order_by(text("1"))
    )
    return {
        "granularity": trunc,
        "points": [
            {
                "ts": r[0].isoformat() if r[0] else None,
                "bytes": int(r[1]),
                "packets": int(r[2]),
                "flows": int(r[3]),
            }
            for r in rows.all()
        ],
    }


@app.get("/api/netflow/top-talkers")
async def netflow_top_talkers(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    rows = await db.execute(
        select(
            NetflowBucket.src_ip,
            func.sum(NetflowBucket.bytes).label("b"),
            func.sum(NetflowBucket.packets).label("pk"),
            func.sum(NetflowBucket.flows).label("f"),
        )
        .where(*conds, NetflowBucket.src_ip.isnot(None))
        .group_by(NetflowBucket.src_ip)
        .order_by(text("b DESC"))
        .limit(limit)
    )
    items = [
        {"ip": r[0], "bytes": int(r[1] or 0), "packets": int(r[2] or 0), "flows": int(r[3] or 0)}
        for r in rows.all()
    ]
    # Enrich with geo
    if items:
        ips = [i["ip"] for i in items]
        geos = await db.execute(
            select(GeoIPCache.ip, GeoIPCache.country, GeoIPCache.city, GeoIPCache.org)
            .where(GeoIPCache.ip.in_(ips))
        )
        geo_map = {g[0]: {"country": g[1], "city": g[2], "org": g[3]} for g in geos.all()}
        for it in items:
            g = geo_map.get(it["ip"], {})
            it["country"] = g.get("country")
            it["city"] = g.get("city")
            it["org"] = g.get("org")
    return items


@app.get("/api/netflow/top-destinations")
async def netflow_top_destinations(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    rows = await db.execute(
        select(
            NetflowBucket.dst_ip,
            func.sum(NetflowBucket.bytes).label("b"),
            func.sum(NetflowBucket.packets).label("pk"),
            func.sum(NetflowBucket.flows).label("f"),
        )
        .where(*conds, NetflowBucket.dst_ip.isnot(None))
        .group_by(NetflowBucket.dst_ip)
        .order_by(text("b DESC"))
        .limit(limit)
    )
    items = [
        {"ip": r[0], "bytes": int(r[1] or 0), "packets": int(r[2] or 0), "flows": int(r[3] or 0)}
        for r in rows.all()
    ]
    if items:
        ips = [i["ip"] for i in items]
        geos = await db.execute(
            select(
                GeoIPCache.ip, GeoIPCache.country, GeoIPCache.city,
                GeoIPCache.org, GeoIPCache.lat, GeoIPCache.lon,
            ).where(GeoIPCache.ip.in_(ips))
        )
        geo_map = {
            g[0]: {"country": g[1], "city": g[2], "org": g[3], "lat": g[4], "lon": g[5]}
            for g in geos.all()
        }
        for it in items:
            g = geo_map.get(it["ip"], {})
            it["country"] = g.get("country")
            it["city"] = g.get("city")
            it["org"] = g.get("org")
            it["lat"] = g.get("lat")
            it["lon"] = g.get("lon")
    return items


@app.get("/api/netflow/top-ports")
async def netflow_top_ports(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    rows = await db.execute(
        select(
            NetflowBucket.dst_port,
            NetflowBucket.protocol,
            func.sum(NetflowBucket.bytes).label("b"),
            func.sum(NetflowBucket.flows).label("f"),
        )
        .where(*conds, NetflowBucket.dst_port.isnot(None))
        .group_by(NetflowBucket.dst_port, NetflowBucket.protocol)
        .order_by(text("b DESC"))
        .limit(limit)
    )
    return [
        {
            "port": r[0],
            "protocol": _PROTO_NAMES.get(r[1] or 0, str(r[1])) if r[1] is not None else None,
            "service": _PORT_SERVICES.get(r[0] or 0),
            "bytes": int(r[2] or 0),
            "flows": int(r[3] or 0),
        }
        for r in rows.all()
    ]


@app.get("/api/netflow/protocols")
async def netflow_protocols(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    rows = await db.execute(
        select(
            NetflowBucket.protocol,
            func.sum(NetflowBucket.bytes).label("b"),
            func.sum(NetflowBucket.flows).label("f"),
        )
        .where(*conds)
        .group_by(NetflowBucket.protocol)
        .order_by(text("b DESC"))
    )
    return [
        {
            "protocol_num": r[0],
            "protocol": _PROTO_NAMES.get(r[0] or 0, f"proto-{r[0]}"),
            "bytes": int(r[1] or 0),
            "flows": int(r[2] or 0),
        }
        for r in rows.all()
    ]


@app.get("/api/netflow/geo")
async def netflow_geo(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Lat/Lon of top destinations for the world map."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    # Pull top destinations and join geo in-app to keep the query simple.
    rows = await db.execute(
        select(
            NetflowBucket.dst_ip,
            func.sum(NetflowBucket.bytes).label("b"),
            func.sum(NetflowBucket.flows).label("f"),
        )
        .where(*conds, NetflowBucket.dst_ip.isnot(None))
        .group_by(NetflowBucket.dst_ip)
        .order_by(text("b DESC"))
        .limit(limit * 2)  # fetch extra; some won't have geo
    )
    items = list(rows.all())
    if not items:
        return []
    ips = [r[0] for r in items]
    geos = await db.execute(
        select(GeoIPCache.ip, GeoIPCache.country, GeoIPCache.city, GeoIPCache.lat, GeoIPCache.lon)
        .where(GeoIPCache.ip.in_(ips), GeoIPCache.lat.isnot(None))
    )
    geo_map = {g[0]: {"country": g[1], "city": g[2], "lat": g[3], "lon": g[4]} for g in geos.all()}
    out = []
    for r in items:
        g = geo_map.get(r[0])
        if not g:
            continue
        out.append({
            "ip": r[0],
            "lat": g["lat"],
            "lon": g["lon"],
            "country": g["country"],
            "city": g["city"],
            "bytes": int(r[1] or 0),
            "flows": int(r[2] or 0),
        })
        if len(out) >= limit:
            break
    return out


@app.get("/api/netflow/interfaces")
async def netflow_interfaces(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Per-interface bytes/packets/flows. Direction is split into 'in' and
    'out' so the UI can render Ingress vs. Egress side by side. Avg-Mbps is
    computed across the requested time window."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    seconds = max(1, (datetime.now(timezone.utc) - since).total_seconds())

    conds = [NetflowIfaceBucket.bucket_start >= since]
    if firewall and firewall != "all":
        conds.append(NetflowIfaceBucket.firewall_ip == firewall)

    rows = await db.execute(
        select(
            NetflowIfaceBucket.firewall_ip,
            NetflowIfaceBucket.iface_idx,
            NetflowIfaceBucket.direction,
            func.coalesce(func.sum(NetflowIfaceBucket.bytes), 0).label("b"),
            func.coalesce(func.sum(NetflowIfaceBucket.packets), 0).label("pk"),
            func.coalesce(func.sum(NetflowIfaceBucket.flows), 0).label("f"),
        )
        .where(*conds)
        .group_by(NetflowIfaceBucket.firewall_ip, NetflowIfaceBucket.iface_idx, NetflowIfaceBucket.direction)
    )

    # Resolve interface names: app_settings key 'iface_names' stores a JSON
    # mapping {firewall_ip: {iface_idx: name}}.
    name_map: dict = {}
    name_setting = await db.get(AppSetting, "iface_names")
    if name_setting and name_setting.value:
        try:
            name_map = json.loads(name_setting.value)
        except (ValueError, TypeError):
            name_map = {}

    # Pivot direction → in/out per (fw, iface)
    pivot: dict[tuple[str, int], dict] = {}
    for r in rows.all():
        fw, idx, direction, b, pk, f = r
        key = (fw, idx)
        if key not in pivot:
            pivot[key] = {
                "firewall_ip": fw,
                "iface_idx": idx,
                "name": (name_map.get(fw, {}) or {}).get(str(idx)),
                "bytes_in": 0, "packets_in": 0, "flows_in": 0,
                "bytes_out": 0, "packets_out": 0, "flows_out": 0,
            }
        cell = pivot[key]
        if direction == "in":
            cell["bytes_in"] = int(b); cell["packets_in"] = int(pk); cell["flows_in"] = int(f)
        else:
            cell["bytes_out"] = int(b); cell["packets_out"] = int(pk); cell["flows_out"] = int(f)

    aliases = await _load_firewall_aliases(db)
    items = list(pivot.values())
    for it in items:
        it["firewall_name"] = aliases.get(it["firewall_ip"]) or it["firewall_ip"]
        total = it["bytes_in"] + it["bytes_out"]
        it["bytes_total"] = total
        it["mbps_in_avg"] = round(it["bytes_in"] * 8 / seconds / 1_000_000, 3)
        it["mbps_out_avg"] = round(it["bytes_out"] * 8 / seconds / 1_000_000, 3)
    items.sort(key=lambda x: -x["bytes_total"])
    return items


@app.get("/api/netflow/interface-timeline")
async def netflow_interface_timeline(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    iface: int | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = [NetflowIfaceBucket.bucket_start >= since]
    if firewall and firewall != "all":
        conds.append(NetflowIfaceBucket.firewall_ip == firewall)
    if iface is not None:
        conds.append(NetflowIfaceBucket.iface_idx == iface)

    if days <= 1:
        trunc = "minute"
    elif days <= 7:
        trunc = "hour"
    else:
        trunc = "day"

    rows = await db.execute(
        select(
            func.date_trunc(trunc, NetflowIfaceBucket.bucket_start).label("ts"),
            NetflowIfaceBucket.direction,
            func.coalesce(func.sum(NetflowIfaceBucket.bytes), 0).label("b"),
        )
        .where(*conds)
        .group_by(text("1"), NetflowIfaceBucket.direction)
        .order_by(text("1"))
    )
    out: dict[str, dict] = {}
    for r in rows.all():
        ts = r[0].isoformat() if r[0] else None
        if ts not in out:
            out[ts] = {"ts": ts, "bytes_in": 0, "bytes_out": 0}
        if r[1] == "in":
            out[ts]["bytes_in"] = int(r[2])
        else:
            out[ts]["bytes_out"] = int(r[2])
    return {"granularity": trunc, "points": list(out.values())}


class IfaceNameMapIn(BaseModel):
    # JSON object: {firewall_ip: {iface_idx: name}}
    names: dict[str, dict[str, str]]


@app.get("/api/netflow/iface-names")
async def get_iface_names(db: AsyncSession = Depends(get_db)):
    setting = await db.get(AppSetting, "iface_names")
    if not setting or not setting.value:
        return {}
    try:
        return json.loads(setting.value)
    except (ValueError, TypeError):
        return {}


@app.put("/api/netflow/iface-names")
async def put_iface_names(body: IfaceNameMapIn, db: AsyncSession = Depends(get_db)):
    payload = json.dumps(body.names)
    setting = await db.get(AppSetting, "iface_names")
    if setting is None:
        db.add(AppSetting(key="iface_names", value=payload))
    else:
        setting.value = payload
    await db.commit()
    return {"ok": True, "names": body.names}


class FirewallAliasMapIn(BaseModel):
    aliases: dict[str, str]  # {firewall_ip: hostname}


@app.get("/api/netflow/firewall-aliases")
async def get_firewall_aliases(db: AsyncSession = Depends(get_db)):
    return await _load_firewall_aliases(db)


@app.put("/api/netflow/firewall-aliases")
async def put_firewall_aliases(body: FirewallAliasMapIn, db: AsyncSession = Depends(get_db)):
    payload = json.dumps(body.aliases)
    setting = await db.get(AppSetting, "firewall_aliases")
    if setting is None:
        db.add(AppSetting(key="firewall_aliases", value=payload))
    else:
        setting.value = payload
    await db.commit()
    return {"ok": True, "aliases": body.aliases}


@app.get("/api/netflow/top-flows")
async def netflow_top_flows(
    days: int = Query(default=1, ge=1, le=90),
    firewall: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated flows (src + dst + port + protocol) sorted by bytes."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    conds = _netflow_filter(since, firewall)

    rows = await db.execute(
        select(
            NetflowBucket.src_ip,
            NetflowBucket.dst_ip,
            NetflowBucket.dst_port,
            NetflowBucket.protocol,
            func.sum(NetflowBucket.bytes).label("b"),
            func.sum(NetflowBucket.packets).label("pk"),
            func.sum(NetflowBucket.flows).label("f"),
        )
        .where(*conds, NetflowBucket.src_ip.isnot(None), NetflowBucket.dst_ip.isnot(None))
        .group_by(NetflowBucket.src_ip, NetflowBucket.dst_ip, NetflowBucket.dst_port, NetflowBucket.protocol)
        .order_by(text("b DESC"))
        .limit(limit)
    )
    return [
        {
            "src_ip": r[0],
            "dst_ip": r[1],
            "dst_port": r[2],
            "protocol": _PROTO_NAMES.get(r[3] or 0, f"proto-{r[3]}") if r[3] is not None else None,
            "service": _PORT_SERVICES.get(r[2] or 0),
            "bytes": int(r[4] or 0),
            "packets": int(r[5] or 0),
            "flows": int(r[6] or 0),
        }
        for r in rows.all()
    ]


# --- Admin / Settings ---


@app.get("/api/admin/settings")
async def get_admin_settings():
    """Return the current settings snapshot. Secrets are masked: only an
    is_set flag is returned for password-like fields."""
    return serialize_settings(reveal_secrets=False)


class AdminSettingsIn(BaseModel):
    # Free-form dict; we filter against MANAGED_KEYS in save_settings.
    # Empty string is meaningful (clears the value) — None means "do not change",
    # but BaseModel can't distinguish, so callers should send only fields they
    # want to update.
    sophos_client_id: str | None = None
    sophos_client_secret: str | None = None
    sophos_tenant_id: str | None = None
    firewall_threat_feed_enabled: bool | None = None
    firewall_mdr_feed_enabled: bool | None = None
    firewall_mdr_feed_firewall_ids: str | None = Field(default=None, max_length=4000)
    firewall_mdr_feed_sync_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    o365_tenant_id: str | None = None
    o365_client_id: str | None = None
    o365_client_secret: str | None = None
    m365_login_watch_enabled: bool | None = None
    m365_login_watch_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    m365_login_watch_lookback_minutes: int | None = Field(default=None, ge=5, le=1440)
    hostname_resolve_enabled: bool | None = None
    internal_dns_servers: str | None = Field(default=None, max_length=500)
    hostname_netbios_enabled: bool | None = None
    hostname_cache_ttl_hours: int | None = Field(default=None, ge=1, le=8760)
    hostname_negative_ttl_hours: int | None = Field(default=None, ge=1, le=168)
    firewall_api_enabled: bool | None = None
    firewall_api_host: str | None = Field(default=None, max_length=255)
    firewall_api_port: int | None = Field(default=None, ge=1, le=65535)
    firewall_api_user: str | None = Field(default=None, max_length=128)
    firewall_api_password: str | None = Field(default=None, max_length=256)
    firewall_api_verify_tls: bool | None = None
    firewall_central_sync_enabled: bool | None = None
    mcp_enabled: bool | None = None
    mcp_api_key: str | None = Field(default=None, max_length=200)
    firewall_dhcp_entity: str | None = Field(default=None, max_length=200)
    firewall_dhcp_refresh_seconds: int | None = Field(default=None, ge=60, le=86400)
    host_identity_monitor_enabled: bool | None = None
    host_identity_alarm: bool | None = None
    host_identity_scan_interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    entra_block_enabled: bool | None = None
    entra_block_sync_interval_minutes: int | None = None
    entra_ca_exclude_users: str | None = None
    telegram_enabled: bool | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    telegram_poll_interval_seconds: int | None = None
    teams_outgoing_secret: str | None = None
    teams_incoming_webhook: str | None = None
    maxmind_license_key: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None
    shodan_auto_every_lookup: bool | None = None
    shodan_auto_on_malicious: bool | None = None
    shodan_auto_abuse_threshold: int | None = None
    sophos_intelix_client_id: str | None = None
    sophos_intelix_client_secret: str | None = None
    collector_interval: int | None = Field(default=None, ge=30, le=86400)
    log_level: str | None = None
    dashboard_title: str | None = None
    firewall_log_retention_enabled: bool | None = None
    firewall_log_connection_retention_days: int | None = Field(default=None, ge=1, le=3650)
    firewall_log_retention_days: int | None = Field(default=None, ge=1, le=3650)
    agent_enabled: bool | None = None
    agent_provider: str | None = None
    agent_base_url: str | None = None
    agent_api_key: str | None = None
    agent_model: str | None = None
    agent_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    agent_temperature: float | None = Field(default=None, ge=0, le=2)
    agent_max_tokens: int | None = Field(default=None, ge=1, le=32000)
    agent_structured_output: bool | None = None
    agent_auto_execute: bool | None = None
    agent_learning_enabled: bool | None = None
    agent_learning_threshold: int | None = Field(default=None, ge=1, le=1000)
    agent_language: str | None = Field(default=None, pattern="^(en|de)$")
    agent_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_waf_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_event_enabled: bool | None = None
    agent_event_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    agent_event_types: str | None = Field(default=None, max_length=8000)
    agent_event_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_ips_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_failed_login_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_waf_enabled: bool | None = None
    agent_waf_threshold: int | None = Field(default=None, ge=1, le=10000)
    agent_waf_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    agent_ips_enabled: bool | None = None
    agent_ips_threshold: int | None = Field(default=None, ge=1, le=10000)
    agent_ips_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    agent_anomaly_enabled: bool | None = None
    agent_anomaly_interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    agent_anomaly_hours: int | None = Field(default=None, ge=1, le=720)
    agent_anomaly_min_flows: int | None = Field(default=None, ge=1, le=1000000)
    agent_anomaly_max_ips: int | None = Field(default=None, ge=1, le=200)
    agent_anomaly_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_connanom_enabled: bool | None = None
    agent_connanom_interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    agent_connanom_hours: int | None = Field(default=None, ge=1, le=168)
    agent_connanom_min_score: float | None = Field(default=None, ge=0.0, le=1.0)
    agent_connanom_max_alerts: int | None = Field(default=None, ge=1, le=200)
    agent_conntriage_enabled: bool | None = None
    agent_conntriage_interval_seconds: int | None = Field(default=None, ge=3600, le=604800)
    agent_conntriage_min_score: float | None = Field(default=None, ge=0.0, le=1.0)
    agent_conntriage_max: int | None = Field(default=None, ge=1, le=200)
    agent_conntriage_alarm: bool | None = None
    agent_conntriage_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_failed_login_enabled: bool | None = None
    agent_failed_login_threshold: int | None = Field(default=None, ge=1, le=10000)
    agent_failed_login_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    agent_failed_login_subnet_attempts: int | None = Field(default=None, ge=1, le=10000)
    agent_failed_login_subnet_min_ips: int | None = Field(default=None, ge=2, le=1000)
    agent_failed_login_distributed_enabled: bool | None = None
    agent_failed_login_distributed_window_minutes: int | None = Field(default=None, ge=5, le=10080)
    agent_failed_login_distributed_attempts: int | None = Field(default=None, ge=1, le=100000)
    agent_failed_login_distributed_min_ips: int | None = Field(default=None, ge=2, le=10000)
    agent_failed_login_network_block_enabled: bool | None = None
    agent_failed_login_distributed_system_prompt: str | None = Field(default=None, max_length=20000)
    agent_triage_system_prompt: str | None = Field(default=None, max_length=20000)
    analyst_system_prompt: str | None = Field(default=None, max_length=20000)
    chat_sql_enabled: bool | None = None
    osint_abuseipdb_daily_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_abuseipdb_monthly_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_virustotal_daily_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_virustotal_monthly_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_shodan_daily_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_shodan_monthly_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_greynoise_daily_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_greynoise_monthly_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_intelix_daily_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_intelix_monthly_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_ipinfo_daily_limit: int | None = Field(default=None, ge=0, le=10000000)
    osint_ipinfo_monthly_limit: int | None = Field(default=None, ge=0, le=10000000)


@app.put("/api/admin/settings")
async def update_admin_settings(body: AdminSettingsIn):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if "log_level" in updates:
        lvl = updates["log_level"].upper()
        if lvl not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise HTTPException(status_code=400, detail="invalid log_level")
        updates["log_level"] = lvl
    saved = await save_settings(updates)
    return {"updated": list(saved.keys()), "settings": serialize_settings()}


@app.post("/api/admin/test/sophos")
async def test_sophos_connection():
    """Force a fresh Sophos auth round-trip with the current credentials."""
    if not settings.sophos_client_id or not settings.sophos_client_secret:
        return {"ok": False, "error": "client_id/client_secret not set"}
    sophos_client.reload()
    try:
        await sophos_client._authenticate()
        return {
            "ok": True,
            "tenant_id": sophos_client.tenant_id,
            "data_region": sophos_client.data_region_url,
        }
    except httpx.HTTPStatusError as e:
        return {"ok": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}


@app.post("/api/admin/test/telegram")
async def test_telegram_connection():
    from app.telegram_client import test_telegram
    return await test_telegram()


@app.post("/api/admin/test/entra")
async def test_entra_connection():
    from app.entra_client import entra_client
    return await entra_client.test()


@app.post("/api/admin/entra/sync-now")
async def entra_sync_now():
    """Force an immediate blocklist → Entra named-location sync."""
    from app.entra_client import entra_client
    if not entra_client.configured:
        raise HTTPException(status_code=400, detail="O365 app credentials not set")
    if not settings.entra_block_enabled:
        raise HTTPException(status_code=400, detail="entra_block_enabled is off")
    try:
        return await entra_client.sync_blocklist()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Graph {e.response.status_code}: {e.response.text[:200]}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/entra/ca-policy")
async def get_entra_ca_policy():
    """Current on/off state of the Warroom block policy (for the admin toggle)."""
    from app.entra_client import entra_client
    return await entra_client.get_ca_policy_state()


class CaPolicyToggleIn(BaseModel):
    enabled: bool
    # Optional: set/confirm the excluded break-glass accounts at activation time
    # (comma-separated UPNs or object ids). None = leave the stored value as-is.
    exclude_users: str | None = Field(None, max_length=2000)


@app.post("/api/admin/entra/ca-policy")
async def set_entra_ca_policy(body: CaPolicyToggleIn):
    """Enable (enforce) or disable the Warroom conditional-access block policy."""
    from app.entra_client import entra_client
    if not entra_client.configured:
        raise HTTPException(status_code=400, detail="O365 app credentials not set")
    try:
        return await entra_client.set_ca_policy_state(body.enabled, body.exclude_users)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Graph {e.response.status_code}: {e.response.text[:200]}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/admin/test/o365")
async def test_o365_connection():
    """Fresh M365 auth round-trip + subscription check with current credentials."""
    if not o365_client.configured:
        return {"ok": False, "error": "tenant_id/client_id/client_secret not set"}
    o365_client.reload()
    try:
        await o365_client._authenticate()
        await o365_client._ensure_subscription()
        return {"ok": True, "tenant_id": settings.o365_tenant_id}
    except httpx.HTTPStatusError as e:
        return {"ok": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}


# --- AI Agent ---


def _serialize_decision(r: AgentDecision, alert: Alert | None) -> dict:
    return {
        "id": r.id,
        "alert_id": r.alert_id,
        "source_type": r.source_type,
        "source_ip": r.source_ip,
        "action": r.action,
        "action_args": r.action_args or {},
        "reasoning": r.reasoning,
        "status": r.status,
        "model": r.model,
        "decided_by": r.decided_by,
        "human_comment": r.human_comment,
        "supersedes": r.supersedes,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "decided_at": r.decided_at.isoformat() if r.decided_at else None,
        "error": r.error,
        "alert": {
            "id": alert.id, "type": alert.alert_type, "severity": alert.severity,
            "category": alert.category,
            "description": alert.description, "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "country": alert.attacker_country, "city": alert.attacker_city,
            "agent": alert.managed_agent_name,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            "acknowledged_action": alert.acknowledged_action,
        } if alert else None,
    }


@app.get("/api/agent/decisions")
async def list_agent_decisions(
    status: str | None = Query(default=None),
    decided_by: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AgentDecision).order_by(AgentDecision.created_at.desc())
    if status:
        stmt = stmt.where(AgentDecision.status == status)
    if decided_by:
        stmt = stmt.where(AgentDecision.decided_by == decided_by)
    if action:
        stmt = stmt.where(AgentDecision.action == action)
    stmt = stmt.limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    alert_ids = [r.alert_id for r in rows]
    alerts_by_id: dict[str, Alert] = {}
    if alert_ids:
        ares = await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))
        alerts_by_id = {a.id: a for a in ares.scalars().all()}

    return {"items": [_serialize_decision(r, alerts_by_id.get(r.alert_id)) for r in rows]}


@app.get("/api/agent/decisions/stats")
async def agent_decisions_stats(db: AsyncSession = Depends(get_db)):
    """Counts grouped by status and decided_by, used by the agent page tiles."""
    rows = (await db.execute(
        select(AgentDecision.status, AgentDecision.decided_by, func.count(AgentDecision.id))
        .group_by(AgentDecision.status, AgentDecision.decided_by)
    )).all()
    out = {"total": 0, "by_status": {}, "by_actor": {"agent": 0, "human": 0}}
    for status, actor, cnt in rows:
        out["total"] += cnt
        out["by_status"][status or "unknown"] = out["by_status"].get(status or "unknown", 0) + cnt
        out["by_actor"][actor or "agent"] = out["by_actor"].get(actor or "agent", 0) + cnt
    return out


@app.get("/api/agent/decisions/timeline")
async def agent_decisions_timeline(days: int = Query(default=7, ge=1, le=90), db: AsyncSession = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await db.execute(
        select(
            func.date_trunc("hour", AgentDecision.created_at).label("ts"),
            AgentDecision.decided_by,
            func.count(AgentDecision.id),
        )
        .where(AgentDecision.created_at >= since)
        .group_by(text("1"), AgentDecision.decided_by)
        .order_by(text("1"))
    )).all()
    return [
        {"ts": r[0].isoformat() if r[0] else None, "actor": r[1] or "agent", "count": int(r[2])}
        for r in rows
    ]


@app.get("/api/agent/decisions/{decision_id}")
async def get_agent_decision(decision_id: int, db: AsyncSession = Depends(get_db)):
    rec = await db.get(AgentDecision, decision_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="decision not found")
    alert = await db.get(Alert, rec.alert_id)
    payload = _serialize_decision(rec, alert)
    if alert and alert.raw_data:
        payload["alert"]["raw_data"] = alert.raw_data
    # Chain history: any decisions that supersede this one, and the one this superseded
    chain_q = await db.execute(
        select(AgentDecision).where(
            (AgentDecision.supersedes == decision_id) | (AgentDecision.id == (rec.supersedes or -1))
        ).order_by(AgentDecision.created_at)
    )
    payload["chain"] = [_serialize_decision(r, alert) for r in chain_q.scalars().all()]
    return payload


class DecisionFeedback(BaseModel):
    comment: str | None = Field(None, max_length=2000)


@app.post("/api/agent/decisions/{decision_id}/approve")
async def approve_agent_decision(decision_id: int, body: DecisionFeedback | None = None, db: AsyncSession = Depends(get_db)):
    rec = await db.get(AgentDecision, decision_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="decision not found")
    was_pending = rec.status == "pending"
    if body and body.comment is not None:
        rec.human_comment = body.comment
        await db.commit()
    from app.agent import execute_decision, record_feedback_by_id
    try:
        result = await execute_decision(decision_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    # Learn from this human approval (only count a genuine pending->executed
    # transition, not a re-approve of an already-executed decision).
    if was_pending:
        await record_feedback_by_id(decision_id, approved=True)
    return result


@app.post("/api/agent/decisions/{decision_id}/reject")
async def reject_agent_decision(decision_id: int, body: DecisionFeedback | None = None, db: AsyncSession = Depends(get_db)):
    rec = await db.get(AgentDecision, decision_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="decision not found")
    was_pending = rec.status == "pending"
    rec.status = "rejected"
    rec.decided_at = datetime.now(timezone.utc)
    if body and body.comment is not None:
        rec.human_comment = body.comment
    await db.commit()
    # Learn from this human rejection (subtracts from the pattern's net score).
    if was_pending:
        from app.agent import record_feedback_by_id
        await record_feedback_by_id(decision_id, approved=False)
    return {"ok": True}


class DeclineIn(BaseModel):
    # Full reset wipes the learned pattern; otherwise decline counts as one
    # rejection (net −1) so the pattern can drop below the threshold.
    reset_pattern: bool = False
    comment: str | None = Field(None, max_length=2000)


@app.post("/api/agent/decisions/{decision_id}/decline")
async def decline_agent_decision(decision_id: int, body: DeclineIn | None = None, db: AsyncSession = Depends(get_db)):
    """Decline an already-executed decision after the fact: remove the IP(s)/
    domain/URL it put on the blocklist, mark it 'declined', and correct the
    learner — either record a rejection (net −1) or, if reset_pattern is set,
    forget the whole pattern's statistics."""
    rec = await db.get(AgentDecision, decision_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="decision not found")
    if rec.status != "executed":
        raise HTTPException(status_code=400, detail="only executed decisions can be declined")

    from app.agent import revert_decision, record_feedback_by_id, forget_pattern_for
    try:
        reverted = await revert_decision(decision_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"revert failed: {e}")

    reset = bool(body and body.reset_pattern)
    if reset:
        pattern_reset = await forget_pattern_for(decision_id)
    else:
        pattern_reset = False
        await record_feedback_by_id(decision_id, approved=False)

    rec = await db.get(AgentDecision, decision_id)
    rec.status = "declined"
    rec.decided_at = datetime.now(timezone.utc)
    default_note = "Declined after execution — blocklist entries removed."
    if body and body.comment:
        rec.human_comment = body.comment
    elif not rec.human_comment:
        rec.human_comment = default_note
    await db.commit()

    return {"ok": True, "reverted": reverted, "pattern_reset": pattern_reset}


class BulkApproveIn(BaseModel):
    source_type: str | None = Field(None, max_length=20)
    action: str | None = Field(None, max_length=50)
    comment: str | None = Field(None, max_length=2000)


@app.post("/api/agent/decisions/approve-all-pending")
async def approve_all_pending(body: BulkApproveIn | None = None, db: AsyncSession = Depends(get_db)):
    """Bulk-approve every pending decision (optionally filtered by source_type
    and/or action). Each is executed via the same code path as a single
    approve — whitelist guards and other safety checks still apply per row."""
    q = select(AgentDecision).where(AgentDecision.status == "pending")
    if body and body.source_type:
        q = q.where(AgentDecision.source_type == body.source_type)
    if body and body.action:
        q = q.where(AgentDecision.action == body.action)
    q = q.order_by(AgentDecision.id.asc())
    rows = (await db.execute(q)).scalars().all()
    if not rows:
        return {"ok": True, "approved": 0, "failed": 0, "ids": [], "errors": []}

    if body and body.comment:
        for rec in rows:
            rec.human_comment = body.comment
        await db.commit()

    from app.agent import execute_decision, record_feedback_by_id
    approved: list[int] = []
    errors: list[dict[str, str | int]] = []
    for rec in rows:
        try:
            await execute_decision(rec.id)
            approved.append(rec.id)
            # Each bulk-approved row is a human approval — feed the learner.
            await record_feedback_by_id(rec.id, approved=True)
        except Exception as e:
            errors.append({"id": rec.id, "error": str(e)[:200]})
            logger.warning(f"bulk-approve: decision {rec.id} failed: {e}")
    return {
        "ok": True,
        "approved": len(approved),
        "failed": len(errors),
        "ids": approved,
        "errors": errors,
    }


@app.get("/api/agent/approval-patterns")
async def list_approval_patterns(db: AsyncSession = Depends(get_db)):
    """Learned approval patterns for the self-learning auto-approval feature.
    net = approvals − rejections; eligible = learning ON and net ≥ threshold."""
    rows = (await db.execute(select(AgentApprovalPattern))).scalars().all()
    threshold = max(1, int(settings.agent_learning_threshold or 3))
    enabled = bool(settings.agent_learning_enabled)

    def _ser(p: AgentApprovalPattern) -> dict:
        net = (p.approvals or 0) - (p.rejections or 0)
        return {
            "id": p.id, "signature": p.signature, "source_type": p.source_type,
            "action": p.action, "rule": p.rule,
            "approvals": p.approvals, "rejections": p.rejections,
            "auto_approved": p.auto_approved, "net": net,
            "eligible": enabled and net >= threshold,
            "last_decided_at": p.last_decided_at.isoformat() if p.last_decided_at else None,
        }

    patterns = sorted((_ser(p) for p in rows), key=lambda x: (-x["net"], -x["id"]))
    return {"enabled": enabled, "threshold": threshold, "patterns": patterns}


@app.delete("/api/agent/approval-patterns/{pattern_id}")
async def delete_approval_pattern(pattern_id: int, db: AsyncSession = Depends(get_db)):
    """Forget a learned pattern — removes its accumulated approvals/rejections
    so it must be re-learned from scratch."""
    p = await db.get(AgentApprovalPattern, pattern_id)
    if p is None:
        raise HTTPException(status_code=404, detail="pattern not found")
    await db.delete(p)
    await db.commit()
    return {"ok": True}


_ALLOWED_HUMAN_ACTIONS = {"block_ip", "acknowledge", "isolate", "no_action"}


class HumanDecisionIn(BaseModel):
    alert_id: str | None = Field(None, max_length=255)
    source_type: str = Field("alert", max_length=20)
    source_ip: str | None = Field(None, max_length=45)
    action: str = Field(..., min_length=1, max_length=50)
    action_args: dict | None = None
    comment: str | None = Field(None, max_length=2000)
    supersedes: int | None = None
    execute: bool = True


@app.post("/api/agent/decisions/manual")
async def manual_agent_decision(body: HumanDecisionIn, db: AsyncSession = Depends(get_db)):
    """Record a human-initiated decision. For Sophos alerts pass ``alert_id``;
    for WAF override pass ``source_type='waf'`` + ``source_ip``."""
    if body.action not in _ALLOWED_HUMAN_ACTIONS:
        raise HTTPException(status_code=400, detail=f"action must be one of {sorted(_ALLOWED_HUMAN_ACTIONS)}")

    alert = None
    if body.alert_id:
        alert = await db.get(Alert, body.alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
    elif body.source_type == "waf":
        if not body.source_ip:
            raise HTTPException(status_code=400, detail="source_ip required for waf decision")
    else:
        raise HTTPException(status_code=400, detail="either alert_id or (source_type=waf + source_ip) required")

    rec = AgentDecision(
        alert_id=body.alert_id,
        source_type=body.source_type,
        source_ip=body.source_ip,
        action=body.action,
        action_args=body.action_args or {},
        reasoning="(manual decision)",
        status="pending",
        decided_by="human",
        human_comment=body.comment,
        supersedes=body.supersedes,
        model=None,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    if body.supersedes:
        prev = await db.get(AgentDecision, body.supersedes)
        if prev is not None and prev.status in {"pending"}:
            prev.status = "superseded"
            prev.decided_at = datetime.now(timezone.utc)
            await db.commit()

    if body.execute:
        from app.agent import execute_decision, record_feedback_by_id
        try:
            await execute_decision(rec.id)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"recorded but execution failed: {e}")
        # A manual execute is the human endorsing this action for this
        # situation — teach the pattern so similar future ones can auto-run.
        await record_feedback_by_id(rec.id, approved=True)

    await db.refresh(rec)
    return _serialize_decision(rec, alert)


class TriageIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    type: str = Field("auto", max_length=10)  # auto | ip | domain | url
    note: str | None = Field(None, max_length=500)


def _detect_indicator_type(value: str) -> str:
    """Best-effort classification of an OSINT/triage indicator."""
    v = value.strip()
    if re.match(r"^https?://", v, re.IGNORECASE):
        return "url"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "ip"
    if ":" in v and re.match(r"^[0-9a-fA-F:]+$", v):
        return "ip"  # IPv6
    if "/" in v or "?" in v:
        return "url"
    return "domain"


@app.post("/api/agent/triage")
async def agent_triage(body: TriageIn):
    """Hand a single indicator (IP / domain / URL) to the LLM for triage.
    Runs OSINT enrichment, asks the model whether to block, and records a
    pending agent decision (auto-executed if the auto-execute settings allow).
    Used by the OSINT page's 'an KI-Triage übergeben' action."""
    import ipaddress

    value = body.value.strip()
    vtype = body.type if body.type in {"ip", "domain", "url"} else _detect_indicator_type(value)

    if vtype == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid IP address")
    elif vtype == "domain":
        try:
            value = _normalize_domain(value)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"invalid domain: {e}")
    elif vtype == "url":
        try:
            value = _normalize_url(value)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"invalid url: {e}")

    from app.agent import triage_value
    try:
        result = await triage_value(value, vtype, body.note)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"triage failed: {e}")
    return {"ok": True, "type": vtype, "value": value, **result}


@app.get("/api/agent/workflow")
async def get_agent_workflow():
    """Structured description of the LLM-agent workflow for the workflow admin
    page: the decision pipeline plus each stage's editable config (enable,
    thresholds, interval, allowed actions, prompt status). Writes go through the
    normal PUT /api/admin/settings; prompts via /api/admin/agent/default-prompt."""

    def _set(v):  # is this prompt overridden (custom) vs. using the default?
        return bool((getattr(settings, v, "") or "").strip())

    glob = {
        "enabled": settings.agent_enabled,
        "model": settings.agent_model or "local-model",
        "base_url": settings.agent_base_url,
        "provider": settings.agent_provider,
        "structured_output": settings.agent_structured_output,
        "temperature": settings.agent_temperature,
        "max_tokens": settings.agent_max_tokens,
        "auto_execute": settings.agent_auto_execute,
        "interval_seconds": settings.agent_interval_seconds,
        "learning_enabled": settings.agent_learning_enabled,
        "learning_threshold": settings.agent_learning_threshold,
    }

    # step/detail are German fallbacks; the frontend prefers the i18n dict
    # keyed by `key` (agentWorkflow.pipeline.<key>.step/.detail).
    pipeline = [
        {"key": "candidates", "step": "Kandidaten", "detail": "Quelle liefert Kandidaten (Alert / WAF- / IPS- / Login-Events)"},
        {"key": "osint", "step": "OSINT", "detail": "Anreicherung öffentlicher IPs (AbuseIPDB, VirusTotal, Shodan, GreyNoise, Intelix, ipinfo) — Shodan High/Critical-CVE (CVSS >= 7) oder KEV ⇒ Block-Indikator"},
        {"key": "llm", "step": "LLM", "detail": "Strukturierte Abfrage mit Pydantic-Schema (response_format) je Stufen-Prompt"},
        {"key": "validation", "step": "Validierung", "detail": "Pydantic-Validierung + Beschränkung auf erlaubte Aktionen der Stufe"},
        {"key": "persistence", "step": "Persistenz", "detail": "Entscheidung in agent_decisions gespeichert"},
        {"key": "execution", "step": "Ausführung", "detail": "Auto-Execute nur für acknowledge (Master-Switch); Block-Aktionen immer pending zur Freigabe"},
    ]

    stages = [
        {
            "key": "alert", "label": "Sophos Alerts",
            "trigger": "Neue Alarme aus Sophos Central (letzte 24 h)",
            "enabled_key": "agent_enabled",
            "enabled": settings.agent_enabled,
            "prompt_source": "alert", "prompt_key": "agent_system_prompt",
            "prompt_overridden": _set("agent_system_prompt"),
            "allowed_actions": ["block_ip", "acknowledge", "isolate", "no_action"],
            "settings": [
                {"key": "agent_interval_seconds", "label": "Intervall (s)", "value": settings.agent_interval_seconds, "type": "int", "min": 30, "max": 86400},
            ],
            "run_now": "/api/agent/run-now",
        },
        {
            "key": "event", "label": "Central Events",
            "trigger": "Sophos-Central-Event-Stream (Endpoint-Threat/C2/Exploit), gefiltert nach event_type",
            "enabled_key": "agent_event_enabled",
            "enabled": settings.agent_event_enabled,
            "prompt_source": "event", "prompt_key": "agent_event_system_prompt",
            "prompt_overridden": _set("agent_event_system_prompt"),
            "allowed_actions": ["block_ip", "isolate", "acknowledge", "no_action"],
            "settings": [
                {"key": "agent_event_interval_seconds", "label": "Intervall (s)", "value": settings.agent_event_interval_seconds, "type": "int", "min": 30, "max": 86400},
            ],
            "run_now": "/api/agent/event-run-now",
        },
        {
            "key": "waf", "label": "WAF",
            "trigger": "Frische 4xx/5xx-WAF-Events pro IP · Pfad-Cache (Redis, 24 h) erkennt Wordlist-/Directory-Brute-Force",
            "enabled_key": "agent_waf_enabled",
            "enabled": settings.agent_waf_enabled,
            "prompt_source": "waf", "prompt_key": "agent_waf_system_prompt",
            "prompt_overridden": _set("agent_waf_system_prompt"),
            "allowed_actions": ["block_ip", "no_action"],
            "settings": [
                {"key": "agent_waf_threshold", "label": "Schwelle (24 h)", "value": settings.agent_waf_threshold, "type": "int", "min": 1, "max": 10000},
                {"key": "agent_waf_interval_seconds", "label": "Intervall (s)", "value": settings.agent_waf_interval_seconds, "type": "int", "min": 30, "max": 86400},
            ],
            "run_now": "/api/agent/waf-run-now",
        },
        {
            "key": "ips", "label": "IPS / IDP",
            "trigger": "IDP/IPS-Intrusion-Events pro IP",
            "enabled_key": "agent_ips_enabled",
            "enabled": settings.agent_ips_enabled,
            "prompt_source": "ips", "prompt_key": "agent_ips_system_prompt",
            "prompt_overridden": _set("agent_ips_system_prompt"),
            "allowed_actions": ["block_ip", "no_action"],
            "settings": [
                {"key": "agent_ips_threshold", "label": "Schwelle (24 h)", "value": settings.agent_ips_threshold, "type": "int", "min": 1, "max": 10000},
                {"key": "agent_ips_interval_seconds", "label": "Intervall (s)", "value": settings.agent_ips_interval_seconds, "type": "int", "min": 30, "max": 86400},
            ],
            "run_now": "/api/agent/ips-run-now",
        },
        {
            "key": "anomaly", "label": "FW-Anomalien",
            "trigger": "Isolation-Forest-Anomalien über NetFlow (Volumen/Ports/Nacht) → OSINT-Triage; nicht-schädliche Anomalien werden als 'Verdächtig' markiert",
            "enabled_key": "agent_anomaly_enabled",
            "enabled": settings.agent_anomaly_enabled,
            "prompt_source": "anomaly", "prompt_key": "agent_anomaly_system_prompt",
            "prompt_overridden": _set("agent_anomaly_system_prompt"),
            "allowed_actions": ["block_ip", "no_action"],
            "settings": [
                {"key": "agent_anomaly_interval_seconds", "label": "Intervall (s)", "value": settings.agent_anomaly_interval_seconds, "type": "int", "min": 60, "max": 86400},
                {"key": "agent_anomaly_hours", "label": "NetFlow-Fenster (h)", "value": settings.agent_anomaly_hours, "type": "int", "min": 1, "max": 720},
                {"key": "agent_anomaly_min_flows", "label": "Min. Flows/IP", "value": settings.agent_anomaly_min_flows, "type": "int", "min": 1, "max": 1000000},
                {"key": "agent_anomaly_max_ips", "label": "Max. IPs/Sweep", "value": settings.agent_anomaly_max_ips, "type": "int", "min": 1, "max": 200},
            ],
            "run_now": "/api/agent/anomaly-run-now",
        },
        {
            "key": "failed_login", "label": "Failed-Login (per IP)",
            "trigger": "Fehlgeschlagene Logins pro Quell-IP",
            "enabled_key": "agent_failed_login_enabled",
            "enabled": settings.agent_failed_login_enabled,
            "prompt_source": "failed_login", "prompt_key": "agent_failed_login_system_prompt",
            "prompt_overridden": _set("agent_failed_login_system_prompt"),
            "allowed_actions": ["block_ip", "no_action"],
            "settings": [
                {"key": "agent_failed_login_threshold", "label": "Schwelle (24 h)", "value": settings.agent_failed_login_threshold, "type": "int", "min": 1, "max": 10000},
                {"key": "agent_failed_login_interval_seconds", "label": "Intervall (s)", "value": settings.agent_failed_login_interval_seconds, "type": "int", "min": 30, "max": 86400},
            ],
            "run_now": "/api/agent/failed-login-run-now",
        },
        {
            "key": "failed_login_distributed", "label": "Verteilter Brute-Force",
            "trigger": "Alle Login-Versuche des Fensters → LLM gruppiert nach /24",
            "enabled_key": "agent_failed_login_distributed_enabled",
            "enabled": settings.agent_failed_login_distributed_enabled,
            "prompt_source": "failed_login_distributed", "prompt_key": "agent_failed_login_distributed_system_prompt",
            "prompt_overridden": _set("agent_failed_login_distributed_system_prompt"),
            "allowed_actions": ["block_subnet", "block_ips", "no_action"],
            "settings": [
                {"key": "agent_failed_login_distributed_window_minutes", "label": "Fenster (min)", "value": settings.agent_failed_login_distributed_window_minutes, "type": "int", "min": 5, "max": 10080},
                {"key": "agent_failed_login_distributed_attempts", "label": "Versuche/​/24 (Richtwert)", "value": settings.agent_failed_login_distributed_attempts, "type": "int", "min": 1, "max": 100000},
                {"key": "agent_failed_login_distributed_min_ips", "label": "Distinct-IPs/​/24", "value": settings.agent_failed_login_distributed_min_ips, "type": "int", "min": 2, "max": 10000},
            ],
            "run_now": "/api/agent/failed-login-run-now",
        },
        {
            "key": "triage", "label": "Triage (OSINT-Übergabe)",
            "trigger": "Manuelle Übergabe eines Werts von der OSINT-Seite",
            "enabled_key": None, "enabled": True,
            "prompt_source": "triage", "prompt_key": "agent_triage_system_prompt",
            "prompt_overridden": _set("agent_triage_system_prompt"),
            "allowed_actions": ["block_ip", "block_domain", "block_url", "no_action"],
            "settings": [],
            "run_now": None,
        },
    ]
    return {"global": glob, "pipeline": pipeline, "stages": stages}


@app.post("/api/agent/run-now")
async def agent_run_now():
    """Trigger one immediate pass of the agent loop. Useful for testing
    from the admin UI without waiting for the scheduler."""
    from app.agent import agent_loop
    scheduler.add_job(agent_loop, "date", id="agent_manual", replace_existing=True)
    return {"ok": True}


@app.post("/api/agent/event-run-now")
async def agent_event_run_now():
    """Trigger one immediate pass of the Central-event agent loop. Runs even
    when the event agent is otherwise disabled — admin-initiated."""
    from app.agent import agent_event_loop
    scheduler.add_job(
        agent_event_loop, "date",
        id="agent_event_manual", replace_existing=True,
        kwargs={"force": True},
    )
    return {"ok": True}


@app.post("/api/agent/waf-run-now")
async def agent_waf_run_now(window_minutes: int = Query(default=60, ge=1, le=10080)):
    """Trigger a WAF-agent scan over the past ``window_minutes`` (default 60).
    Runs even when the WAF agent is otherwise disabled — admin-initiated."""
    from app.agent import agent_waf_loop
    scheduler.add_job(
        agent_waf_loop, "date",
        id="agent_waf_manual", replace_existing=True,
        kwargs={"window_minutes": window_minutes, "force": True},
    )
    return {"ok": True, "window_minutes": window_minutes}


@app.post("/api/agent/ips-run-now")
async def agent_ips_run_now(window_minutes: int = Query(default=60, ge=1, le=10080)):
    from app.agent import agent_ips_loop
    scheduler.add_job(
        agent_ips_loop, "date",
        id="agent_ips_manual", replace_existing=True,
        kwargs={"window_minutes": window_minutes, "force": True},
    )
    return {"ok": True, "window_minutes": window_minutes}


@app.post("/api/agent/anomaly-run-now")
async def agent_anomaly_run_now(all: bool = Query(default=False)):
    """Trigger an FW-anomaly agent sweep immediately. Runs even when the sweep
    is otherwise disabled — admin-initiated. ``all=true`` lifts the per-sweep
    IP cap so every not-yet-verdicted anomaly is processed in one run
    (hard safety limit: 100)."""
    from app.agent import agent_anomaly_loop
    scheduler.add_job(
        agent_anomaly_loop, "date",
        id="agent_anomaly_manual", replace_existing=True,
        kwargs={"force": True, "no_cap": bool(all)},
    )
    return {"ok": True, "all": bool(all)}


@app.post("/api/agent/failed-login-run-now")
async def agent_failed_login_run_now(window_minutes: int = Query(default=60, ge=1, le=10080)):
    from app.agent import agent_failed_login_loop
    scheduler.add_job(
        agent_failed_login_loop, "date",
        id="agent_failed_login_manual", replace_existing=True,
        kwargs={"window_minutes": window_minutes, "force": True},
    )
    return {"ok": True, "window_minutes": window_minutes}


@app.post("/api/admin/firewall-retention/run-now")
async def firewall_retention_run_now():
    """Trigger a firewall_logs retention purge now (batched, runs in background).
    Useful for the first big cleanup without waiting for the scheduled run."""
    from app.firewall_retention import purge_firewall_logs
    scheduler.add_job(
        purge_firewall_logs, "date",
        id="firewall_retention_manual", replace_existing=True,
    )
    return {"ok": True}


@app.post("/api/admin/test/agent")
async def test_agent_connection():
    from app.agent import test_connection
    return await test_connection()


@app.get("/api/admin/agent/models")
async def list_agent_models():
    """Pull /v1/models from the configured agent endpoint so the admin UI
    can populate a dropdown of model IDs."""
    from app.agent import list_available_models
    return await list_available_models()


@app.get("/api/admin/agent/default-prompt")
async def get_agent_default_prompt(
    source: str = Query(default="alert"),
    lang: str | None = Query(default=None, pattern="^(en|de)$"),
):
    """Return the bundled fallback system prompt so the admin UI can offer
    'reset to default'. ``source`` is "alert" or any key in agent._RULE_PROMPTS
    (waf, ips, event, failed_login, failed_login_distributed, failed_login_user,
    triage). Language follows ``lang`` if given, else the configured
    agent_language (so the default matches the agent's active language)."""
    from app.agent import default_prompt, _RULE_PROMPTS
    prompt = default_prompt(source, lang)
    if prompt is None:
        valid = ["alert", *sorted(_RULE_PROMPTS)]
        raise HTTPException(
            status_code=400,
            detail=f"unknown source {source!r}; must be one of {valid}",
        )
    return {"default": prompt, "source": source}


@app.post("/api/admin/test/abuseipdb")
async def test_abuseipdb_connection():
    """Cheap probe: query AbuseIPDB for 8.8.8.8."""
    if not settings.abuseipdb_api_key:
        return {"ok": False, "error": "abuseipdb_api_key not set"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": "8.8.8.8"},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
        if resp.status_code == 200:
            return {"ok": True}
        return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}


# --- OSINT-Provider usage telemetry ---


@app.get("/api/admin/stats/osint-usage")
async def osint_usage_stats(days: int = Query(default=30, ge=1, le=365)):
    """Aggregated outbound OSINT-provider call counts. Returns per-provider
    totals (today / this month / window), status breakdown
    (success/no_record/error/cache_hit), cache-hit rate, and quota
    utilization against the configured daily/monthly limits."""
    from app.osint_metrics import query_usage
    return await query_usage(days=days)


@app.post("/api/admin/stats/osint-usage/flush")
async def osint_usage_flush():
    """Force-flush the in-memory provider counter into ``osint_usage``
    immediately. Useful after a manual lookup burst when you don't want to
    wait the full 60s scheduler tick."""
    from app.osint_metrics import flush_to_db
    n = await flush_to_db()
    return {"ok": True, "flushed": n}


@app.get("/api/admin/stats/llm-usage")
async def llm_usage_stats(
    days: int = Query(default=30, ge=1, le=365),
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = Query(default=None),
):
    """Aggregated outbound LLM-call counts: per source (alert/waf/ips/
    failed_login/test), per model, token totals, average latency, plus per-
    source per-day series for the analyzer chart on /stats.html.

    If ``from`` and/or ``to`` (YYYY-MM-DD) are supplied they override
    ``days`` — used by the analyzer card's date pickers."""
    from app.llm_metrics import query_usage

    start: datetime | None = None
    end: datetime | None = None
    if from_:
        try:
            start = datetime.fromisoformat(from_).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"invalid from={from_!r}")
    if to:
        try:
            end = datetime.fromisoformat(to).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"invalid to={to!r}")
    return await query_usage(days=days, start=start, end=end)


@app.post("/api/admin/stats/llm-usage/flush")
async def llm_usage_flush():
    """Force-flush the in-memory LLM counter into ``llm_usage`` immediately."""
    from app.llm_metrics import flush_to_db
    n = await flush_to_db()
    return {"ok": True, "flushed": n}


# --- Cache warmer ---

# Endpoints + default params the dashboard hits with the UI's default
# settings (7-day window, table limits). Each call routes through the
# @cached decorator → Redis stays warm so users never pay the cold price.
# Order matters only insofar as failures are isolated — one bad query
# won't stop the others.
_WARM_TARGETS: list[tuple[str, dict]] = [
    ("get_summary", {}),
    ("get_severity_distribution", {"days": 7}),
    ("get_timeline", {"days": 7}),
    ("get_categories", {"days": 7}),
    ("get_top_attackers", {"days": 7, "limit": 20}),
    ("get_firewall_event_stats", {"days": 7}),
    ("get_attack_map", {"days": 7}),
    # The map now reads the daily rollup, so warming the 30-day range is cheap.
    ("get_attack_map", {"days": 30}),
    ("get_blocked_outbound_stats", {"days": 7}),
    ("get_recent_alerts", {"limit": 200}),
    ("get_recent_events", {"limit": 200}),
    ("get_recent_detections", {"limit": 200}),
    # Optional Query(...) defaults stay as sentinel objects when bypassing
    # FastAPI's DI — pass them explicitly so the SQL sees None.
    ("get_recent_fw_logs", {"limit": 500, "log_type": None}),
    ("get_failed_logins", {"days": 7, "limit": 300}),
    ("get_waf_stats", {"days": 7}),
    ("get_waf_recent", {"days": 7, "limit": 300, "status_class": "4xx_5xx"}),
    ("get_ips_stats", {"days": 7}),
    ("get_ips_recent", {"days": 7, "limit": 300}),
    ("get_endpoints_list", {"limit": 200, "health": None, "isolation": None, "search": None}),
    ("get_endpoints_stats", {}),
]


async def warm_dashboard_cache() -> None:
    """Pre-populate Redis with the heavy dashboard endpoints.

    Calls each cached function with the UI's default parameters so the
    cache key matches what the browser later requests. Runs targets in
    parallel with a small concurrency cap so the DB pool (size 10) isn't
    overwhelmed; failure on one target doesn't block the others.
    """
    import asyncio
    import time

    sem = asyncio.Semaphore(4)
    start = time.monotonic()
    results = {"ok": 0, "fail": 0}

    async def warm_one(name: str, kwargs: dict) -> None:
        func = globals().get(name)
        if func is None:
            logger.warning(f"warmer: target {name!r} not found")
            results["fail"] += 1
            return
        async with sem:
            try:
                async with async_session() as db:
                    await func(db=db, **kwargs)
                results["ok"] += 1
            except Exception as e:
                results["fail"] += 1
                logger.warning(f"warmer: {name} failed: {e}")

    await asyncio.gather(*(warm_one(name, kw) for name, kw in _WARM_TARGETS))
    logger.info(
        f"cache warmer: {results['ok']} ok / {results['fail']} failed "
        f"in {time.monotonic() - start:.2f}s"
    )
