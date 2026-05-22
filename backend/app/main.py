import hmac
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, text, case, literal_column
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cached
from app.collector import collect_all
from app.config import settings
from app.database import async_session, ensure_schema, get_db
from app.geoip_service import get_redis
from fastapi.responses import PlainTextResponse

from app.models import Alert, AppSetting, BlockedIp, Detection, Endpoint, Event, FirewallLocation, FirewallLog, GeoIPCache, NetflowBucket, NetflowIfaceBucket
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


async def verify_api_key(x_api_key: str | None = Header(default=None)):
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
    # Merge DB overrides on top of .env defaults before any client uses settings.
    await apply_overrides_to_settings()
    sophos_client.reload()
    scheduler.add_job(collect_all, "interval", seconds=settings.collector_interval, id="collector")
    scheduler.start()
    # Run initial collection after short delay
    scheduler.add_job(collect_all, "date", id="initial_collect")
    logger.info(f"Collector scheduled every {settings.collector_interval}s")
    yield
    scheduler.shutdown()
    await sophos_client.aclose()


app = FastAPI(title="Warroom API", lifespan=lifespan, dependencies=[Depends(verify_api_key)])


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
@cached(ttl=60)
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
        GROUP BY threat_ip, attacker_lat, attacker_lon, attacker_country, attacker_city
        ORDER BY cnt DESC
        LIMIT 500
    """)
    alert_rows = (await db.execute(alert_sql, {"since": since})).all()

    # Attackers from Firewall syslog
    fw_sql = text(f"""
        SELECT
            ({fw_threat_expr}) AS threat_ip,
            attacker_lat, attacker_lon,
            attacker_country, attacker_city,
            COUNT(*) AS cnt,
            MAX(severity) AS max_severity,
            MIN(created_at) AS first_seen,
            MAX(created_at) AS last_seen,
            MAX(attacker_asn) AS asn,
            MAX(attacker_org) AS org,
            array_agg(DISTINCT threat_name) FILTER (WHERE threat_name IS NOT NULL) AS threats,
            array_agg(DISTINCT action)      FILTER (WHERE action IS NOT NULL)      AS actions,
            array_agg(DISTINCT log_type)    FILTER (WHERE log_type IS NOT NULL)    AS log_types,
            array_agg(DISTINCT destination_port::text) FILTER (WHERE destination_port IS NOT NULL) AS dest_ports,
            array_agg(DISTINCT user_name)   FILTER (WHERE user_name IS NOT NULL)   AS users,
            array_agg(DISTINCT firewall_name) FILTER (WHERE firewall_name IS NOT NULL) AS firewalls,
            bool_or({fw_in_expr})  AS has_inbound,
            bool_or({fw_out_expr}) AS has_outbound
        FROM firewall_logs
        WHERE created_at >= :since
          AND attacker_lat IS NOT NULL
          AND attacker_lon IS NOT NULL
        GROUP BY threat_ip, attacker_lat, attacker_lon, attacker_country, attacker_city
        ORDER BY cnt DESC
        LIMIT 500
    """)
    fw_rows = (await db.execute(fw_sql, {"since": since})).all()

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


# --- Firewall Stats ---

@app.get("/api/stats/firewall-events")
@cached(ttl=60)
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
            }
            for b in rows
        ],
    }


@app.post("/api/firewall/block-ip")
async def block_ip(body: BlockIpIn, db: AsyncSession = Depends(get_db)):
    import ipaddress
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")

    existing = await db.execute(select(BlockedIp).where(BlockedIp.ip == body.ip))
    entry = existing.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if entry is None:
        entry = BlockedIp(ip=body.ip, comment=body.comment, blocked_at=now)
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
        db.add(BlockedIp(ip=ip, comment=body.comment, blocked_at=now))
        added.append(ip)
    await db.commit()

    return {
        "ok": True,
        "added": added,
        "skipped": skipped,
        "invalid": invalid,
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
    rows = (await db.execute(select(BlockedIp.ip).order_by(BlockedIp.ip))).scalars().all()
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


@app.get("/api/detections/recent")
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
    ips = {r[0] for r in rows if r[0]}
    if ips:
        bres = await db.execute(select(BlockedIp).where(BlockedIp.ip.in_(ips)))
        blocked_set = {b.ip: b for b in bres.scalars().all()}

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
@cached(ttl=60)
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

    top_attacks_sql = text(f"""
        SELECT COALESCE(threat_name, raw_data->>'attack', raw_data->>'attack_type', raw_data->>'reason', raw_data->>'log_subtype') AS attack,
               COUNT(*) AS cnt
        FROM firewall_logs
        WHERE created_at >= :since AND {_WAF_FILTER_SQL} AND {_WAF_ATTACK_FILTER_SQL}
          AND COALESCE(threat_name, raw_data->>'attack', raw_data->>'attack_type', raw_data->>'reason', raw_data->>'log_subtype') IS NOT NULL
        GROUP BY attack
        ORDER BY cnt DESC
        LIMIT 10
    """)
    attacks = (await db.execute(top_attacks_sql, {"since": since})).all()

    return {
        "total": int(row[0] or 0),
        "last_24h": int(row[1] or 0),
        "blocked": int(row[2] or 0),
        "unique_sources": int(row[3] or 0),
        "unique_hosts": int(row[4] or 0),
        "total_all": int(row[5] or 0),
        "allowed_all": int(row[5] or 0) - int(row[0] or 0),
        "top_attackers": [
            {"ip": r[0], "country": r[1], "city": r[2], "count": int(r[3])}
            for r in attackers
        ],
        "top_hosts": [{"host": r[0], "count": int(r[1])} for r in hosts],
        "top_attacks": [{"attack": r[0], "count": int(r[1])} for r in attacks],
    }


@app.get("/api/firewall-logs/waf/recent")
async def get_waf_recent(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=200, ge=1, le=1000),
    include_allowed: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    attack_filter_clause = "" if include_allowed else f"AND {_WAF_ATTACK_FILTER_SQL}"
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
            action,
            message,
            threat_name,
            attacker_country,
            attacker_city,
            COALESCE(raw_data->>'domain', raw_data->>'website', raw_data->>'host') AS host,
            COALESCE(raw_data->>'httpmethod', raw_data->>'method') AS http_method,
            COALESCE(raw_data->>'httpquery', raw_data->>'url', raw_data->>'querystring', raw_data->>'request') AS http_query,
            COALESCE(raw_data->>'httpresp_code', raw_data->>'status_code', raw_data->>'response_code') AS http_status,
            COALESCE(raw_data->>'reason', raw_data->>'attack', raw_data->>'attack_type') AS reason,
            COALESCE(raw_data->>'useragent', raw_data->>'user_agent') AS user_agent,
            COALESCE(raw_data->>'referer', raw_data->>'referrer') AS referer,
            raw_data->>'log_component' AS log_component,
            raw_data->>'log_subtype' AS log_subtype
        FROM firewall_logs
        WHERE created_at >= :since AND {_WAF_FILTER_SQL} {attack_filter_clause}
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
@cached(ttl=60)
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


# --- Manual Collection Trigger ---

@app.post("/api/collect")
async def trigger_collection():
    scheduler.add_job(collect_all, "date", id="manual_collect", replace_existing=True)
    return {"status": "collection triggered"}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


# --- OSINT lookup ---


@app.get("/api/osint/{ip}")
async def osint_lookup(ip: str, force: bool = Query(default=False)):
    """Run AbuseIPDB / VirusTotal / Shodan / GreyNoise / ipinfo in parallel
    for a given IP. Results are cached in Redis for 1h. Pass ?force=true to
    bypass the cache."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")

    from app.osint import lookup as osint_lookup_fn
    return await osint_lookup_fn(ip, force=force)


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
    maxmind_license_key: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None
    sophos_intelix_client_id: str | None = None
    sophos_intelix_client_secret: str | None = None
    collector_interval: int | None = Field(default=None, ge=30, le=86400)
    log_level: str | None = None
    dashboard_title: str | None = None


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
