import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.geoip_service import lookup_ip
from app.models import Alert, Event, Detection, Endpoint, FirewallLocation, O365AuditLog
from app.o365_client import o365_client
from app.sophos_client import sophos_client

logger = logging.getLogger(__name__)


def _parse_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _extract_source_ip(item: dict) -> str | None:
    for key in ("source_info.ip", "sourceIp", "source", "srcIp"):
        parts = key.split(".")
        val = item
        for part in parts:
            if isinstance(val, dict):
                val = val.get(part)
            else:
                val = None
                break
        if val and isinstance(val, str):
            return val
    # Try nested data
    data = item.get("data", {})
    if isinstance(data, dict):
        for key in ("source_ip", "sourceIp", "src_ip"):
            if data.get(key):
                return data[key]
    return None


_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _extract_ips_from_description(item: dict) -> tuple[str | None, str | None]:
    """Extract source and destination IPs from Firewall alert descriptions.

    Sophos formats: 'from source X.X.X.X to destination Y.Y.Y.Y'
    Returns (source_ip, destination_ip/threat_ip).
    """
    desc = item.get("description", "")
    if not desc:
        return None, None

    # Try structured pattern first
    m = re.search(r"source\s+(\d+\.\d+\.\d+\.\d+).*?destination\s+(\d+\.\d+\.\d+\.\d+)", desc)
    if m:
        return m.group(1), m.group(2)

    # Fallback: find all IPs in description
    ips = _IP_RE.findall(desc)
    if len(ips) >= 2:
        return ips[0], ips[1]
    elif len(ips) == 1:
        return ips[0], None

    return None, None


async def collect_all():
    from app.config import settings
    if not settings.sophos_client_id or not settings.sophos_client_secret:
        logger.warning("Sophos credentials not configured, skipping collection")
        return

    logger.info("Starting Sophos data collection...")

    async with async_session() as db:
        # Determine last fetch time
        last_alert = await db.execute(
            select(func.max(Alert.created_at))
        )
        last_alert_time = last_alert.scalar()

        last_event = await db.execute(
            select(func.max(Event.created_at))
        )
        last_event_time = last_event.scalar()

        from_date = None
        if last_alert_time or last_event_time:
            latest = max(filter(None, [last_alert_time, last_event_time]))
            from_date = latest - timedelta(minutes=5)

        # First run: fetch all alerts (no from_date filter)
        try:
            alerts = await sophos_client.get_alerts(from_date)
            await _process_alerts(db, alerts)
        except Exception as e:
            logger.error(f"Failed to collect alerts: {e}")

        try:
            events = await sophos_client.get_events(from_date)
            await _process_events(db, events)
        except Exception as e:
            logger.error(f"Failed to collect events: {e}")

        try:
            detections = await sophos_client.get_detections(from_date)
            await _process_detections(db, detections)
        except Exception as e:
            logger.error(f"Failed to collect detections: {e}")

        # The SFOS XML API (firewall_api_host) is the source of truth about the
        # firewall now; the Central inventory sync only re-creates duplicate map
        # pins, so it's opt-in and off by default.
        if settings.firewall_central_sync_enabled:
            try:
                firewalls = await sophos_client.get_firewalls()
                await _sync_firewalls(db, firewalls)
            except Exception as e:
                logger.error(f"Failed to sync firewalls: {e}")

        try:
            endpoints = await sophos_client.get_endpoints()
            await _sync_endpoints(db, endpoints)
        except Exception as e:
            logger.error(f"Failed to sync endpoints: {e}")

    logger.info("Collection cycle complete")


async def _process_alerts(db: AsyncSession, alerts: list[dict]):
    new_count = 0
    for item in alerts:
        alert_id = item.get("id")
        if not alert_id:
            continue

        existing = await db.execute(select(Alert).where(Alert.id == alert_id))
        if existing.scalar_one_or_none():
            continue

        # Extract IPs: try structured fields first, then parse description
        source_ip = _extract_source_ip(item)
        destination_ip = None

        if not source_ip:
            desc_src, desc_dst = _extract_ips_from_description(item)
            source_ip = desc_src
            destination_ip = desc_dst

        # For firewall ATP alerts, the destination IP is the threat/attacker
        # Use destination IP for GeoIP if available, otherwise source
        threat_ip = destination_ip or source_ip
        geo = await lookup_ip(threat_ip, db) if threat_ip else None

        alert = Alert(
            id=alert_id,
            alert_type=item.get("type"),
            severity=item.get("severity", "").lower(),
            category=item.get("category"),
            description=item.get("description"),
            source_ip=source_ip,
            destination_ip=destination_ip,
            tenant_id=item.get("tenant", {}).get("id") if isinstance(item.get("tenant"), dict) else None,
            managed_agent_name=item.get("managedAgent", {}).get("name") if isinstance(item.get("managedAgent"), dict) else None,
            created_at=_parse_dt(item.get("raisedAt") or item.get("created_at")),
            raw_data=item,
            attacker_lat=geo["lat"] if geo else None,
            attacker_lon=geo["lon"] if geo else None,
            attacker_country=geo["country"] if geo else None,
            attacker_city=geo["city"] if geo else None,
        )
        db.add(alert)
        new_count += 1

    await db.commit()
    logger.info(f"Processed {len(alerts)} alerts ({new_count} new)")


async def _process_events(db: AsyncSession, events: list[dict]):
    for item in events:
        event_id = item.get("id")
        if not event_id:
            continue

        existing = await db.execute(select(Event).where(Event.id == event_id))
        if existing.scalar_one_or_none():
            continue

        source_ip = _extract_source_ip(item)
        geo = await lookup_ip(source_ip, db) if source_ip else None

        event = Event(
            id=event_id,
            event_type=item.get("type"),
            severity=item.get("severity", "").lower(),
            name=item.get("name"),
            source_ip=source_ip,
            destination_ip=item.get("destination", {}).get("ip") if isinstance(item.get("destination"), dict) else None,
            group_name=item.get("group"),
            created_at=_parse_dt(item.get("created_at")),
            raw_data=item,
            attacker_lat=geo["lat"] if geo else None,
            attacker_lon=geo["lon"] if geo else None,
            attacker_country=geo["country"] if geo else None,
            attacker_city=geo["city"] if geo else None,
        )
        db.add(event)

    await db.commit()
    logger.info(f"Processed {len(events)} events")


async def _process_detections(db: AsyncSession, detections: list[dict]):
    for item in detections:
        det_id = item.get("id")
        if not det_id:
            continue

        existing = await db.execute(select(Detection).where(Detection.id == det_id))
        if existing.scalar_one_or_none():
            continue

        source_ip = _extract_source_ip(item)
        geo = await lookup_ip(source_ip, db) if source_ip else None

        detection = Detection(
            id=det_id,
            detection_type=item.get("type"),
            severity=item.get("severity", "").lower(),
            description=item.get("description"),
            source_ip=source_ip,
            device_name=item.get("managedAgent", {}).get("name") if isinstance(item.get("managedAgent"), dict) else None,
            created_at=_parse_dt(item.get("created_at")),
            raw_data=item,
            attacker_lat=geo["lat"] if geo else None,
            attacker_lon=geo["lon"] if geo else None,
            attacker_country=geo["country"] if geo else None,
            attacker_city=geo["city"] if geo else None,
        )
        db.add(detection)

    await db.commit()
    logger.info(f"Processed {len(detections)} detections")


async def _sync_endpoints(db: AsyncSession, endpoints: list[dict]):
    """Upsert endpoint inventory. Sophos endpoint UUIDs are stable PKs."""
    upserted = 0
    for item in endpoints:
        ep_id = item.get("id")
        if not ep_id:
            continue

        os_obj = item.get("os") or {}
        health = item.get("health") or {}
        isolation = item.get("isolation") or {}
        encryption = item.get("encryption") or {}
        ipv4_list = item.get("ipv4Addresses") or []
        mac_list = item.get("macAddresses") or []

        existing = await db.execute(select(Endpoint).where(Endpoint.id == ep_id))
        ep = existing.scalar_one_or_none()

        fields = {
            "hostname": item.get("hostname"),
            "endpoint_type": item.get("type"),
            "os_platform": os_obj.get("platform"),
            "os_name": os_obj.get("name"),
            "os_major_version": str(os_obj.get("majorVersion")) if os_obj.get("majorVersion") is not None else None,
            "ipv4": ipv4_list[0] if ipv4_list else None,
            "mac": mac_list[0] if mac_list else None,
            "last_seen_at": _parse_dt(item.get("lastSeenAt")),
            "health_overall": (health.get("overall") if isinstance(health, dict) else None),
            "health_threats": _nested_status(health, "threats"),
            "health_services": _nested_status(health, "services"),
            "isolation_status": isolation.get("status") if isinstance(isolation, dict) else None,
            "isolation_last_enabled_at": _parse_dt(isolation.get("lastEnabledAt") if isinstance(isolation, dict) else None),
            "tamper_protection_enabled": item.get("tamperProtectionEnabled"),
            "encryption_status": _nested_status(encryption, "volumes"),
            "online": item.get("online"),
            "raw_data": item,
            "updated_at": datetime.now(timezone.utc),
        }

        if ep:
            for k, v in fields.items():
                setattr(ep, k, v)
        else:
            db.add(Endpoint(id=ep_id, **fields))
        upserted += 1

    await db.commit()
    logger.info(f"Synced {upserted} endpoints")


def _nested_status(parent: dict | None, key: str) -> str | None:
    """Sophos health/encryption objects often nest a {"status": "..."}."""
    if not isinstance(parent, dict):
        return None
    sub = parent.get(key)
    if isinstance(sub, dict):
        return sub.get("status")
    if isinstance(sub, str):
        return sub
    return None


def _clean_o365_ip(raw: str | None) -> str | None:
    """O365 ClientIP comes as '1.2.3.4', '1.2.3.4:5678' or '[2a02::1]:443' —
    strip the port so GeoIP and blocklists get a plain address."""
    if not raw:
        return None
    ip = raw.strip()
    if ip.startswith("["):                       # [ipv6]:port
        ip = ip[1:].split("]", 1)[0]
    elif ip.count(":") == 1 and "." in ip:       # v4:port
        ip = ip.split(":", 1)[0]
    return ip or None


def _o365_extended_prop(item: dict, name: str) -> str | None:
    for prop in item.get("ExtendedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == name:
            return prop.get("Value")
    return None


async def collect_o365():
    """Poll Microsoft 365 login audit records (Management Activity API).

    Scheduled like collect_all but independent of the Sophos credentials —
    idles silently when the O365 app registration isn't configured yet.
    """
    if not o365_client.configured:
        logger.debug("O365 credentials not configured, skipping collection")
        return

    logger.info("Starting O365 audit-log collection...")
    async with async_session() as db:
        last = await db.execute(select(func.max(O365AuditLog.created_at)))
        last_time = last.scalar()

        now = datetime.now(timezone.utc)
        # Audit blobs trail real time by up to ~30 min, so look back past the
        # newest stored record. The API allows at most a 24h window.
        if last_time:
            start = max(last_time - timedelta(minutes=45), now - timedelta(hours=24))
        else:
            start = now - timedelta(hours=24)   # first run: 24h backfill

        try:
            records = await o365_client.get_login_records(start, now)
            await _process_o365_logins(db, records)
        except Exception as e:
            logger.error(f"Failed to collect O365 audit logs: {e}")

    logger.info("O365 collection cycle complete")


async def _process_o365_logins(db: AsyncSession, records: list[dict]):
    new_count = 0
    for item in records:
        rec_id = item.get("Id")
        if not rec_id:
            continue

        existing = await db.execute(select(O365AuditLog).where(O365AuditLog.id == rec_id))
        if existing.scalar_one_or_none():
            continue

        operation = item.get("Operation") or ""
        client_ip = _clean_o365_ip(item.get("ClientIP") or item.get("ClientIPAddress"))
        geo = await lookup_ip(client_ip, db) if client_ip else None
        created = _parse_dt(item.get("CreationTime"))
        user_id = item.get("UserId")
        logon_error = item.get("LogonError")
        failed = operation == "UserLoginFailed"

        db.add(O365AuditLog(
            id=rec_id,
            operation=operation,
            workload=item.get("Workload"),
            user_id=user_id,
            client_ip=client_ip,
            result_status=item.get("ResultStatus"),
            logon_error=logon_error,
            user_agent=(_o365_extended_prop(item, "UserAgent") or "")[:512] or None,
            application_id=item.get("ApplicationId"),
            created_at=created,
            raw_data=item,
            attacker_lat=geo["lat"] if geo else None,
            attacker_lon=geo["lon"] if geo else None,
            attacker_country=geo["country"] if geo else None,
            attacker_city=geo["city"] if geo else None,
        ))

        # Failed logins additionally become Alerts so they show up on the
        # attack map and get picked up by the generic AI-agent loop.
        if failed:
            db.add(Alert(
                id=f"o365-{rec_id}",
                alert_type="O365LoginFailed",
                severity="medium",
                category="o365",
                description=(
                    f"M365 login failed: {user_id or 'unknown user'} "
                    f"from {client_ip or 'unknown IP'}"
                    + (f" ({logon_error})" if logon_error else "")
                ),
                source_ip=client_ip,
                created_at=created,
                raw_data=item,
                attacker_lat=geo["lat"] if geo else None,
                attacker_lon=geo["lon"] if geo else None,
                attacker_country=geo["country"] if geo else None,
                attacker_city=geo["city"] if geo else None,
            ))
        new_count += 1

    await db.commit()
    logger.info(f"Processed {len(records)} O365 login records ({new_count} new)")


async def _sync_firewalls(db: AsyncSession, firewalls: list[dict]):
    for fw in firewalls:
        name = fw.get("name", "")
        ext_ips = fw.get("externalIpv4Addresses", [])
        ext_ip = ext_ips[0] if ext_ips else None

        # Check if firewall already exists by name
        existing = await db.execute(
            select(FirewallLocation).where(FirewallLocation.name == name)
        )
        fw_entry = existing.scalar_one_or_none()

        # Resolve GeoIP for external IP
        geo = await lookup_ip(ext_ip, db) if ext_ip else None

        if fw_entry:
            # Update IP and geo if changed
            if ext_ip and ext_ip != fw_entry.ip:
                fw_entry.ip = ext_ip
                if geo:
                    fw_entry.lat = geo["lat"]
                    fw_entry.lon = geo["lon"]
                    fw_entry.country = geo["country"]
                    fw_entry.city = geo["city"]
        else:
            if geo:
                new_fw = FirewallLocation(
                    name=name,
                    ip=ext_ip,
                    lat=geo["lat"],
                    lon=geo["lon"],
                    country=geo["country"],
                    city=geo["city"],
                )
                db.add(new_fw)
                logger.info(f"Added firewall location: {name} ({ext_ip}) -> {geo['city']}, {geo['country']}")
            elif ext_ip:
                logger.warning(f"Could not resolve GeoIP for firewall {name} ({ext_ip})")

    await db.commit()
    logger.info(f"Synced {len(firewalls)} firewalls")
