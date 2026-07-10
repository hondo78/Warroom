"""M365 login watch — alerts on sign-ins from new devices or new locations.

Maintains a per-user baseline (``m365_login_profiles``) of the devices and
countries each user has signed in from. Every successful ``UserLoggedIn``
audit record outside that baseline raises a **pending revoke-sessions
decision** — the operator gets a Telegram approval prompt (approve = revoke
all sessions via Graph, reject = dismiss) and, when configured, a Teams info
message. The dashboard's agent card offers the same approve/reject.

First run: if the baseline table is empty, the ENTIRE audit-log history is
seeded silently (no alerts) — otherwise every known device would fire once.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, text

from app.config import settings
from app.database import async_session
from app.models import M365LoginProfile

logger = logging.getLogger(__name__)


def _device_props(raw: dict) -> dict[str, str]:
    """DeviceProperties is a list of {Name, Value} pairs → plain dict."""
    out: dict[str, str] = {}
    for p in (raw or {}).get("DeviceProperties") or []:
        name, value = p.get("Name"), p.get("Value")
        if name and value:
            out[str(name)] = str(value)
    return out


def _fingerprint(raw: dict, user_agent: str | None) -> tuple[str, str] | None:
    """(device_key, device_label) for a login record.

    Prefers the stable Entra device id; falls back to OS|Browser, then to the
    raw user agent. Returns None when nothing usable is present (those logins
    can't be device-checked)."""
    props = _device_props(raw)
    label_bits = [b for b in (props.get("DisplayName"), props.get("OS"), props.get("BrowserType")) if b]
    label = " · ".join(label_bits) or (user_agent or "?")[:120]
    if props.get("Id"):
        return props["Id"].lower(), label
    if props.get("OS") or props.get("BrowserType"):
        return f"{props.get('OS', '?')}|{props.get('BrowserType', '?')}".lower(), label
    if user_agent:
        return f"ua:{user_agent[:180].lower()}", label
    return None


def _reasoning(lang: str, user: str, new_device: str | None, device_label: str | None,
               new_country: str | None, city: str | None, ip: str | None) -> str:
    loc = f"{new_country}{' / ' + city if city else ''}" if new_country else None
    if lang == "de":
        parts = [f"M365-Anmeldung von {user}:"]
        if new_device:
            parts.append(f"NEUES Gerät: {device_label or new_device}.")
        if loc:
            parts.append(f"NEUER Standort: {loc}.")
        parts.append(f"IP: {ip or '?'}.")
        parts.append("Freigabe widerruft ALLE Sessions des Benutzers (erneute Anmeldung überall nötig).")
    else:
        parts = [f"M365 sign-in by {user}:"]
        if new_device:
            parts.append(f"NEW device: {device_label or new_device}.")
        if loc:
            parts.append(f"NEW location: {loc}.")
        parts.append(f"IP: {ip or '?'}.")
        parts.append("Approving revokes ALL of the user's sessions (re-login required everywhere).")
    return " ".join(parts)


async def m365_login_watch(force: bool = False) -> dict:
    """One watch pass. Returns a summary dict (handy for the run-now endpoint)."""
    if not settings.m365_login_watch_enabled and not force:
        return {"skipped": "disabled"}

    now = datetime.now(timezone.utc)
    lookback = timedelta(minutes=max(5, settings.m365_login_watch_lookback_minutes))

    async with async_session() as db:
        seeded = (await db.execute(
            text("SELECT EXISTS (SELECT 1 FROM m365_login_profiles)")
        )).scalar()
        # Seed mode processes the whole history silently; normal mode only the
        # recent window (overlap is fine — known pairs never re-alert).
        where_ts = "" if not seeded else "AND ingested_at >= :since"
        rows = (await db.execute(text(f"""
            SELECT user_id, client_ip, user_agent, attacker_country, attacker_city,
                   created_at, raw_data
            FROM o365_audit_logs
            WHERE operation = 'UserLoggedIn'
              AND result_status = 'Success'
              AND user_id IS NOT NULL
              {where_ts}
            ORDER BY created_at ASC
        """), ({} if not seeded else {"since": now - lookback}))).all()

    if not rows:
        return {"seed": not seeded, "logins": 0, "alerts": 0}

    # Load the known pairs for the affected users in one query.
    users = sorted({r[0] for r in rows})
    async with async_session() as db:
        known_rows = (await db.execute(
            select(M365LoginProfile).where(M365LoginProfile.user_id.in_(users))
        )).scalars().all()
    known: dict[tuple, M365LoginProfile] = {
        (k.user_id, k.kind, k.value): k for k in known_rows
    }
    seen_new: set[tuple] = set()          # pairs discovered within this batch
    alerts: list[dict[str, Any]] = []

    async with async_session() as db:
        for user, ip, ua, country, city, created_at, raw in rows:
            fp = _fingerprint(raw or {}, ua)
            loc_key = (country or "").strip().upper() or None

            new_device = new_location = None
            device_label = None
            for kind, value, label in (
                ("device", fp[0] if fp else None, fp[1] if fp else None),
                ("location", loc_key, f"{country}{' / ' + city if city else ''}" if loc_key else None),
            ):
                if not value:
                    continue
                key = (user, kind, value)
                if key in known:
                    k = known[key]
                    row_db = await db.get(M365LoginProfile, k.id)
                    if row_db is not None:
                        if created_at and (row_db.last_seen is None or created_at > row_db.last_seen):
                            row_db.last_seen = created_at
                        row_db.seen_count = (row_db.seen_count or 0) + 1
                    continue
                if key in seen_new:
                    continue
                seen_new.add(key)
                db.add(M365LoginProfile(
                    user_id=user, kind=kind, value=value, label=(label or "")[:255],
                    first_seen=created_at or now, last_seen=created_at or now,
                ))
                if kind == "device":
                    new_device, device_label = value, label
                else:
                    new_location = loc_key
            if (new_device or new_location) and seeded:
                alerts.append({
                    "user": user, "ip": ip, "country": country, "city": city,
                    "new_device": new_device, "device_label": device_label,
                    "new_location": new_location, "created_at": created_at,
                })
        await db.commit()

    if not seeded:
        logger.info(f"m365_watch: baseline seeded silently — {len(seen_new)} profile(s) "
                    f"from {len(rows)} historic login(s), no alerts")
        return {"seed": True, "logins": len(rows), "profiles": len(seen_new), "alerts": 0}

    # Raise one pending revoke-sessions decision per alerting login. The shared
    # decision pipeline handles Telegram approval buttons + learned auto-approval.
    lang = "de" if settings.agent_language == "de" else "en"
    for a in alerts:
        reasoning = _reasoning(lang, a["user"], a["new_device"], a["device_label"],
                               a["new_location"], a["city"], a["ip"])
        try:
            from app.agent import _store_rule_decision
            await _store_rule_decision(
                source_type="m365_login", ip=a["ip"],
                action="revoke_sessions", reasoning=reasoning,
                args={"target_user": a["user"]},
                context={
                    "rule": "new_device" if a["new_device"] else "new_location",
                    "new_device": a["device_label"], "new_location": a["new_location"],
                    "country": a["country"], "city": a["city"],
                    "login_at": a["created_at"].isoformat() if a["created_at"] else None,
                },
            )
        except Exception as e:
            logger.warning(f"m365_watch: decision store failed for {a['user']}: {e}")
            continue
        # Teams gets an informational card (no buttons there — approval happens
        # via Telegram or the dashboard). Telegram already gets the button prompt.
        if settings.teams_incoming_webhook:
            try:
                from app.notifications import send_teams
                await send_teams(reasoning, title="Warroom · M365-Login")
            except Exception as e:
                logger.warning(f"m365_watch: teams notify failed: {e}")

    if alerts:
        logger.info(f"m365_watch: {len(alerts)} new-device/location alert(s) raised")
    return {"seed": False, "logins": len(rows), "new_profiles": len(seen_new),
            "alerts": len(alerts)}
