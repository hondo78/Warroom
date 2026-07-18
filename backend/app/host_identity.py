"""Host-identity monitoring.

Stores every observed IP↔MAC↔hostname combination long-term and detects when a
binding changes, so identity spoofing / device swaps are caught even across
NetFlow retention. Each change is evaluated (what it means + a severity) and the
security-relevant ones raise a Telegram/Teams alarm.

Change types:
  ip_mac_change   an IP that had MAC A now has a different MAC B  → HIGH
                  (possible ARP spoofing / IP takeover / hardware swap)
  hostname_change the hostname bound to an (ip, mac) changed      → MEDIUM
                  (rename, or identity impersonation)
  mac_moved       a known MAC (device) appears on a new IP        → LOW  (DHCP)
  new_device      a MAC never seen on the network before          → LOW

Only ip_mac_change and hostname_change alarm (they require a prior value to have
changed, so they can't false-positive on a MAC merely being learned late); the
rest are logged for review. The first scan seeds the baseline silently.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.hostname_service import is_internal
from app.models import HostIdentity, HostIdentityEvent, IpHostname

logger = logging.getLogger(__name__)

_ALARM_TYPES = {"ip_mac_change", "hostname_change"}


def _lang() -> str:
    return "en" if (settings.agent_language or "de").lower().startswith("en") else "de"


def _meaning(ev: dict, lang: str) -> str:
    de = lang == "de"
    ip, mac, hn = ev["ip"], ev["mac"], ev.get("hostname") or "?"
    t = ev["type"]
    if t == "ip_mac_change":
        return (f"IP {ip}: MAC von {ev['old']} auf {ev['new']} geändert. "
                f"Eine andere Hardware nutzt jetzt diese IP — möglicher ARP-Spoofing / "
                f"IP-Übernahme oder Geräte-Tausch. Prüfen!" if de else
                f"IP {ip}: MAC changed from {ev['old']} to {ev['new']}. A different device "
                f"now uses this IP — possible ARP spoofing / IP takeover or hardware swap. "
                f"Investigate!")
    if t == "hostname_change":
        return (f"{ip} / {mac}: Hostname von „{ev['old']}“ zu „{ev['new']}“ geändert — "
                f"Umbenennung oder Identitäts-Täuschung." if de else
                f"{ip} / {mac}: hostname changed from \"{ev['old']}\" to \"{ev['new']}\" — "
                f"a rename or identity impersonation.")
    if t == "mac_moved":
        return (f"Gerät {mac} ({hn}) von IP {ev['old']} → {ip} (meist DHCP)." if de else
                f"Device {mac} ({hn}) moved from IP {ev['old']} → {ip} (usually DHCP).")
    return (f"Neues Gerät im Netzwerk: MAC {mac} an IP {ip} ({hn})." if de else
            f"New device on the network: MAC {mac} at IP {ip} ({hn}).")


def _alert_html(ev: dict, lang: str) -> str:
    icon = {"high": "🔴", "medium": "🟠"}.get(ev["sev"], "🟢")
    head = {"ip_mac_change": ("MAC-Wechsel an IP" if lang == "de" else "MAC change on IP"),
            "hostname_change": ("Hostname-Änderung" if lang == "de" else "Hostname change")}.get(
                ev["type"], ev["type"])
    return f"{icon} <b>{head}</b>\n{_meaning(ev, lang)}"


async def scan(force: bool = False) -> dict:
    """Compare the current IP↔MAC↔hostname bindings against the long-term store,
    record + evaluate changes, and alarm on the security-relevant ones."""
    if not settings.host_identity_monitor_enabled and not force:
        return {"skipped": "disabled"}
    now = datetime.now(timezone.utc)

    async with async_session() as db:
        rows = (await db.execute(
            select(IpHostname).where(IpHostname.mac.isnot(None))
        )).scalars().all()
        current = [(r.ip, r.mac.lower(), r.hostname) for r in rows
                   if r.ip and r.mac and is_internal(r.ip)]

        idents = (await db.execute(select(HostIdentity))).scalars().all()
        seeding = len(idents) == 0
        combo = {(i.ip, i.mac): i for i in idents}
        macs_by_ip: dict[str, list] = defaultdict(list)
        ips_by_mac: dict[str, list] = defaultdict(list)
        for i in idents:
            macs_by_ip[i.ip].append(i)
            ips_by_mac[i.mac].append(i)

        events: list[dict] = []
        for ip, mac, hostname in current:
            ex = combo.get((ip, mac))
            if ex is not None:
                ex.last_seen = now
                ex.times_seen = (ex.times_seen or 0) + 1
                if (hostname and ex.hostname and hostname != ex.hostname and not seeding):
                    events.append({"type": "hostname_change", "sev": "medium",
                                   "ip": ip, "mac": mac, "hostname": hostname,
                                   "old": ex.hostname, "new": hostname})
                if hostname:
                    ex.hostname = hostname
                continue
            # A new (ip, mac) combination.
            db.add(HostIdentity(ip=ip, mac=mac, hostname=hostname,
                                first_seen=now, last_seen=now, times_seen=1))
            if seeding:
                continue
            prior_ip_macs = [i for i in macs_by_ip.get(ip, []) if i.mac != mac]
            prior_mac_ips = [i for i in ips_by_mac.get(mac, []) if i.ip != ip]
            if prior_ip_macs:
                old = max(prior_ip_macs, key=lambda i: i.last_seen or now)
                events.append({"type": "ip_mac_change", "sev": "high",
                               "ip": ip, "mac": mac, "hostname": hostname,
                               "old": f"{old.mac} ({old.hostname or '?'})",
                               "new": f"{mac} ({hostname or '?'})"})
            elif prior_mac_ips:
                old = max(prior_mac_ips, key=lambda i: i.last_seen or now)
                events.append({"type": "mac_moved", "sev": "low",
                               "ip": ip, "mac": mac, "hostname": hostname,
                               "old": old.ip, "new": ip})
            else:
                events.append({"type": "new_device", "sev": "low",
                               "ip": ip, "mac": mac, "hostname": hostname})

        lang = _lang()
        for ev in events:
            db.add(HostIdentityEvent(
                ip=ev["ip"], mac=ev["mac"], hostname=ev.get("hostname"),
                event_type=ev["type"], severity=ev["sev"],
                detail=_meaning(ev, lang), detected_at=now,
                notified=False))
        await db.commit()

    alarms = 0
    if not seeding and events and settings.host_identity_alarm:
        from app.notifications import notify
        for ev in [e for e in events if e["type"] in _ALARM_TYPES][:20]:
            try:
                await notify(_alert_html(ev, lang), title="Warroom · Host-Identität")
                alarms += 1
            except Exception as e:
                logger.warning(f"host-identity alarm failed: {e}")

    logger.info(f"host-identity scan: {len(current)} bindings, "
                f"{'seeded' if seeding else str(len(events)) + ' change(s)'}, {alarms} alarm(s)")
    return {"bindings": len(current), "seeding": seeding,
            "events": len(events), "alarms": alarms}
