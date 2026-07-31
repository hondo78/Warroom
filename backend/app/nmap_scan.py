"""On-demand nmap port scanning of internal hosts.

Opt-in (``host_nmap_enabled``) and deliberately restricted: only PRIVATE /
internal IPs may ever be scanned (hard guard), and we use an unprivileged TCP
connect scan (``-sT``) so no raw-socket capability is needed inside the
container. Each scan run is persisted (``host_scans``); the resulting open ports
are diffed against the stored state (``host_ports``) so transitions — a service
that appeared or disappeared — are recorded as ``host_port_events`` for the
long-term timeline and optionally alarmed.

nmap XML is parsed with the stdlib (no extra dependency).
"""

import asyncio
import ipaddress
import logging
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.models import HostInventory, HostPort, HostPortEvent, HostScan

logger = logging.getLogger(__name__)

# nmap argument sets per profile. All use -sT (connect scan, no root) + -Pn
# (skip host discovery so a host that drops ping is still scanned).
PROFILES: dict[str, list[str]] = {
    "quick":   ["-sT", "-sV", "--top-ports", "1000", "-T4", "-Pn"],
    "full":    ["-sT", "-sV", "-p-", "-T4", "-Pn"],
    "scripts": ["-sT", "-sV", "-sC", "--top-ports", "1000", "-T4", "-Pn"],
}
DEFAULT_PROFILE = "quick"

# Bounded concurrency + per-IP dedup so a burst of scan requests can't fork a
# process per host or scan the same host twice at once.
_semaphore: asyncio.Semaphore | None = None
_in_progress: set[str] = set()


def _sem() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(max(1, int(settings.host_nmap_max_concurrent or 2)))
    return _semaphore


def _valid_internal_ip(ip: str) -> str:
    """Return the normalized IP if it is a scannable private/internal address,
    else raise ValueError. This is the security boundary — never scan public IPs."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ValueError(f"invalid IP address: {ip!r}")
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
        raise ValueError(f"{ip} is not a scannable host")
    if not (addr.is_private or addr.is_link_local):
        raise ValueError(f"{ip} is not internal — only private IPs may be scanned")
    return str(addr)


def _profile(name: str | None) -> str:
    return name if name in PROFILES else (settings.host_nmap_default_profile or DEFAULT_PROFILE)


async def _run_nmap(ip: str, profile: str) -> tuple[str, str]:
    """Run nmap and return (xml_output, command_string). Raises on failure/timeout."""
    cmd = ["nmap", *PROFILES[profile], "-oX", "-", ip]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    timeout = max(30, int(settings.host_nmap_timeout_seconds or 1800))
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        raise RuntimeError(f"scan timed out after {timeout}s")
    if proc.returncode != 0:
        raise RuntimeError((err.decode(errors="replace") or f"nmap exit {proc.returncode}")[:400])
    return out.decode(errors="replace"), " ".join(cmd)


def _parse(xml_str: str) -> tuple[list[dict], str | None, str | None, str | None]:
    """Parse nmap XML → (open_ports, os_guess, hostname, mac)."""
    ports: list[dict] = []
    os_guess = hostname = mac = None
    root = ET.fromstring(xml_str)
    host = root.find("host")
    if host is None:
        return ports, os_guess, hostname, mac
    for addr in host.findall("address"):
        if addr.get("addrtype") == "mac":
            mac = addr.get("addr")
    hn = host.find("./hostnames/hostname")
    if hn is not None:
        hostname = hn.get("name")
    for p in host.findall("./ports/port"):
        st = p.find("state")
        if st is None or st.get("state") != "open":
            continue
        svc = p.find("service")
        ports.append({
            "port": int(p.get("portid")),
            "proto": p.get("protocol") or "tcp",
            "service": (svc.get("name") if svc is not None else None),
            "product": (svc.get("product") if svc is not None else None),
            "version": (svc.get("version") if svc is not None else None),
        })
    osmatch = host.find("./os/osmatch")
    if osmatch is not None:
        os_guess = osmatch.get("name")
    return ports, os_guess, hostname, mac


def _svc_label(p: dict) -> str:
    bits = [p.get("service") or "?"]
    if p.get("product"):
        bits.append(p["product"] + (f" {p['version']}" if p.get("version") else ""))
    return " ".join(bits)


async def _apply_results(db, ip: str, found: list[dict], now) -> list[dict]:
    """Diff the scan's open ports against stored host_ports; write transitions to
    host_port_events; update host_ports. Returns the list of change events."""
    existing = {(hp.port, hp.proto): hp for hp in (await db.execute(
        select(HostPort).where(HostPort.ip == ip)
    )).scalars().all()}
    found_keys = {(f["port"], f["proto"]) for f in found}
    events: list[dict] = []

    for f in found:
        key = (f["port"], f["proto"])
        svc = _svc_label(f)
        hp = existing.get(key)
        if hp is None:
            db.add(HostPort(ip=ip, port=f["port"], proto=f["proto"], state="open",
                            service=f["service"], product=f["product"], version=f["version"],
                            first_seen=now, last_seen=now, last_state_change=now))
            events.append({"port": f["port"], "proto": f["proto"], "event_type": "opened",
                           "service": f["service"], "detail": f"{f['port']}/{f['proto']} open ({svc})"})
        else:
            reopened = hp.state != "open"
            old_svc = _svc_label({"service": hp.service, "product": hp.product, "version": hp.version})
            hp.last_seen = now
            if reopened:
                hp.state = "open"
                hp.last_state_change = now
                events.append({"port": f["port"], "proto": f["proto"], "event_type": "opened",
                               "service": f["service"], "detail": f"{f['port']}/{f['proto']} re-opened ({svc})"})
            elif svc != old_svc and (f["service"] or f["product"]):
                events.append({"port": f["port"], "proto": f["proto"], "event_type": "service_change",
                               "service": f["service"],
                               "detail": f"{f['port']}/{f['proto']}: {old_svc} → {svc}"})
            hp.service, hp.product, hp.version = f["service"], f["product"], f["version"]

    # Ports previously open but absent now → closed.
    for key, hp in existing.items():
        if key in found_keys or hp.state != "open":
            continue
        hp.state = "closed"
        hp.last_state_change = now
        hp.last_seen = now
        events.append({"port": hp.port, "proto": hp.proto, "event_type": "closed",
                       "service": hp.service,
                       "detail": f"{hp.port}/{hp.proto} no longer open (was {_svc_label({'service': hp.service, 'product': hp.product, 'version': hp.version})})"})

    for ev in events:
        db.add(HostPortEvent(ip=ip, port=ev["port"], proto=ev["proto"],
                             event_type=ev["event_type"], service=ev.get("service"),
                             detail=ev.get("detail"), detected_at=now))
    return events


def _alert_html(ip: str, hostname: str | None, events: list[dict]) -> str:
    en = (settings.agent_language or "de").lower().startswith("en")
    who = f"{hostname} (<code>{ip}</code>)" if hostname else f"<code>{ip}</code>"
    head = "🔎 <b>Host port changes</b>" if en else "🔎 <b>Host-Port-Änderungen</b>"
    lines = [head, who]
    icon = {"opened": "🟢", "closed": "🔴", "service_change": "🟡"}
    for ev in events[:15]:
        lines.append(f"{icon.get(ev['event_type'], '•')} {ev['detail']}")
    return "\n".join(lines)


async def start_scan(ip: str, profile: str | None = None) -> dict:
    """Validate + create the scan row and launch it in the background. Returns
    {scan_id, ip, profile, status} immediately (poll the scan for results)."""
    ip = _valid_internal_ip(ip)
    prof = _profile(profile)
    if ip in _in_progress:
        return {"ip": ip, "status": "running", "note": "a scan for this host is already running"}
    async with async_session() as db:
        rec = HostScan(ip=ip, profile=prof, status="running",
                       arguments=" ".join(PROFILES[prof]))
        db.add(rec)
        await db.commit()
        await db.refresh(rec)
        scan_id = rec.id
    _in_progress.add(ip)
    asyncio.create_task(_execute(scan_id, ip, prof))
    return {"scan_id": scan_id, "ip": ip, "profile": prof, "status": "running"}


async def _execute(scan_id: int, ip: str, profile: str) -> None:
    """Background worker: run nmap, persist ports + transitions, finalize + alarm."""
    t0 = time.monotonic()
    try:
        async with _sem():
            xml_str, args = await _run_nmap(ip, profile)
        found, os_guess, hostname, mac = _parse(xml_str)
        now = datetime.now(timezone.utc)
        async with async_session() as db:
            events = await _apply_results(db, ip, found, now)
            # Upsert the long-term inventory record.
            inv = await db.get(HostInventory, ip)
            if inv is None:
                inv = HostInventory(ip=ip, first_seen=now)
                db.add(inv)
            inv.last_seen = now
            inv.last_scan_at = now
            inv.open_ports = len(found)
            if os_guess:
                inv.os_guess = os_guess
            if hostname and not inv.hostname:
                inv.hostname = hostname
            if mac:
                inv.mac = mac
            rec = await db.get(HostScan, scan_id)
            if rec is not None:
                rec.status = "done"
                rec.ports_open = len(found)
                rec.os_guess = os_guess
                rec.arguments = args
                rec.duration_ms = int((time.monotonic() - t0) * 1000)
                rec.finished_at = now
            await db.commit()
        logger.info(f"nmap_scan: {ip} ({profile}) → {len(found)} open, {len(events)} change(s)")
        if events and settings.host_nmap_alarm:
            try:
                from app.notifications import notify
                await notify(_alert_html(ip, hostname, events), title="Warroom · Host-Scan")
                async with async_session() as db:
                    for ev in (await db.execute(
                        select(HostPortEvent).where(HostPortEvent.ip == ip,
                                                    HostPortEvent.detected_at == now)
                    )).scalars().all():
                        ev.notified = True
                    await db.commit()
            except Exception as e:
                logger.warning(f"nmap_scan: alarm failed for {ip}: {e}")
    except Exception as e:
        logger.warning(f"nmap_scan: scan {scan_id} for {ip} failed: {e}")
        try:
            async with async_session() as db:
                rec = await db.get(HostScan, scan_id)
                if rec is not None:
                    rec.status = "error"
                    rec.error = str(e)[:500]
                    rec.duration_ms = int((time.monotonic() - t0) * 1000)
                    rec.finished_at = datetime.now(timezone.utc)
                    await db.commit()
        except Exception:
            pass
    finally:
        _in_progress.discard(ip)
