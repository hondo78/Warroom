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
from app.models import HostInventory, HostPort, HostPortEvent, HostPresence, HostScan

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


def _parse_host_el(host) -> dict:
    """Parse one nmap <host> element → {ip, ports, os_guess, hostname, mac, up}."""
    ip = os_guess = hostname = mac = None
    for addr in host.findall("address"):
        t = addr.get("addrtype")
        if t == "ipv4" or (t == "ipv6" and not ip):
            ip = addr.get("addr")
        elif t == "mac":
            mac = addr.get("addr")
    st = host.find("status")
    up = st is None or st.get("state") == "up"
    hn = host.find("./hostnames/hostname")
    if hn is not None:
        hostname = hn.get("name")
    ports: list[dict] = []
    for p in host.findall("./ports/port"):
        pst = p.find("state")
        if pst is None or pst.get("state") != "open":
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
    return {"ip": ip, "ports": ports, "os_guess": os_guess,
            "hostname": hostname, "mac": mac, "up": up}


def _parse(xml_str: str) -> tuple[list[dict], str | None, str | None, str | None]:
    """Single-host parse → (open_ports, os_guess, hostname, mac)."""
    root = ET.fromstring(xml_str)
    host = root.find("host")
    if host is None:
        return [], None, None, None
    h = _parse_host_el(host)
    return h["ports"], h["os_guess"], h["hostname"], h["mac"]


def _parse_hosts(xml_str: str) -> list[dict]:
    """Network parse → one dict per host that is up (has an IP)."""
    root = ET.fromstring(xml_str)
    out = []
    for host in root.findall("host"):
        h = _parse_host_el(host)
        if h["ip"] and h["up"]:
            out.append(h)
    return out


async def _upsert_inventory(db, ip: str, found: list[dict], os_guess, hostname, mac, now):
    """Create/update the long-term inventory row for one host."""
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
            await _upsert_inventory(db, ip, found, os_guess, hostname, mac, now)
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
                await notify(_alert_html(ip, hostname, events),
                             title="Warroom · Host-Scan", event="host_scan")
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


# --- whole-network scan ------------------------------------------------------

# Cap the range so a mistyped prefix can't launch a scan of millions of hosts.
MAX_NET_HOSTS = 4096  # /20 IPv4


def _valid_internal_cidr(cidr: str) -> str:
    """Return the normalized CIDR if it is a scannable private range, else raise."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"invalid network {cidr!r}: {e}")
    # Same exclusions as _valid_internal_ip: is_private alone says True for
    # 127.0.0.0/8, so the network entry point would happily scan the container's
    # own loopback while the single-host entry point refuses the same address.
    if net.is_loopback or net.is_multicast or net.is_unspecified:
        raise ValueError(f"{net} is not a scannable network")
    if not net.is_private:
        raise ValueError(f"{net} is not internal — only private ranges may be scanned")
    if net.num_addresses > MAX_NET_HOSTS:
        raise ValueError(f"{net} is too large ({net.num_addresses} addresses, max {MAX_NET_HOSTS})")
    return str(net)


def _net_args(profile: str) -> list[str]:
    """Network profile args: drop -Pn so nmap does host discovery and only scans
    responsive hosts (scanning every dead address in a range would be far too
    slow)."""
    return [a for a in PROFILES[profile] if a != "-Pn"]


async def start_network_scan(cidr: str, profile: str | None = None) -> dict:
    """Validate + launch a whole-network scan in the background. Discovered hosts
    are added to the inventory and existing ones updated. Returns the scan id."""
    cidr = _valid_internal_cidr(cidr)
    prof = _profile(profile)
    if cidr in _in_progress:
        return {"cidr": cidr, "status": "running", "note": "a scan for this network is already running"}
    async with async_session() as db:
        rec = HostScan(ip=cidr, profile=prof, status="running",
                       arguments=" ".join(_net_args(prof)))
        db.add(rec)
        await db.commit()
        await db.refresh(rec)
        scan_id = rec.id
    _in_progress.add(cidr)
    asyncio.create_task(_execute_network(scan_id, cidr, prof))
    return {"scan_id": scan_id, "cidr": cidr, "profile": prof, "status": "running"}


async def _execute_network(scan_id: int, cidr: str, profile: str) -> None:
    """Background worker: scan a whole network, then upsert every discovered host
    (ports + transitions + inventory). Existing hosts are updated, new ones added."""
    t0 = time.monotonic()
    try:
        cmd = ["nmap", *_net_args(profile), "-oX", "-", cidr]
        timeout = max(60, int(settings.host_nmap_timeout_seconds or 1800))
        async with _sem():
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try:
                    proc.kill(); await proc.wait()
                except Exception:
                    pass
                raise RuntimeError(f"network scan timed out after {timeout}s")
        if proc.returncode != 0:
            raise RuntimeError((err.decode(errors="replace") or f"nmap exit {proc.returncode}")[:400])

        hosts = _parse_hosts(out.decode(errors="replace"))
        now = datetime.now(timezone.utc)
        total_open = 0
        all_events: list[tuple[str, str | None, list[dict]]] = []
        async with async_session() as db:
            for h in hosts:
                ip = h["ip"]
                found = h["ports"]
                total_open += len(found)
                events = await _apply_results(db, ip, found, now)
                await _upsert_inventory(db, ip, found, h["os_guess"], h["hostname"], h["mac"], now)
                if events:
                    all_events.append((ip, h["hostname"], events))
            rec = await db.get(HostScan, scan_id)
            if rec is not None:
                rec.status = "done"
                rec.ports_open = total_open
                rec.os_guess = f"{len(hosts)} host(s) up"   # summary in the run row
                rec.duration_ms = int((time.monotonic() - t0) * 1000)
                rec.finished_at = now
            await db.commit()
        logger.info(f"nmap_scan: network {cidr} ({profile}) → {len(hosts)} host(s) up, "
                    f"{total_open} open port(s), {sum(len(e) for _, _, e in all_events)} change(s)")

        if all_events and settings.host_nmap_alarm:
            try:
                from app.notifications import notify
                alerted = all_events[:20]
                for ip, hostname, events in alerted:
                    await notify(_alert_html(ip, hostname, events),
                             title="Warroom · Host-Scan", event="host_scan")
                # Only the hosts an alert actually went out for. Marking the
                # whole list would tell the operator that hosts 21+ had been
                # reported when nothing was ever sent for them, and the flag is
                # what the UI shows.
                async with async_session() as db:
                    ips = [ip for ip, _, _ in alerted]
                    for ev in (await db.execute(
                        select(HostPortEvent).where(HostPortEvent.ip.in_(ips),
                                                    HostPortEvent.detected_at == now)
                    )).scalars().all():
                        ev.notified = True
                    await db.commit()
            except Exception as e:
                logger.warning(f"nmap_scan: network alarm failed for {cidr}: {e}")
    except Exception as e:
        logger.warning(f"nmap_scan: network scan {scan_id} for {cidr} failed: {e}")
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
        _in_progress.discard(cidr)


# --- live online status (ping sweep) -----------------------------------------

MAX_PRESENCE_HOSTS = 8192


def _internal_only(ips) -> list[str]:
    out = []
    for ip in ips or []:
        try:
            out.append(_valid_internal_ip(ip))
        except ValueError:
            continue
    # de-dup, preserve order
    seen, uniq = set(), []
    for ip in out:
        if ip not in seen:
            seen.add(ip); uniq.append(ip)
    return uniq[:MAX_PRESENCE_HOSTS]


async def presence_sweep(ips: list[str]) -> dict:
    """nmap ping-sweep (-sn, no port scan) over the given internal IPs; mark the
    responsive ones online (host_presence.last_online). Cheap and fast — used for
    the live online status. Returns {checked, online}."""
    targets = _internal_only(ips)
    if not targets:
        return {"checked": 0, "online": 0}
    now = datetime.now(timezone.utc)
    # Discovery: ICMP echo (-PE) + TCP-SYN ping to configured ports. Specifying
    # explicit probes replaces nmap's default set (which SYN-pings 443 / ACK-pings
    # 80 — exactly what firewalls SYN-ACK for phantom hosts). We deliberately omit
    # 80/443 so a gateway answering there doesn't mark a non-existent host online.
    disc = ["-PE"]
    ports = (settings.host_presence_probe_ports or "").replace(" ", "")
    if ports:
        disc.append("-PS" + ports)
    cmd = ["nmap", "-sn", *disc, "-T4", "-n", "--max-retries", "1", "-oX", "-", *targets]
    async with _sem():
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            try:
                proc.kill(); await proc.wait()
            except Exception:
                pass
            raise RuntimeError("presence sweep timed out")
    online = {h["ip"] for h in _parse_hosts(out.decode(errors="replace")) if h["ip"]}
    from app.models import HostPresenceEvent, HostPresenceSnapshot
    async with async_session() as db:
        rows = {p.ip: p for p in (await db.execute(
            select(HostPresence).where(HostPresence.ip.in_(targets)))).scalars().all()}
        for ip in targets:
            is_up = ip in online
            p = rows.get(ip)
            if p is None:
                p = HostPresence(ip=ip)
                db.add(p)
            # Log a transition whenever the state changes (compact history).
            if p.online is None or bool(p.online) != is_up:
                db.add(HostPresenceEvent(ip=ip, online=is_up, at=now))
            p.online = is_up
            p.last_checked = now
            if is_up:
                p.last_online = now
        # Fleet snapshot for the trend chart.
        db.add(HostPresenceSnapshot(checked_at=now, total=len(targets), online=len(online)))
        await db.commit()
    logger.info(f"nmap_scan: presence sweep — {len(online)}/{len(targets)} online")
    return {"checked": len(targets), "online": len(online)}
