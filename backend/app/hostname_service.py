"""Hostname resolution for internal (private) IPs.

Shows a friendly name wherever an internal IP appears. Resolution is multi-source
and best-effort, tried in order and cached in ``ip_hostnames``:

  1. Sophos endpoints  — the managed-device inventory (ipv4 → hostname). Instant.
  2. Reverse DNS (PTR)  — the configured internal DNS server(s), else the system
                          resolver. Covers servers/printers with PTR records.
  3. NetBIOS (NBSTAT)   — a UDP/137 node-status query; the workstation name of a
                          reachable Windows host.

DNS/NetBIOS can block for seconds, so the request path NEVER resolves live: the
API returns whatever is already cached and pushes unknown IPs onto a Redis set
that a background worker drains. Positive hits are cached for a week, misses for
a few hours so a host that later comes online still gets picked up.
"""
import asyncio
import ipaddress
import logging
import socket
import struct
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.geoip_service import get_redis
from app.models import Endpoint, IpHostname

logger = logging.getLogger(__name__)

_PENDING_KEY = "hostnames:pending"
_WORKER_BATCH = 40
_WORKER_CONCURRENCY = 8


def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback and not a.is_link_local and not a.is_unspecified


# --- resolution sources --------------------------------------------------------

async def _from_endpoints(ips: list[str]) -> dict[str, str]:
    if not ips:
        return {}
    async with async_session() as db:
        rows = (await db.execute(
            select(Endpoint.ipv4, Endpoint.hostname)
            .where(Endpoint.ipv4.in_(ips), Endpoint.hostname.isnot(None))
        )).all()
    return {ip: hn for ip, hn in rows if ip and hn}


def _reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    """PTR lookup. Uses the configured internal DNS server(s) via dnspython when
    set (the container's default resolver usually can't resolve private ranges),
    otherwise the system resolver."""
    servers = [s.strip() for s in (settings.internal_dns_servers or "").split(",") if s.strip()]
    if servers:
        try:
            import dns.resolver
            import dns.reversename
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = servers
            r.lifetime = timeout
            r.timeout = timeout
            ans = r.resolve(dns.reversename.from_address(ip), "PTR")
            name = str(ans[0]).rstrip(".")
            return name or None
        except Exception:
            return None
    # System resolver fallback (works for public + any range the host can resolve).
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host or None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def _netbios_name(ip: str, timeout: float = 1.5) -> str | None:
    """NetBIOS node-status (NBSTAT) query → the host's UNIQUE workstation name.
    Skips group names (e.g. the workgroup) via the NAME_FLAGS group bit."""
    if not settings.hostname_netbios_enabled:
        return None
    # NBSTAT query for the wildcard name "*" (encoded as 'CKAA…').
    header = struct.pack(">HHHHHH", 0x4741, 0x0000, 1, 0, 0, 0)
    q = header + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00" + struct.pack(">HH", 0x0021, 0x0001)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (ip, 137))
        data, _ = s.recvfrom(2048)
    except Exception:
        return None
    finally:
        s.close()
    try:
        if len(data) < 57:
            return None
        n = data[56]
        off = 57
        fallback = None
        for _ in range(n):
            if off + 18 > len(data):
                break
            name = data[off:off + 15].decode("ascii", "replace").strip().strip("\x00").strip()
            suffix = data[off + 15]
            flags = int.from_bytes(data[off + 16:off + 18], "big")
            is_group = bool(flags & 0x8000)
            off += 18
            if not name or name == "__MSBROWSE__" or not name.isprintable():
                continue
            # Workstation service (suffix 0x00), unique (not a group) → the host name.
            if suffix == 0x00 and not is_group:
                return name
            if fallback is None and not is_group:
                fallback = name
        return fallback
    except Exception:
        return None


import time as _time
_dhcp_cache: dict = {"map": {}, "at": 0.0}


async def get_dhcp_map(force: bool = False) -> dict[str, str]:
    """Cached IP→hostname map from the Sophos Firewall DHCP config (XML API).
    Returns {} when the firewall API is disabled; keeps the last good map on a
    transient fetch error."""
    if not settings.firewall_api_enabled:
        return {}
    now = _time.monotonic()
    ttl = max(60, int(settings.firewall_dhcp_refresh_seconds or 600))
    if not force and _dhcp_cache["map"] and (now - _dhcp_cache["at"]) < ttl:
        return _dhcp_cache["map"]
    try:
        from app.sfos_client import fetch_dhcp_map
        m = await fetch_dhcp_map()
        _dhcp_cache["map"] = m
        _dhcp_cache["at"] = now
        logger.info(f"DHCP map from firewall: {len(m)} IP↔hostname mapping(s)")
        return m
    except Exception as e:
        logger.warning(f"DHCP map fetch failed: {e}")
        return _dhcp_cache["map"]


async def _resolve_one(ip: str) -> tuple[str | None, str | None]:
    """Return (hostname, source) for one internal IP, trying each source in order:
    Sophos endpoints → reverse DNS → NetBIOS → firewall DHCP."""
    # 1) Sophos endpoints
    ep = await _from_endpoints([ip])
    if ep.get(ip):
        return ep[ip], "sophos"
    loop = asyncio.get_event_loop()
    # 2) reverse DNS (off-thread — it blocks). Keep the FQDN; the UI can shorten.
    dns_name = await loop.run_in_executor(None, _reverse_dns, ip)
    if dns_name:
        return dns_name, "dns"
    # 3) NetBIOS
    nb = await loop.run_in_executor(None, _netbios_name, ip)
    if nb:
        return nb, "netbios"
    # 4) Firewall DHCP mapping (reserved/lease client names)
    if settings.firewall_api_enabled:
        dm = await get_dhcp_map()
        if dm.get(ip):
            return dm[ip], "dhcp"
    return None, None


# --- cache + queue -------------------------------------------------------------

def _fresh(row: IpHostname, now: datetime) -> bool:
    if row.source == "manual":
        return True                      # operator-set names never expire
    if row.resolved_at is None:
        return False
    ttl = settings.hostname_cache_ttl_hours if row.hostname else settings.hostname_negative_ttl_hours
    return (now - row.resolved_at) < timedelta(hours=max(1, ttl))


async def lookup_cached(ips: list[str]) -> dict[str, dict]:
    """Fast, DB-only. Returns {ip: {hostname, source}} for internal IPs known via
    the Sophos inventory or a fresh cache row. Unknown/stale IPs are omitted (the
    caller queues them). Never does live DNS/NetBIOS."""
    internal = sorted({ip for ip in ips if ip and is_internal(ip)})
    if not internal:
        return {}
    now = datetime.now(timezone.utc)
    out: dict[str, dict] = {}

    async with async_session() as db:
        rows = (await db.execute(select(IpHostname).where(IpHostname.ip.in_(internal)))).scalars().all()
    cache = {r.ip: r for r in rows}
    unresolved: list[str] = []
    for ip in internal:
        r = cache.get(ip)
        if r is not None and _fresh(r, now):
            if r.hostname:
                out[ip] = {"hostname": r.hostname, "source": r.source}
            continue
        unresolved.append(ip)

    # Sophos inventory is authoritative + instant — fold it in directly (also
    # covers first-seen IPs before the worker runs).
    if unresolved:
        ep = await _from_endpoints(unresolved)
        for ip, hn in ep.items():
            out[ip] = {"hostname": hn, "source": "sophos"}
    return out


async def queue_for_resolution(ips: list[str]) -> None:
    """Push internal IPs that lookup_cached couldn't answer onto the worker set."""
    if not settings.hostname_resolve_enabled:
        return
    todo = sorted({ip for ip in ips if ip and is_internal(ip)})
    if not todo:
        return
    redis = await get_redis()
    if redis:
        try:
            await redis.sadd(_PENDING_KEY, *todo)
        except Exception as e:
            logger.debug(f"hostname queue failed: {e}")


async def _upsert(ip: str, hostname: str | None, source: str | None) -> None:
    now = datetime.now(timezone.utc)
    async with async_session() as db:
        row = await db.get(IpHostname, ip)
        if row is not None and row.source == "manual":
            return                       # never overwrite an operator-set name
        if row is None:
            db.add(IpHostname(ip=ip, hostname=hostname, source=source, resolved_at=now))
        else:
            row.hostname, row.source, row.resolved_at = hostname, source, now
        await db.commit()


async def set_manual(ip: str, hostname: str | None) -> dict:
    """Operator override. A non-empty hostname is stored as source='manual' and
    is never overwritten by the auto-resolver; an empty hostname clears the
    manual entry so automatic resolution can take over again."""
    if not is_internal(ip):
        raise ValueError("only internal (private) IPs can be named manually")
    hostname = (hostname or "").strip()[:255] or None
    now = datetime.now(timezone.utc)
    async with async_session() as db:
        row = await db.get(IpHostname, ip)
        if hostname is None:
            if row is not None:
                await db.delete(row)     # clear → auto-resolver may re-fill it
            await db.commit()
            return {"ip": ip, "hostname": None, "source": None}
        if row is None:
            db.add(IpHostname(ip=ip, hostname=hostname, source="manual", resolved_at=now))
        else:
            row.hostname, row.source, row.resolved_at = hostname, "manual", now
        await db.commit()
    return {"ip": ip, "hostname": hostname, "source": "manual"}


async def hostname_resolve_worker() -> dict:
    """Drain a batch of pending IPs, resolve each, and cache the result."""
    if not settings.hostname_resolve_enabled:
        return {"skipped": "disabled"}
    redis = await get_redis()
    if not redis:
        return {"skipped": "no redis"}
    try:
        batch = await redis.spop(_PENDING_KEY, _WORKER_BATCH)
    except Exception as e:
        logger.debug(f"hostname worker spop failed: {e}")
        return {"error": str(e)[:120]}
    ips = [b.decode() if isinstance(b, (bytes, bytearray)) else b for b in (batch or [])]
    ips = [ip for ip in ips if is_internal(ip)]
    if not ips:
        return {"resolved": 0}

    sem = asyncio.Semaphore(_WORKER_CONCURRENCY)

    async def _do(ip):
        async with sem:
            hn, src = await _resolve_one(ip)
            await _upsert(ip, hn, src)
            return 1 if hn else 0

    results = await asyncio.gather(*[_do(ip) for ip in ips])
    hits = sum(results)
    logger.info(f"hostname worker: resolved {hits}/{len(ips)} internal IP(s)")
    return {"processed": len(ips), "resolved": hits}
