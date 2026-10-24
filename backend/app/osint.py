"""OSINT lookups for IPs, domains and URLs.

Each provider is queried independently — failures of one source do not break
the others. Results are merged into a flat dict so the frontend can render
them in a uniform card. Results are cached in Redis for 1h to avoid burning
free-tier rate limits when the user clicks the same value repeatedly.
"""
import asyncio
import base64
import ipaddress
import json
import logging
import socket
from typing import Any
from urllib.parse import quote

import httpx

from app.config import settings
from app.geoip_service import get_redis

logger = logging.getLogger(__name__)

CACHE_TTL = 3600
TIMEOUT = 12.0


# These reasons indicate the provider returned BEFORE any outbound HTTP call
# was made (missing credentials / OAuth setup), so they don't burn quota and
# shouldn't be counted as 'error'. Everything else from a provider failure
# IS counted so misconfigurations and outages stay visible.
_NO_CALL_REASON_HINTS = ("api key", "client_id", "oauth token")


async def _track(provider: str, coro):
    """Wrap a provider coroutine so its outcome is recorded in
    ``osint_metrics``. Failure of the metrics layer never propagates."""
    try:
        result = await coro
    except Exception:
        try:
            from app.osint_metrics import record
            await record(provider, "error")
        except Exception:
            pass
        raise

    try:
        from app.osint_metrics import record
        if isinstance(result, dict):
            if result.get("available") is False:
                reason = (result.get("reason") or "").lower()
                if not any(h in reason for h in _NO_CALL_REASON_HINTS):
                    await record(provider, "error")
            elif result.get("no_record"):
                await record(provider, "no_record")
            else:
                await record(provider, "success")
    except Exception:
        pass
    return result


async def _record_cache_hit(providers: list[str]) -> None:
    try:
        from app.osint_metrics import record
        for p in providers:
            await record(p, "cache_hit")
    except Exception:
        pass


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


async def _abuseipdb(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    if not settings.abuseipdb_api_key:
        return {"available": False, "reason": "no API key"}
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        )
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}"}
        d = (r.json() or {}).get("data") or {}
        return {
            "available": True,
            "abuse_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "distinct_users": d.get("numDistinctUsers"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "last_reported": d.get("lastReportedAt"),
            "is_whitelisted": d.get("isWhitelisted"),
            "url": f"https://www.abuseipdb.com/check/{ip}",
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def _virustotal(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    key = getattr(settings, "virustotal_api_key", "")
    if not key:
        return {"available": False, "reason": "no API key"}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
        )
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}"}
        attr = ((r.json() or {}).get("data") or {}).get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation"),
            "as_owner": attr.get("as_owner"),
            "asn": attr.get("asn"),
            "country": attr.get("country"),
            "tags": attr.get("tags") or [],
            "last_analysis_date": attr.get("last_analysis_date"),
            "url": f"https://www.virustotal.com/gui/ip-address/{ip}",
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def _shodan(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    key = getattr(settings, "shodan_api_key", "")
    if not key:
        return {"available": False, "reason": "no API key"}
    try:
        r = await client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key, "minify": "true"},
        )
        if r.status_code == 404:
            return {"available": True, "no_record": True, "url": f"https://www.shodan.io/host/{ip}"}
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}"}
        d = r.json() or {}
        return {
            "available": True,
            "ports": d.get("ports") or [],
            "hostnames": d.get("hostnames") or [],
            "domains": d.get("domains") or [],
            "vulns": list((d.get("vulns") or {}).keys()) if isinstance(d.get("vulns"), dict) else (d.get("vulns") or []),
            "tags": d.get("tags") or [],
            "org": d.get("org"),
            "asn": d.get("asn"),
            "country": d.get("country_code"),
            "city": d.get("city"),
            "os": d.get("os"),
            "latitude": d.get("latitude"),
            "longitude": d.get("longitude"),
            "last_update": d.get("last_update"),
            "url": f"https://www.shodan.io/host/{ip}",
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def _greynoise(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """GreyNoise Community API — no key required, generous rate limit."""
    try:
        r = await client.get(f"https://api.greynoise.io/v3/community/{ip}")
        if r.status_code == 404:
            return {"available": True, "noise": False, "classification": "unobserved"}
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}"}
        d = r.json() or {}
        return {
            "available": True,
            "classification": d.get("classification"),  # benign/malicious/unknown
            "noise": d.get("noise"),
            "name": d.get("name"),
            "link": d.get("link"),
            "last_seen": d.get("last_seen"),
            "url": f"https://viz.greynoise.io/ip/{ip}",
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


_INTELIX_TOKEN_KEY = "osint:intelix_token"
_INTELIX_AUTH_URL = "https://api.labs.sophos.com/oauth2/token"
_INTELIX_BASE_URL = "https://de.api.labs.sophos.com"  # EU region


async def _intelix_token(client: httpx.AsyncClient) -> str | None:
    """Fetch (and cache) an OAuth access token for Sophos Intelix."""
    cid = getattr(settings, "sophos_intelix_client_id", "")
    csecret = getattr(settings, "sophos_intelix_client_secret", "")
    if not cid or not csecret:
        return None

    redis = await get_redis()
    if redis:
        try:
            cached = await redis.get(_INTELIX_TOKEN_KEY)
            if cached:
                return cached
        except Exception:
            pass

    try:
        r = await client.post(
            _INTELIX_AUTH_URL,
            data={"grant_type": "client_credentials"},
            auth=(cid, csecret),
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            logger.warning(f"Intelix token endpoint returned {r.status_code}: {r.text[:120]}")
            return None
        d = r.json() or {}
        token = d.get("access_token")
        if not token:
            return None
        # Cache slightly less than expires_in
        ttl = max(60, int(d.get("expires_in", 14400)) - 120)
        if redis:
            try:
                await redis.setex(_INTELIX_TOKEN_KEY, ttl, token)
            except Exception:
                pass
        return token
    except Exception as e:
        logger.warning(f"Intelix token error: {e}")
        return None


async def _intelix(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """Sophos Labs Intelix IP reputation lookup."""
    cid = getattr(settings, "sophos_intelix_client_id", "")
    csecret = getattr(settings, "sophos_intelix_client_secret", "")
    if not cid or not csecret:
        return {"available": False, "reason": "no client_id/secret"}

    token = await _intelix_token(client)
    if not token:
        return {"available": False, "reason": "OAuth token unavailable"}

    try:
        r = await client.get(
            f"{_INTELIX_BASE_URL}/lookup/ips/v1/{ip}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if r.status_code == 404:
            return {"available": True, "no_record": True}
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}: {r.text[:120]}"}
        d = r.json() or {}

        def _flatten(value):
            """Intelix sometimes returns category as a dict like
            {'name': 'Malicious', 'description': '...'} or as a list of such
            dicts. Reduce that to a comma-separated string so the UI can
            render it safely."""
            if value is None:
                return None
            if isinstance(value, str):
                return value
            if isinstance(value, dict):
                return value.get("name") or value.get("description") or json.dumps(value)
            if isinstance(value, list):
                parts = []
                for item in value:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        parts.append(item.get("name") or item.get("description") or json.dumps(item))
                    else:
                        parts.append(str(item))
                return ", ".join(p for p in parts if p)
            return str(value)

        score = d.get("score")
        if isinstance(score, dict):
            score = score.get("value")
        try:
            score = int(score) if score is not None else None
        except (ValueError, TypeError):
            score = None

        return {
            "available": True,
            "category": _flatten(d.get("category")),
            "category_description": _flatten(d.get("categoryDescription") or d.get("description")),
            "productivity_category": _flatten(d.get("productivityCategory")),
            "security_category": _flatten(d.get("securityCategory")),
            "score": score,
            "request_id": d.get("requestId"),
            "raw": d,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def _ipinfo(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """ipinfo.io — key-less endpoint, ~50k/month free.

    The free ipinfo endpoint reports the ASN only inside ``org`` and never the
    allocated CIDR, so we additionally resolve the owning network via RDAP (run
    concurrently with the ipinfo call so it adds no serial latency) and expose it
    as ``network`` — this is what the failed-login agent groups on to block a
    whole attacker network rather than a naive /24.
    """
    async def _info() -> dict[str, Any]:
        try:
            r = await client.get(f"https://ipinfo.io/{ip}/json", headers={"Accept": "application/json"})
            if r.status_code != 200:
                return {"available": False, "reason": f"HTTP {r.status_code}"}
            d = r.json() or {}
            return {
                "available": True,
                "hostname": d.get("hostname"),
                "city": d.get("city"),
                "region": d.get("region"),
                "country": d.get("country"),
                "loc": d.get("loc"),
                "org": d.get("org"),
                "postal": d.get("postal"),
                "timezone": d.get("timezone"),
                "url": f"https://ipinfo.io/{ip}",
            }
        except Exception as e:
            return {"available": False, "reason": str(e)[:120]}

    net, info = await asyncio.gather(_rdap_network(client, ip), _info())
    info["network"] = (net or {}).get("cidr")          # allocated CIDR (via RDAP)
    info["network_name"] = (net or {}).get("name")
    return info


# --- Network (CIDR) resolution -------------------------------------------------
# ipinfo's free tier omits the allocated prefix, so we resolve the owning network
# via RDAP (rdap.org bootstraps to the responsible RIR). Cached in Redis for a
# day — allocations are stable, and the failed-login sweep hits the same nets.
_NETWORK_CACHE_TTL = 86400
# Cache "couldn't resolve" too (short TTL) so a sweep of RDAP-silent IPs doesn't
# re-hit rdap.org every loop. Stored as {"cidr": null}.
_NETWORK_NEG_TTL = 3600


def _parse_rdap_cidr(d: dict[str, Any], ip: str) -> str | None:
    """Best CIDR for ``ip`` from an RDAP IP-network object: prefer the cidr0
    extension, fall back to summarising startAddress..endAddress."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    # cidr0_cidrs extension: [{"v4prefix": "1.2.3.0", "length": 24}, ...]
    best: ipaddress._BaseNetwork | None = None
    for c in d.get("cidr0_cidrs") or []:
        prefix = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if prefix is None or length is None:
            continue
        try:
            net = ipaddress.ip_network(f"{prefix}/{length}", strict=False)
        except ValueError:
            continue
        if addr in net and (best is None or net.num_addresses < best.num_addresses):
            best = net
    if best is not None:
        return str(best)
    # Fallback: start/end range → smallest aligned block containing the ip.
    start, end = d.get("startAddress"), d.get("endAddress")
    if start and end:
        try:
            nets = list(ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)))
        except (ValueError, TypeError):
            nets = []
        covering = [n for n in nets if addr in n]
        if covering:
            return str(min(covering, key=lambda n: n.num_addresses))
        # No summarised block actually contains the IP (malformed RDAP range) →
        # don't guess; returning a non-covering CIDR could block the wrong net.
    return None


async def _rdap_network(client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
    """Resolve {cidr, name, handle} for ``ip`` via RDAP, Redis-cached (24h).
    Returns None on any failure — callers fall back to a /24."""
    redis = await get_redis()
    ck = f"osint:net:{ip}"
    if redis:
        try:
            cached = await redis.get(ck)
            if cached:
                obj = json.loads(cached)
                return obj if obj.get("cidr") else None   # {"cidr": null} = known-negative
        except Exception:
            pass
    result: dict[str, Any] | None = None
    try:
        r = await client.get(f"https://rdap.org/ip/{ip}",
                             headers={"Accept": "application/json"}, follow_redirects=True)
        if r.status_code == 200:
            d = r.json() or {}
            cidr = _parse_rdap_cidr(d, ip)
            if cidr:
                result = {"cidr": cidr, "name": d.get("name"), "handle": d.get("handle")}
    except Exception as e:
        logger.debug(f"rdap network lookup failed for {ip}: {e}")
    if redis:
        try:
            if result is not None:
                await redis.setex(ck, _NETWORK_CACHE_TTL, json.dumps(result))
            else:
                await redis.setex(ck, _NETWORK_NEG_TTL, json.dumps({"cidr": None}))
        except Exception:
            pass
    return result


async def network_for_ip(ip: str) -> dict[str, Any] | None:
    """Public helper: the allocated network {cidr, name, handle} for a public IP,
    determined via the OSINT/RDAP lookup and cached in Redis. None if unresolved
    or non-public. Used by the failed-login agent to block whole attacker nets."""
    if not is_public(ip):
        return None
    redis = await get_redis()
    if redis:
        try:
            cached = await redis.get(f"osint:net:{ip}")
            if cached:
                obj = json.loads(cached)
                return obj if obj.get("cidr") else None   # {"cidr": null} = known-negative
        except Exception:
            pass
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        return await _rdap_network(client, ip)


# Shodan API credits are scarce, so Shodan is NOT part of the routine OSINT
# sweep. It is queried only when explicitly allowed (allow_shodan=True — human
# interaction) or, for automated callers, when the cheaper providers already
# flag the IP as clearly malicious (see looks_malicious + shodan_enrich).
_SHODAN_SKIPPED = {"available": False, "skipped": "not queried (Shodan is human-/malicious-only)"}
# Auto-every-lookup is on but the daily/monthly Shodan quota is reached.
_SHODAN_QUOTA_SKIPPED = {"available": False, "skipped": "Shodan-Tageslimit erreicht — uebersprungen"}


def _has_shodan_data(s: Any) -> bool:
    """True if Shodan was actually queried (don't re-query), False for the
    skipped sentinel (so a human/malicious request can upgrade it)."""
    return isinstance(s, dict) and s.get("available") is True and "skipped" not in s


def looks_malicious(payload: dict[str, Any], abuse_threshold: int = 80) -> bool:
    """Cheap-signal verdict used to decide whether an automated caller may
    spend a Shodan credit on this IP."""
    if not isinstance(payload, dict):
        return False
    ab = (payload.get("abuseipdb") or {}).get("abuse_score")
    if isinstance(ab, (int, float)) and ab >= abuse_threshold:
        return True
    vt = (payload.get("virustotal") or {}).get("malicious")
    if isinstance(vt, (int, float)) and vt >= 3:
        return True
    if (payload.get("greynoise") or {}).get("classification") == "malicious":
        return True
    return False


async def shodan_enrich(ip: str) -> dict[str, Any]:
    """Query Shodan for a single IP and persist the ports/CVEs long-term.
    The ONLY path that spends a Shodan credit. Enriches the CVE list with
    severity (CVSS/KEV via the free Shodan CVE DB) so callers can weigh
    High/Critical vulns instead of a raw count."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        s = await _track("shodan", _shodan(client, ip))
    if isinstance(s, dict) and s.get("vulns"):
        try:
            from app.cve_severity import enrich_cves
            s["cve_severity"] = await enrich_cves(s["vulns"])
        except Exception as e:
            logger.warning(f"OSINT CVE severity enrich failed for {ip}: {e}")
    await _persist_shodan(ip, s)
    return s


async def shodan_on_demand(ip: str) -> dict[str, Any]:
    """Human-triggered Shodan lookup (the 'Shodan abfragen' button). Queries +
    persists, and folds the result into the cached OSINT payload so re-opening
    the panel shows it without another credit."""
    if not is_public(ip):
        return {"available": False, "reason": "private/reserved IP"}
    s = await shodan_enrich(ip)
    redis = await get_redis()
    if redis:
        try:
            cached = await redis.get(f"osint:{ip}")
            if cached:
                payload = json.loads(cached)
                payload["shodan"] = s
                await redis.setex(f"osint:{ip}", CACHE_TTL, json.dumps(payload))
        except Exception as e:
            logger.warning(f"OSINT shodan cache update failed: {e}")
    return s


# --- Tor exit-node list ------------------------------------------------------
# Membership check against the Tor Project's published exit addresses
# (https://check.torproject.org/exit-addresses). The list is fetched hourly and
# cached in Redis; the per-lookup check is a cheap set lookup, no network call.
TOR_EXIT_URL = "https://check.torproject.org/exit-addresses"
TOR_REDIS_KEY = "tor:exit_nodes"
_TOR_MEMO_TTL = 300  # seconds — cap on re-reading the set from Redis
_TOR_MEMO: dict[str, Any] = {"ips": frozenset(), "ts": 0.0}


async def refresh_tor_exit_nodes() -> dict[str, Any]:
    """Fetch + parse the Tor exit-address list and cache it in Redis. Scheduled
    hourly. Keeps the previous set on failure; returns {count, updated}."""
    import time
    from datetime import datetime, timezone
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(TOR_EXIT_URL)
        if r.status_code != 200:
            logger.warning(f"tor exit list: HTTP {r.status_code}")
            return {"count": len(_TOR_MEMO["ips"]), "updated": None}
        ips = set()
        for line in r.text.splitlines():
            # Format: "ExitAddress <ip> <ISO-timestamp>"
            if line.startswith("ExitAddress "):
                tok = line.split()
                if len(tok) >= 2:
                    try:
                        ipaddress.ip_address(tok[1])
                        ips.add(tok[1])
                    except ValueError:
                        pass
        frozen = frozenset(ips)
        if not frozen:
            return {"count": len(_TOR_MEMO["ips"]), "updated": None}
        _TOR_MEMO["ips"] = frozen
        _TOR_MEMO["ts"] = time.time()
        redis = await get_redis()
        if redis:
            await redis.set(TOR_REDIS_KEY, json.dumps(sorted(frozen)))
            await redis.set(TOR_REDIS_KEY + ":updated", datetime.now(timezone.utc).isoformat())
        logger.info(f"tor exit list refreshed: {len(frozen)} exit-node IPs")
        return {"count": len(frozen), "updated": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        logger.warning(f"tor exit list refresh failed: {e}")
        return {"count": len(_TOR_MEMO["ips"]), "updated": None}


async def _tor_exit_ips() -> frozenset[str]:
    """Current Tor exit-node IP set: in-process memo → Redis → lazy fetch."""
    import time
    now = time.time()
    if _TOR_MEMO["ips"] and now - _TOR_MEMO["ts"] < _TOR_MEMO_TTL:
        return _TOR_MEMO["ips"]
    ips: frozenset[str] = frozenset()
    try:
        redis = await get_redis()
        if redis:
            raw = await redis.get(TOR_REDIS_KEY)
            if raw:
                ips = frozenset(json.loads(raw))
    except Exception as e:
        logger.warning(f"tor exit list redis read failed: {e}")
    if not ips:
        await refresh_tor_exit_nodes()   # cold start — populate once
        return _TOR_MEMO["ips"]
    _TOR_MEMO["ips"] = ips
    _TOR_MEMO["ts"] = now
    return ips


async def tor_check(ip: str) -> dict[str, Any]:
    """Is `ip` a known Tor exit node? Cheap set membership; never raises."""
    try:
        ips = await _tor_exit_ips()
        return {"available": bool(ips), "is_exit_node": ip in ips, "list_size": len(ips)}
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def reverse_dns(ip: str) -> dict[str, Any]:
    """PTR (reverse DNS) record for an IP — a free signal (no API/quota): the
    hostname the network owner assigned, which often reveals the hosting/ISP or a
    scanner's naming pattern. Runs in a thread executor with a short timeout so a
    slow/hung resolver can't block the lookup."""
    loop = asyncio.get_running_loop()
    try:
        host, _aliases, _addrs = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=4.0)
        return {"available": True, "hostname": host}
    except (socket.herror, socket.gaierror):
        return {"available": True, "hostname": None}   # resolved: no PTR record
    except (asyncio.TimeoutError, OSError, Exception) as e:
        return {"available": False, "reason": (str(e)[:80] or "timeout")}


# --- Enrichment for AI log queries ------------------------------------------
# Compact per-IP OSINT summaries that get handed to the LLM alongside firewall-
# log query results, so it can reason about the external IPs. enrich_cached()
# NEVER makes a provider call (cache/history + the free Tor check only); IPs with
# no cached data come back {"cached": false} so the assistant can offer a live
# lookup. enrich_live() performs the real lookups (cheap providers, no Shodan).

def _risk_summary(payload: dict[str, Any]) -> dict[str, Any]:
    ab = payload.get("abuseipdb") or {}
    vt = payload.get("virustotal") or {}
    gn = payload.get("greynoise") or {}
    intel = payload.get("intelix") or {}
    ipi = payload.get("ipinfo") or {}
    return {
        "abuse_score": ab.get("abuse_score"),
        "vt_malicious": vt.get("malicious"),
        "greynoise": gn.get("classification"),
        "intelix_category": intel.get("security_category") or intel.get("category"),
        "country": ipi.get("country"),
        "org": ipi.get("org"),
    }


async def _history_summary(ip: str) -> dict[str, Any] | None:
    """Latest stored OSINT for an IP from the long-term history table."""
    try:
        from sqlalchemy import select
        from app.database import async_session
        from app.models import OsintResult
        async with async_session() as db:
            row = (await db.execute(
                select(OsintResult).where(OsintResult.value == ip,
                                          OsintResult.indicator_type == "ip")
            )).scalar_one_or_none()
        if not row:
            return None
        return {
            "abuse_score": row.abuse_score,
            "vt_malicious": row.vt_malicious,
            "greynoise": row.greynoise,
            "intelix_category": row.intelix_category,
            "country": row.country,
            "org": row.org,
        }
    except Exception:
        return None


def _distinct_public(ips: list[str], cap: int) -> list[str]:
    seen: list[str] = []
    for ip in ips or []:
        if ip and ip not in seen and is_public(ip):
            seen.append(ip)
        if len(seen) >= cap:
            break
    return seen


async def enrich_cached(ips: list[str], cap: int = 30) -> dict[str, dict]:
    """OSINT summary per distinct PUBLIC IP from cache/history + the free Tor
    check only — no provider calls. Uncached IPs get {"cached": false} (+ Tor)."""
    out: dict[str, dict] = {}
    redis = await get_redis()
    for ip in _distinct_public(ips, cap):
        summary: dict[str, Any] | None = None
        if redis:
            try:
                raw = await redis.get(f"osint:{ip}")
                if raw:
                    summary = _risk_summary(json.loads(raw))
            except Exception:
                summary = None
        if summary is None:
            summary = await _history_summary(ip)
        tor = await tor_check(ip)
        is_tor = bool(tor.get("is_exit_node"))
        if summary is None:
            out[ip] = {"cached": False, "tor_exit_node": is_tor}
        else:
            summary["cached"] = True
            summary["tor_exit_node"] = is_tor
            out[ip] = summary
    return out


async def enrich_live(ips: list[str], cap: int = 10,
                      context: str | None = None) -> dict[str, dict]:
    """Run real (cache-aware, no-Shodan) OSINT lookups for distinct public IPs,
    capped. Use only after the user approves enriching OSINT-uncached IPs."""
    out: dict[str, dict] = {}
    for ip in _distinct_public(ips, cap):
        try:
            payload = await lookup(ip, context=context)
            summary = _risk_summary(payload)
            summary["cached"] = bool(payload.get("cached"))
            summary["tor_exit_node"] = bool((payload.get("tor") or {}).get("is_exit_node"))
            out[ip] = summary
        except Exception as e:
            out[ip] = {"error": str(e)[:120]}
    return out


# --- provider matrix ----------------------------------------------------------
# Which provider may be asked from which part of the system. One global on/off
# per provider was never enough: the honeypot sees dozens of fresh addresses an
# hour and would drain a daily quota by lunchtime, while an analyst opening a
# dossier wants everything there is. Same provider, opposite answer, depending
# only on who is asking — so the switch belongs at the intersection.

# Free or effectively unmetered; listed so the matrix is honest about what runs,
# but they are not worth switching off and are enabled everywhere by default.
FREE_PROVIDERS = ("tor", "rdns", "dns")
# Metered: every call costs quota or a credit.
PAID_PROVIDERS = ("abuseipdb", "virustotal", "greynoise", "ipinfo", "intelix", "shodan")
PROVIDERS = PAID_PROVIDERS + FREE_PROVIDERS

# Where a lookup can originate. Adding one here plus a default row below is all
# it takes to bring a new call site under the matrix.
CONTEXTS = {
    "manual":   "Analyst on the OSINT page / dossier button",
    "dossier":  "IP dossier view",
    "agent":    "Automatic agent triage",
    "honeypot": "Decoy login captures",
    "mcp":      "MCP tools (LLM clients)",
    "command":  "Teams / Telegram commands",
    "recheck":  "Weekly re-check of OSINT-based blocks",
}

# Defaults chosen by cost per context, not by taste:
#   manual/dossier — a human asked; give them everything except the scarce credit
#   agent/command  — automated but low volume; the cheap providers
#   honeypot       — highest volume by far; nothing metered runs unattended
#   mcp            — a model is asking, often in a loop; cheap providers only
_DEFAULT_MATRIX: dict[str, dict[str, bool]] = {
    "manual":   {p: True for p in PAID_PROVIDERS if p != "shodan"} | {"shodan": False},
    "dossier":  {p: True for p in PAID_PROVIDERS if p != "shodan"} | {"shodan": False},
    "agent":    {"abuseipdb": True, "virustotal": True, "greynoise": True,
                 "ipinfo": True, "intelix": True, "shodan": False},
    "command":  {"abuseipdb": True, "virustotal": True, "greynoise": True,
                 "ipinfo": True, "intelix": True, "shodan": False},
    "honeypot": {p: False for p in PAID_PROVIDERS},
    "mcp":      {"abuseipdb": True, "virustotal": True, "greynoise": True,
                 "ipinfo": True, "intelix": False, "shodan": False},
    # The re-check needs the providers that can make an IP count as malicious.
    # Shodan stays off here: the re-check queries it itself, and only for IPs
    # whose block rested on Shodan CVEs.
    "recheck":  {"abuseipdb": True, "virustotal": True, "greynoise": True,
                 "ipinfo": False, "intelix": True, "shodan": False},
}


def default_matrix() -> dict[str, dict[str, bool]]:
    """The built-in defaults, free providers included, as the UI shows them."""
    return {ctx: {**{f: True for f in FREE_PROVIDERS}, **row}
            for ctx, row in _DEFAULT_MATRIX.items()}


def _configured_matrix() -> dict[str, dict[str, bool]]:
    """Operator overrides from the ``osint_provider_matrix`` setting.

    Malformed JSON yields an empty override rather than an exception: a typo in
    a settings field must not be able to stop every OSINT lookup in the system.
    """
    raw = (getattr(settings, "osint_provider_matrix", "") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception as e:
        logger.warning(f"osint_provider_matrix is not valid JSON, ignoring it: {e}")
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, dict[str, bool]] = {}
    for ctx, row in parsed.items():
        if ctx in CONTEXTS and isinstance(row, dict):
            out[ctx] = {p: bool(v) for p, v in row.items() if p in PROVIDERS}
    return out


def effective_matrix() -> dict[str, dict[str, bool]]:
    """Defaults with the operator's overrides applied — what actually runs."""
    merged = default_matrix()
    for ctx, row in _configured_matrix().items():
        merged.setdefault(ctx, {}).update(row)
    return merged


def provider_enabled(provider: str, context: str | None) -> bool:
    """May ``provider`` be queried on behalf of ``context``?

    An unknown context is treated as "manual", the most permissive row: a new
    call site that forgets to declare itself should behave like a human asked,
    not silently return nothing.
    """
    if provider not in PROVIDERS:
        return True
    row = effective_matrix().get(context if context in CONTEXTS else "manual", {})
    return bool(row.get(provider, provider in FREE_PROVIDERS))


# Returned in place of a provider's payload when the matrix switched it off, so
# the response shape stays identical and callers can say *why* a field is empty.
def _disabled(provider: str, context: str | None) -> dict[str, Any]:
    return {"skipped": True, "reason": "disabled_by_matrix",
            "provider": provider, "context": context or "manual"}


class _CacheStale(Exception):
    """Cached entry predates a matrix change and must not be served."""


def _cache_is_stale_for(payload: dict[str, Any], providers, context: str | None) -> bool:
    """True when the cached entry lacks a provider this context is now allowed
    to use.

    Without this, switching a provider on would appear to do nothing for an hour:
    the cached payload still carries the "disabled" sentinel from the run that
    happened while it was off, and a cache hit would keep serving it.
    """
    for p in providers:
        if not provider_enabled(p, context):
            continue
        entry = payload.get(p)
        if isinstance(entry, dict) and entry.get("reason") == "disabled_by_matrix":
            return True
    return False


async def lookup(ip: str, force: bool = False, allow_shodan: bool = False,
                 context: str | None = None) -> dict[str, Any]:
    """Run the OSINT providers and return a merged dict.

    Shodan is NEVER queried here by default — it costs a scarce credit and must
    be triggered explicitly: a human presses the "Shodan abfragen" button
    (→ shodan_enrich via /api/osint/shodan/{ip}), or an automated caller decides
    an IP is malicious enough to spend a credit (looks_malicious + shodan_enrich).
    Cached in Redis for `CACHE_TTL` seconds.
    """
    if not is_public(ip):
        return {"ip": ip, "error": "private/reserved IP — OSINT lookups skipped"}

    cache_key = f"osint:{ip}"
    # Shodan runs automatically on every lookup when shodan_auto_every_lookup is
    # on (default); otherwise only when the caller explicitly allows it (human
    # button) or an automated caller follows up on a malicious IP. An explicit
    # human request (allow_shodan) always goes through; the automatic path is
    # hard-capped at the configured daily/monthly Shodan quota.
    # An explicit human request still wins, but only if the matrix lets this
    # context near Shodan at all.
    shodan_allowed = provider_enabled("shodan", context)
    do_shodan = bool(allow_shodan) and shodan_allowed
    quota_blocked = False
    if not do_shodan and shodan_allowed and getattr(settings, "shodan_auto_every_lookup", False):
        try:
            from app.osint_metrics import quota_exhausted
            quota_blocked = await quota_exhausted("shodan")
        except Exception as e:
            logger.warning(f"shodan quota check failed (querying anyway): {e}")
            quota_blocked = False
        do_shodan = not quota_blocked
        if quota_blocked:
            logger.debug(f"OSINT: Shodan auto-skip for {ip} — daily/monthly quota reached")

    redis = await get_redis()
    if redis and not force:
        try:
            cached = await redis.get(cache_key)
            payload = json.loads(cached) if cached is not None else None
            if payload is not None and _cache_is_stale_for(
                    payload, PAID_PROVIDERS + ("tor", "rdns"), context):
                payload = None
            if payload is not None:
                payload["cached"] = True
                # Upgrade a cached entry that skipped Shodan when we're now
                # allowed to query it (auto-enabled, or a human opens the panel).
                if do_shodan and not _has_shodan_data(payload.get("shodan")):
                    payload["shodan"] = await shodan_enrich(ip)
                    payload["cached"] = False
                    try:
                        await redis.setex(cache_key, CACHE_TTL, json.dumps(payload))
                    except Exception as e:
                        logger.warning(f"OSINT redis write failed: {e}")
                else:
                    await _record_cache_hit(["abuseipdb", "virustotal", "shodan", "greynoise", "ipinfo", "intelix"])
                return payload
        except Exception as e:
            logger.warning(f"OSINT redis read failed: {e}")

    async def _maybe(provider: str, coro_factory):
        """Run a provider only if the matrix allows it for this context.

        The coroutine is built lazily — constructing it for a disabled provider
        would leave an un-awaited coroutine behind and, worse, invite someone to
        "just await it anyway" later.
        """
        if not provider_enabled(provider, context):
            return _disabled(provider, context)
        return await _track(provider, coro_factory())

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        abuse, vt, gn, ipi, intelix, rdns = await asyncio.gather(
            _maybe("abuseipdb", lambda: _abuseipdb(client, ip)),
            _maybe("virustotal", lambda: _virustotal(client, ip)),
            _maybe("greynoise", lambda: _greynoise(client, ip)),
            _maybe("ipinfo", lambda: _ipinfo(client, ip)),
            _maybe("intelix", lambda: _intelix(client, ip)),
            reverse_dns(ip) if provider_enabled("rdns", context)
            # The sentinel, not a bare None: _cache_is_stale_for() recognises a
            # switched-off provider by "disabled_by_matrix", and it is asked
            # about rdns. Cached as None it looked exactly like "resolved, no
            # PTR", so switching rdns back on kept serving the empty entry for
            # the rest of the cache TTL — the very thing that check exists to
            # prevent.
            else asyncio.sleep(0, result=_disabled("rdns", context)),
        )

    # Query Shodan when enabled (auto-every-lookup or explicit permission);
    # otherwise store a skipped sentinel (a malicious-IP follow-up may upgrade
    # it). Distinguish "quota reached" so the panel/audit shows why it was skipped.
    if do_shodan:
        shodan = await shodan_enrich(ip)
    elif quota_blocked:
        shodan = dict(_SHODAN_QUOTA_SKIPPED)
    else:
        shodan = dict(_SHODAN_SKIPPED)

    payload = {
        "ip": ip,
        "abuseipdb": abuse,
        "virustotal": vt,
        "shodan": shodan,
        "greynoise": gn,
        "ipinfo": ipi,
        "intelix": intelix,
        "tor": (await tor_check(ip)) if provider_enabled("tor", context)
               else _disabled("tor", context),
        "rdns": rdns,
        "cached": False,
    }

    if redis:
        try:
            await redis.setex(cache_key, CACHE_TTL, json.dumps(payload))
        except Exception as e:
            logger.warning(f"OSINT redis write failed: {e}")

    # Long-term history (independent of the 1h Redis cache).
    await _persist_osint(ip, "ip", payload)

    return payload


# Which stored column each provider is the only source of — used to keep a
# provider that did not run from overwriting the last answer it gave.
_PERSIST_PROVIDER_COLS = {
    "abuseipdb": ("abuse_score",),
    "virustotal": ("vt_malicious",),
    "greynoise": ("greynoise",),
    "intelix": ("intelix_category",),
    "ipinfo": ("country", "city", "org", "asn", "lat", "lon"),
}


async def _persist_osint(value: str, itype: str, payload: dict[str, Any]) -> None:
    """Upsert an OSINT lookup into the long-term history table. Best-effort —
    never breaks the lookup response."""
    try:
        from datetime import datetime, timezone
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from app.database import async_session
        from app.models import OsintResult

        ab = payload.get("abuseipdb") or {}
        vt = payload.get("virustotal") or {}
        gn = payload.get("greynoise") or {}
        intel = payload.get("intelix") or {}
        ipi = payload.get("ipinfo") or {}
        # ipinfo "loc" is "lat,lon"; split when present.
        lat = lon = None
        loc = ipi.get("loc") or ""
        if isinstance(loc, str) and "," in loc:
            try:
                lat, lon = (float(x) for x in loc.split(",", 1))
            except ValueError:
                lat = lon = None
        cols = {
            "value": value[:2048],
            "indicator_type": itype,
            "abuse_score": ab.get("abuse_score") if isinstance(ab.get("abuse_score"), (int, float)) else None,
            "vt_malicious": vt.get("malicious") if isinstance(vt.get("malicious"), (int, float)) else None,
            "greynoise": (gn.get("classification") or None),
            "intelix_category": (intel.get("security_category") or intel.get("category") or None),
            "country": ipi.get("country"),
            "city": ipi.get("city"),
            "org": ipi.get("org"),
            "asn": str(ipi.get("asn")) if ipi.get("asn") else None,
            "lat": lat, "lon": lon,
            "raw": payload,
            "last_seen": datetime.now(timezone.utc),
        }
        # A provider the matrix switched off returns the "disabled" sentinel, not
        # data, so its columns come out None — and writing that None over the
        # stored row erased real enrichment: an IP AbuseIPDB scored 100 read back
        # as unrated after a single honeypot lookup, which runs with the paid
        # providers off. A provider that did not run does not get to overwrite
        # what the last one that did found. The same goes for one that failed
        # (HTTP 429, timeout): GreyNoise's community API rate-limits often, and
        # each 429 turned a stored "malicious" into NULL.
        skipped_cols = {
            c
            for prov, provider_cols in _PERSIST_PROVIDER_COLS.items()
            for c in provider_cols
            if isinstance(payload.get(prov), dict)
            and (payload[prov].get("reason") == "disabled_by_matrix"
                 or payload[prov].get("available") is False)
        }
        async with async_session() as db:
            stmt = pg_insert(OsintResult).values(lookup_count=1, **cols)
            # On repeat lookup: refresh summary + bump the counter, keep first_seen.
            stmt = stmt.on_conflict_do_update(
                index_elements=["value"],
                set_={**{k: cols[k] for k in cols
                         if k != "value" and k not in skipped_cols},
                      "lookup_count": OsintResult.lookup_count + 1},
            )
            await db.execute(stmt)
            await db.commit()
    except Exception as e:
        logger.warning(f"osint persist failed for {value}: {e}")


async def _persist_shodan(ip: str, shodan: dict[str, Any]) -> None:
    """Upsert a Shodan host record when the lookup yielded ports or CVEs.
    Best-effort — never breaks the OSINT response. Geo falls back to GeoIP
    when Shodan didn't return coordinates."""
    if not isinstance(shodan, dict) or not shodan.get("available"):
        return
    ports = shodan.get("ports") or []
    vulns = shodan.get("vulns") or []
    if not ports and not vulns:
        return
    try:
        from datetime import datetime, timezone
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from app.database import async_session
        from app.models import ShodanHost
        from app.geoip_service import lookup_ip

        lat, lon = shodan.get("latitude"), shodan.get("longitude")
        country, city = shodan.get("country"), shodan.get("city")
        async with async_session() as db:
            if lat is None or lon is None:
                geo = await lookup_ip(ip, db)
                if geo:
                    lat = lat if lat is not None else geo.get("lat")
                    lon = lon if lon is not None else geo.get("lon")
                    country = country or geo.get("country")
                    city = city or geo.get("city")
            now = datetime.now(timezone.utc)
            values = {
                "ip": ip, "lat": lat, "lon": lon, "country": country, "city": city,
                "org": shodan.get("org"), "asn": str(shodan.get("asn") or "") or None,
                "os": shodan.get("os"),
                "ports": ports, "vulns": vulns,
                "hostnames": shodan.get("hostnames") or [],
                "tags": shodan.get("tags") or [],
                "shodan_last_update": shodan.get("last_update"),
                "last_seen": now,
            }
            stmt = pg_insert(ShodanHost).values(**values)
            # On conflict refresh everything except first_seen.
            stmt = stmt.on_conflict_do_update(
                index_elements=["ip"],
                set_={k: values[k] for k in values if k != "ip"},
            )
            await db.execute(stmt)
            await db.commit()
    except Exception as e:
        logger.warning(f"shodan persist failed for {ip}: {e}")


# --- Domain & URL OSINT ---

def _vt_url_id(url: str) -> str:
    """VirusTotal identifies URLs by url-safe base64 of the raw URL with
    padding stripped. Same encoding works for the API path segment."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def _intelix_url_id(url: str) -> str:
    """Sophos Intelix URL lookup wants the URL percent-encoded as a path
    segment (no scheme/host parsing — it's passed verbatim into a single
    segment, all reserved chars escaped)."""
    return quote(url, safe="")


async def _vt_domain(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    key = getattr(settings, "virustotal_api_key", "")
    if not key:
        return {"available": False, "reason": "no API key"}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
        )
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}"}
        attr = ((r.json() or {}).get("data") or {}).get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation"),
            "categories": attr.get("categories") or {},
            "tags": attr.get("tags") or [],
            "registrar": attr.get("registrar"),
            "creation_date": attr.get("creation_date"),
            "last_analysis_date": attr.get("last_analysis_date"),
            "url": f"https://www.virustotal.com/gui/domain/{domain}",
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def _vt_url(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    key = getattr(settings, "virustotal_api_key", "")
    if not key:
        return {"available": False, "reason": "no API key"}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(url)}",
            headers={"x-apikey": key},
        )
        # 404 = URL has never been submitted to VT — useful signal, not an error.
        if r.status_code == 404:
            return {
                "available": True,
                "no_record": True,
                "url": f"https://www.virustotal.com/gui/search/{_vt_url_id(url)}",
            }
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}"}
        attr = ((r.json() or {}).get("data") or {}).get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation"),
            "title": attr.get("title"),
            "final_url": attr.get("last_final_url"),
            "http_status": attr.get("last_http_response_code"),
            "tags": attr.get("tags") or [],
            "categories": attr.get("categories") or {},
            "last_analysis_date": attr.get("last_analysis_date"),
            "url": f"https://www.virustotal.com/gui/url/{_vt_url_id(url)}",
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def _intelix_url(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    """Sophos Labs Intelix URL/domain category lookup.

    A bare domain is wrapped as ``http://<domain>/`` so Intelix accepts it —
    the categorisation is per host, not per path.
    """
    cid = getattr(settings, "sophos_intelix_client_id", "")
    csecret = getattr(settings, "sophos_intelix_client_secret", "")
    if not cid or not csecret:
        return {"available": False, "reason": "no client_id/secret"}

    token = await _intelix_token(client)
    if not token:
        return {"available": False, "reason": "OAuth token unavailable"}

    try:
        r = await client.get(
            f"{_INTELIX_BASE_URL}/lookup/urls/v1/{_intelix_url_id(url)}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if r.status_code == 404:
            return {"available": True, "no_record": True}
        if r.status_code != 200:
            return {"available": False, "reason": f"HTTP {r.status_code}: {r.text[:120]}"}
        d = r.json() or {}

        def _flatten(value):
            if value is None:
                return None
            if isinstance(value, str):
                return value
            if isinstance(value, dict):
                return value.get("name") or value.get("description") or json.dumps(value)
            if isinstance(value, list):
                parts = []
                for item in value:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        parts.append(item.get("name") or item.get("description") or json.dumps(item))
                    else:
                        parts.append(str(item))
                return ", ".join(p for p in parts if p)
            return str(value)

        score = d.get("score")
        if isinstance(score, dict):
            score = score.get("value")
        try:
            score = int(score) if score is not None else None
        except (ValueError, TypeError):
            score = None

        return {
            "available": True,
            "category": _flatten(d.get("category")),
            "category_description": _flatten(d.get("categoryDescription") or d.get("description")),
            "productivity_category": _flatten(d.get("productivityCategory")),
            "security_category": _flatten(d.get("securityCategory")),
            "risk_level": _flatten(d.get("riskLevel")),
            "score": score,
            "request_id": d.get("requestId"),
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


async def _dns_a_records(domain: str) -> dict[str, Any]:
    """Resolve a domain to its IPv4/IPv6 addresses via stdlib getaddrinfo
    in a thread executor (no extra dependency). Lightweight signal —
    confirms the domain still resolves and shows where it points."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP),
        )
    except (socket.gaierror, OSError) as e:
        return {"available": True, "resolves": False, "reason": str(e)[:120]}
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}

    ipv4: list[str] = []
    ipv6: list[str] = []
    for fam, _t, _p, _c, sockaddr in infos:
        ip = sockaddr[0]
        if fam == socket.AF_INET and ip not in ipv4:
            ipv4.append(ip)
        elif fam == socket.AF_INET6 and ip not in ipv6:
            ipv6.append(ip)
    return {
        "available": True,
        "resolves": bool(ipv4 or ipv6),
        "ipv4": ipv4,
        "ipv6": ipv6,
    }


def _is_resolvable_host(host: str) -> bool:
    """Cheap sanity check before we let anything hit the wire."""
    if not host or len(host) > 253:
        return False
    if any(c.isspace() for c in host):
        return False
    if host.startswith("*."):  # wildcards aren't queryable as such
        host = host[2:]
    return "." in host and not host.startswith(".") and not host.endswith(".")


async def lookup_domain(domain: str, force: bool = False,
                        context: str | None = None) -> dict[str, Any]:
    """Run domain-capable OSINT providers in parallel."""
    if not _is_resolvable_host(domain):
        return {"domain": domain, "error": "not a usable domain"}

    cache_key = f"osint:domain:{domain.lower()}"
    redis = await get_redis()
    if redis and not force:
        try:
            cached = await redis.get(cache_key)
            if cached:
                payload = json.loads(cached)
                if _cache_is_stale_for(payload, ("virustotal", "intelix", "dns"), context):
                    raise _CacheStale()
                payload["cached"] = True
                await _record_cache_hit(["virustotal", "intelix"])
                return payload
        except _CacheStale:
            pass
        except Exception as e:
            logger.warning(f"OSINT redis read failed: {e}")

    # For Intelix we treat the bare domain as a URL so the host gets categorised.
    intelix_target = domain[2:] if domain.startswith("*.") else domain
    intelix_url = f"http://{intelix_target}/"

    async def _maybe_d(provider: str, coro_factory):
        if not provider_enabled(provider, context):
            return _disabled(provider, context)
        return await _track(provider, coro_factory())

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        vt, intelix, dns = await asyncio.gather(
            _maybe_d("virustotal", lambda: _vt_domain(client, domain)),
            _maybe_d("intelix", lambda: _intelix_url(client, intelix_url)),
            _dns_a_records(intelix_target) if provider_enabled("dns", context)
            # Same sentinel as every other provider: the response shape stays
            # identical and the panel can say *why* the field is empty instead
            # of showing a resolution that simply looks like it found nothing.
            else asyncio.sleep(0, result=_disabled("dns", context)),
        )

    payload = {
        "domain": domain,
        "virustotal": vt,
        "intelix": intelix,
        "dns": dns,
        "cached": False,
    }

    if redis:
        try:
            await redis.setex(cache_key, CACHE_TTL, json.dumps(payload))
        except Exception as e:
            logger.warning(f"OSINT redis write failed: {e}")

    await _persist_osint(domain.lower(), "domain", payload)

    return payload


async def lookup_url(url: str, force: bool = False,
                     context: str | None = None) -> dict[str, Any]:
    """Run URL-capable OSINT providers in parallel."""
    if not url or "://" not in url or len(url) > 2048:
        return {"url": url, "error": "not a usable URL"}

    # Cache key folds long URLs into a short hash so Redis keys stay sane.
    import hashlib
    cache_key = f"osint:url:{hashlib.sha256(url.encode()).hexdigest()[:32]}"
    redis = await get_redis()
    if redis and not force:
        try:
            cached = await redis.get(cache_key)
            if cached:
                payload = json.loads(cached)
                if _cache_is_stale_for(payload, ("virustotal", "intelix", "dns"), context):
                    raise _CacheStale()
                payload["cached"] = True
                await _record_cache_hit(["virustotal", "intelix"])
                return payload
        except _CacheStale:
            pass
        except Exception as e:
            logger.warning(f"OSINT redis read failed: {e}")

    async def _maybe_u(provider: str, coro_factory):
        if not provider_enabled(provider, context):
            return _disabled(provider, context)
        return await _track(provider, coro_factory())

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        vt, intelix = await asyncio.gather(
            _maybe_u("virustotal", lambda: _vt_url(client, url)),
            _maybe_u("intelix", lambda: _intelix_url(client, url)),
        )

    payload = {
        "url": url,
        "virustotal": vt,
        "intelix": intelix,
        "cached": False,
    }

    if redis:
        try:
            await redis.setex(cache_key, CACHE_TTL, json.dumps(payload))
        except Exception as e:
            logger.warning(f"OSINT redis write failed: {e}")

    await _persist_osint(url, "url", payload)

    return payload
