"""OSINT lookups for IP addresses.

Each provider is queried independently — failures of one source do not break
the others. Results are merged into a flat dict so the frontend can render
them in a uniform card. Results are cached in Redis for 1h to avoid burning
free-tier rate limits when the user clicks the same IP repeatedly.
"""
import asyncio
import ipaddress
import json
import logging
from typing import Any

import httpx

from app.config import settings
from app.geoip_service import get_redis

logger = logging.getLogger(__name__)

CACHE_TTL = 3600
TIMEOUT = 12.0


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
    """ipinfo.io — key-less endpoint, ~50k/month free."""
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


async def lookup(ip: str, force: bool = False) -> dict[str, Any]:
    """Run all OSINT providers in parallel and return a merged dict.

    Cached in Redis for `CACHE_TTL` seconds; pass force=True to bypass cache.
    """
    if not is_public(ip):
        return {"ip": ip, "error": "private/reserved IP — OSINT lookups skipped"}

    cache_key = f"osint:{ip}"
    redis = await get_redis()
    if redis and not force:
        try:
            cached = await redis.get(cache_key)
            if cached:
                payload = json.loads(cached)
                payload["cached"] = True
                return payload
        except Exception as e:
            logger.warning(f"OSINT redis read failed: {e}")

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        abuse, vt, shodan, gn, ipi, intelix = await asyncio.gather(
            _abuseipdb(client, ip),
            _virustotal(client, ip),
            _shodan(client, ip),
            _greynoise(client, ip),
            _ipinfo(client, ip),
            _intelix(client, ip),
        )

    payload = {
        "ip": ip,
        "abuseipdb": abuse,
        "virustotal": vt,
        "shodan": shodan,
        "greynoise": gn,
        "ipinfo": ipi,
        "intelix": intelix,
        "cached": False,
    }

    if redis:
        try:
            await redis.setex(cache_key, CACHE_TTL, json.dumps(payload))
        except Exception as e:
            logger.warning(f"OSINT redis write failed: {e}")

    return payload
