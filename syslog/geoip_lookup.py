"""GeoIP lookup for the syslog receiver.

Shares persistent state with the backend service:
- Postgres table `geoip_cache` (same row schema as backend.geoip_service)
- Redis key `geoip:<ip>` (TTL 24h)

Lookup chain: Redis -> Postgres -> MaxMind local DB -> ip-api.com fallback.
Successful lookups are written back to both caches so the backend benefits too.
"""

import ipaddress
import json
import logging
import os
from pathlib import Path

import asyncpg
import httpx
import redis.asyncio as redis

logger = logging.getLogger(__name__)

GEOIP_CITY_PATH = Path("/app/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_PATH = Path("/app/geoip/GeoLite2-ASN.mmdb")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

_redis: redis.Redis | None = None
_city_reader = None
_asn_reader = None


async def _get_redis() -> redis.Redis | None:
    global _redis
    if _redis is None:
        try:
            _redis = redis.from_url(REDIS_URL, decode_responses=True)
        except Exception as e:
            logger.warning(f"Redis unavailable: {e}")
            return None
    return _redis


def _get_city_reader():
    global _city_reader
    if _city_reader is None and GEOIP_CITY_PATH.exists():
        import geoip2.database
        _city_reader = geoip2.database.Reader(str(GEOIP_CITY_PATH))
        logger.info("Loaded MaxMind City DB")
    return _city_reader


def _get_asn_reader():
    global _asn_reader
    if _asn_reader is None and GEOIP_ASN_PATH.exists():
        import geoip2.database
        _asn_reader = geoip2.database.Reader(str(GEOIP_ASN_PATH))
        logger.info("Loaded MaxMind ASN DB")
    return _asn_reader


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _maxmind_lookup(ip: str) -> dict | None:
    city_reader = _get_city_reader()
    if city_reader is None:
        return None
    try:
        r = city_reader.city(ip)
        data = {
            "lat": r.location.latitude,
            "lon": r.location.longitude,
            "country": r.country.iso_code,
            "city": r.city.name,
            "asn": None,
            "org": None,
            "abuse_score": None,
        }
    except Exception:
        return None
    asn_reader = _get_asn_reader()
    if asn_reader:
        try:
            a = asn_reader.asn(ip)
            data["asn"] = f"AS{a.autonomous_system_number}"
            data["org"] = a.autonomous_system_organization
        except Exception:
            pass
    return data


async def _ip_api_lookup(ip: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,countryCode,city,lat,lon,as,org"},
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    return {
                        "lat": d.get("lat"),
                        "lon": d.get("lon"),
                        "country": d.get("countryCode"),
                        "city": d.get("city"),
                        "asn": d.get("as"),
                        "org": d.get("org"),
                        "abuse_score": None,
                    }
    except Exception as e:
        logger.warning(f"ip-api lookup failed for {ip}: {e}")
    return None


async def _abuseipdb_lookup(ip: str) -> int | None:
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                return resp.json()["data"]["abuseConfidenceScore"]
    except Exception:
        pass
    return None


async def lookup_ip(ip: str, pool: asyncpg.Pool | None) -> dict | None:
    """Async GeoIP lookup with shared Redis + Postgres cache."""
    if not ip or not is_public_ip(ip):
        return None

    r = await _get_redis()

    # 1. Redis hot cache
    if r:
        try:
            cached = await r.get(f"geoip:{ip}")
            if cached:
                return json.loads(cached)
        except Exception:
            pass

    # 2. Postgres shared cache
    if pool:
        try:
            row = await pool.fetchrow(
                "SELECT lat, lon, country, city, asn, org, abuse_score "
                "FROM geoip_cache WHERE ip=$1",
                ip,
            )
            if row:
                data = dict(row)
                if r:
                    try:
                        await r.setex(f"geoip:{ip}", 86400, json.dumps(data))
                    except Exception:
                        pass
                return data
        except Exception as e:
            logger.warning(f"DB cache read failed for {ip}: {e}")

    # 3. MaxMind local DB
    data = _maxmind_lookup(ip)

    # 4. ip-api fallback
    if data is None:
        data = await _ip_api_lookup(ip)

    if data is None:
        return None

    # 5. AbuseIPDB enrichment (optional)
    abuse = await _abuseipdb_lookup(ip)
    if abuse is not None:
        data["abuse_score"] = abuse

    # Write through to both caches
    if pool:
        try:
            await pool.execute(
                """
                INSERT INTO geoip_cache
                    (ip, lat, lon, country, city, asn, org, abuse_score, cached_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
                ON CONFLICT (ip) DO UPDATE SET
                    lat = EXCLUDED.lat,
                    lon = EXCLUDED.lon,
                    country = EXCLUDED.country,
                    city = EXCLUDED.city,
                    asn = EXCLUDED.asn,
                    org = EXCLUDED.org,
                    abuse_score = COALESCE(EXCLUDED.abuse_score, geoip_cache.abuse_score),
                    cached_at = NOW()
                """,
                ip, data.get("lat"), data.get("lon"),
                data.get("country"), data.get("city"),
                data.get("asn"), data.get("org"),
                data.get("abuse_score"),
            )
        except Exception as e:
            logger.warning(f"DB cache write failed for {ip}: {e}")

    if r:
        try:
            await r.setex(f"geoip:{ip}", 86400, json.dumps(data))
        except Exception:
            pass

    return data
