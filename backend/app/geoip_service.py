import ipaddress
import json
import logging
from pathlib import Path

import httpx
import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import GeoIPCache

logger = logging.getLogger(__name__)

GEOIP_CITY_PATH = Path("/app/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_PATH = Path("/app/geoip/GeoLite2-ASN.mmdb")

_redis: redis.Redis | None = None
_city_reader = None
_asn_reader = None


async def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def _get_city_reader():
    global _city_reader
    if _city_reader is None and GEOIP_CITY_PATH.exists():
        import geoip2.database
        _city_reader = geoip2.database.Reader(str(GEOIP_CITY_PATH))
        logger.info(f"Loaded MaxMind City DB: {GEOIP_CITY_PATH}")
    return _city_reader


def _get_asn_reader():
    global _asn_reader
    if _asn_reader is None and GEOIP_ASN_PATH.exists():
        import geoip2.database
        _asn_reader = geoip2.database.Reader(str(GEOIP_ASN_PATH))
        logger.info(f"Loaded MaxMind ASN DB: {GEOIP_ASN_PATH}")
    return _asn_reader


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


async def lookup_ip(ip: str, db: AsyncSession) -> dict | None:
    if not ip or not is_public_ip(ip):
        return None

    # Check Redis cache first
    try:
        r = await get_redis()
        cached = await r.get(f"geoip:{ip}")
        if cached:
            return json.loads(cached)
    except Exception:
        pass

    # Check DB cache
    result = await db.execute(select(GeoIPCache).where(GeoIPCache.ip == ip))
    cached_entry = result.scalar_one_or_none()
    if cached_entry:
        data = {
            "ip": ip,
            "lat": cached_entry.lat,
            "lon": cached_entry.lon,
            "country": cached_entry.country,
            "city": cached_entry.city,
            "asn": cached_entry.asn,
            "org": cached_entry.org,
            "abuse_score": cached_entry.abuse_score,
        }
        try:
            r = await get_redis()
            await r.setex(f"geoip:{ip}", 86400, json.dumps(data))
        except Exception:
            pass
        return data

    # Try MaxMind local DB
    geo_data = _lookup_maxmind(ip)

    # Fallback to ip-api.com
    if geo_data is None:
        geo_data = await _lookup_ip_api(ip)

    if geo_data is None:
        return None

    # Check AbuseIPDB
    if settings.abuseipdb_api_key:
        abuse_score = await _lookup_abuseipdb(ip)
        geo_data["abuse_score"] = abuse_score

    # Cache in DB
    cache_entry = GeoIPCache(
        ip=ip,
        lat=geo_data.get("lat"),
        lon=geo_data.get("lon"),
        country=geo_data.get("country"),
        city=geo_data.get("city"),
        asn=geo_data.get("asn"),
        org=geo_data.get("org"),
        abuse_score=geo_data.get("abuse_score"),
    )
    await db.merge(cache_entry)
    await db.commit()

    # Cache in Redis
    try:
        r = await get_redis()
        await r.setex(f"geoip:{ip}", 86400, json.dumps(geo_data))
    except Exception:
        pass

    return geo_data


def _lookup_maxmind(ip: str) -> dict | None:
    city_reader = _get_city_reader()
    if city_reader is None:
        return None
    try:
        response = city_reader.city(ip)
        data = {
            "ip": ip,
            "lat": response.location.latitude,
            "lon": response.location.longitude,
            "country": response.country.iso_code,
            "city": response.city.name,
            "asn": None,
            "org": None,
            "abuse_score": None,
        }
    except Exception:
        return None

    # Enrich with ASN data
    asn_reader = _get_asn_reader()
    if asn_reader:
        try:
            asn_response = asn_reader.asn(ip)
            data["asn"] = f"AS{asn_response.autonomous_system_number}"
            data["org"] = asn_response.autonomous_system_organization
        except Exception:
            pass

    return data


async def _lookup_ip_api(ip: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,org")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "lat": data["lat"],
                        "lon": data["lon"],
                        "country": data.get("countryCode"),
                        "city": data.get("city"),
                        "asn": data.get("as"),
                        "org": data.get("org"),
                        "abuse_score": None,
                    }
    except Exception as e:
        logger.warning(f"ip-api.com lookup failed for {ip}: {e}")
    return None


async def _lookup_abuseipdb(ip: str) -> int | None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
            )
            if resp.status_code == 200:
                return resp.json()["data"]["abuseConfidenceScore"]
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
    return None
