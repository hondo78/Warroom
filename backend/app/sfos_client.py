"""Sophos Firewall (SFOS) client — picks a transport and speaks one language.

SFOS v23 introduced a JSON REST API alongside the long-standing XML API. Both
are supported, because both are real: v23 keeps the XML API (and even exposes
``/administration/xml-api/settings`` over REST to configure it), while firewalls
below v23 have no REST API at all. One Warroom install may point at either.

``firewall_api_mode`` decides:

* ``auto`` (default) — use REST when an API key is configured and the firewall
  answers; otherwise XML. The choice is probed once and remembered, and a REST
  auth failure falls back to XML rather than losing hostname resolution.
* ``rest`` / ``xml`` — pin one transport. Errors surface instead of falling
  back, which is what an operator wants while setting the transport up.

The two transports need *different credentials*: XML uses
``firewall_api_user``/``firewall_api_password``, REST uses ``firewall_api_key``
(HTTP Basic is rejected by the REST API). Configuring one does not configure the
other, so ``auto`` degrades to XML until a key exists.

Callers import from here, never from ``sfos_xml`` / ``sfos_rest`` directly.
"""
from __future__ import annotations

import logging

from app.config import settings
from app import sfos_rest, sfos_xml
from app.sfos_rest import SfosRestAuthError, SfosRestError, SfosRestUnavailable

logger = logging.getLogger(__name__)

# Pure helpers re-exported so existing importers keep working unchanged.
from app.sfos_xml import (  # noqa: E402,F401
    device_ips,
    parse_dhcp,
    parse_dhcp_records,
    probe_entities,
)

# Remembered result of auto-detection: None = not probed yet, else "rest"/"xml".
_auto_transport: str | None = None


def reset_transport_cache() -> None:
    """Forget the auto-detected transport. Called when firewall settings change
    so a newly added API key takes effect without a restart."""
    global _auto_transport
    _auto_transport = None


def mode() -> str:
    """The configured mode, normalised."""
    m = (getattr(settings, "firewall_api_mode", "") or "auto").strip().lower()
    return m if m in ("auto", "xml", "rest") else "auto"


async def active_transport() -> str:
    """Which transport to use right now: ``"rest"`` or ``"xml"``.

    In ``auto`` the answer is probed once and cached — the probe is a real HTTP
    round-trip, and doing it per DHCP refresh would triple the traffic to the
    firewall for no new information."""
    global _auto_transport
    m = mode()
    if m in ("xml", "rest"):
        return m
    if _auto_transport:
        return _auto_transport
    if not sfos_rest.configured():
        _auto_transport = "xml"
        return _auto_transport
    result = await sfos_rest.probe()
    _auto_transport = "rest" if result.get("authenticated") else "xml"
    if _auto_transport == "xml":
        logger.info(f"SFOS auto-detect: falling back to XML API ({result.get('error')})")
    else:
        logger.info("SFOS auto-detect: using the v23 REST API")
    return _auto_transport


async def _try_rest(fn_name: str, *args):
    """Run a REST call, falling back to XML in ``auto`` when the REST side turns
    out not to work. In a pinned mode the error propagates instead."""
    try:
        return await getattr(sfos_rest, fn_name)(*args)
    except Exception as e:
        # Deliberately broad. Catching only the two *expected* REST errors meant
        # an HTTP 500, malformed JSON, or a bare httpx ConnectError/timeout
        # escaped past the fallback into the caller's own `except Exception`,
        # which serves stale data for the whole outage — while the XML API was
        # working the entire time. Any REST failure is a reason to try XML.
        if mode() == "rest":
            raise
        logger.warning(f"SFOS REST unusable ({type(e).__name__}: {e}); "
                       f"falling back to the XML API")
        reset_transport_cache()
        global _auto_transport
        _auto_transport = "xml"
        return await getattr(sfos_xml, fn_name)(*args)


async def fetch_dhcp_records() -> dict[str, dict]:
    """The firewall's DHCP ``{ip: {hostname, mac}}`` records."""
    if await active_transport() == "rest":
        return await _try_rest("fetch_dhcp_records")
    return await sfos_xml.fetch_dhcp_records()


async def fetch_dhcp_map() -> dict[str, str]:
    """The firewall's DHCP IP→hostname mapping (hostname-only)."""
    return {ip: r["hostname"] for ip, r in (await fetch_dhcp_records()).items()}


async def fetch_device_info() -> dict:
    """The firewall's own hostname + interfaces."""
    if await active_transport() == "rest":
        return await _try_rest("fetch_device_info")
    return await sfos_xml.fetch_device_info()


async def fetch_dhcp_raw() -> tuple[int, str]:
    """Diagnostic passthrough for the XML API (raw ``reqxml`` response).

    REST has no single raw document, so the admin diagnostic uses
    :func:`fetch_rest_raw` for that transport instead."""
    return await sfos_xml.fetch_dhcp_raw()


async def fetch_rest_raw() -> dict[str, dict]:
    """Diagnostic: raw JSON per REST endpoint, so an operator can confirm the
    field mapping against their own firmware."""
    return await sfos_rest.fetch_raw()


async def transport_status() -> dict:
    """What the admin UI shows: the configured mode, what is actually in use,
    and whether each transport is usable."""
    rest_probe = await sfos_rest.probe() if sfos_rest.configured() else {
        "available": False, "authenticated": False,
        "error": "firewall_api_key is not set",
    }
    return {
        "mode": mode(),
        "active": await active_transport(),
        "rest": rest_probe,
        "rest_configured": sfos_rest.configured(),
        "xml_configured": bool(settings.firewall_api_user
                               and settings.firewall_api_password),
    }
