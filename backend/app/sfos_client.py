"""Sophos Firewall (SFOS) XML API client.

Reads DHCP IP↔hostname mappings from the firewall to enrich the internal-hosts
inventory. The SFOS XML API lives at ``https://<host>:<port>/webconsole/APIController``
and takes a ``reqxml`` form field carrying a
``<Request><Login>…</Login><Get><entity/></Get></Request>`` document.

DHCP static/reserved entries — and, where the firmware exposes them, dynamic
leases — carry an IP plus a client name. We parse them **generically** (any
record that has an IPv4 child and a name-ish child) so schema differences
between firmware versions don't break the mapping. The entity name(s) queried
are configurable (``firewall_dhcp_entity``, comma-separated) for the same reason.

The admin interface uses a self-signed cert, so TLS verification is off by
default (``firewall_api_verify_tls``); prefer pinning/trusting it if you can.
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Child tags (lowercased) that hold the client/host name in the various DHCP
# entities across SFOS firmware versions.
_NAME_KEYS = ("hostname", "host_name", "name", "host", "clientname",
              "client_name", "devicename", "device_name")


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&apos;"))


def _build_reqxml(entity: str) -> str:
    user = _xml_escape(settings.firewall_api_user or "")
    pw = _xml_escape(settings.firewall_api_password or "")
    gets = "".join(f"<{e.strip()}/>" for e in (entity or "").split(",") if e.strip())
    return (f"<Request><Login><Username>{user}</Username>"
            f"<Password>{pw}</Password></Login><Get>{gets}</Get></Request>")


def parse_dhcp(xml_text: str) -> tuple[dict[str, str], str | None]:
    """Parse an SFOS API response into {ip: hostname}. Returns (map, error).

    Generic: any element whose children include an IPv4 value and a name-ish
    value is treated as a host record. This survives firmware schema drift."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {}, f"invalid XML from firewall: {e}"

    st = root.find(".//Login/status")
    if st is not None and "success" not in (st.text or "").lower():
        return {}, (st.text or "authentication failed").strip()

    out: dict[str, str] = {}
    for rec in root.iter():
        kids = {c.tag.lower(): (c.text or "").strip() for c in list(rec)}
        if not kids:
            continue
        ip = next((v for v in kids.values() if _IP_RE.match(v)), "")
        name = next((kids[k] for k in _NAME_KEYS if kids.get(k)), "")
        if ip and name and name not in ("-", "0.0.0.0"):
            out.setdefault(ip, name[:255])
    return out, None


async def _post_reqxml(entity: str) -> tuple[int, str]:
    """POST a <Get><entity/></Get> request to the SFOS API. SFOS expects the
    request as a multipart form field 'reqxml' (like curl -F), not urlencoded.
    Returns (http_status, response_text)."""
    host = (settings.firewall_api_host or "").strip()
    if not host:
        raise RuntimeError("firewall_api_host is not set")
    port = int(settings.firewall_api_port or 4444)
    if not (settings.firewall_api_user and settings.firewall_api_password):
        raise RuntimeError("firewall_api_user / firewall_api_password not set")
    url = f"https://{host}:{port}/webconsole/APIController"
    reqxml = _build_reqxml(entity)
    verify = bool(settings.firewall_api_verify_tls)
    async with httpx.AsyncClient(verify=verify, timeout=20) as client:
        r = await client.post(url, files={"reqxml": (None, reqxml, "text/xml")})
        return r.status_code, r.text


async def fetch_dhcp_raw() -> tuple[int, str]:
    """Diagnostic: the raw firewall response for the configured DHCP entity."""
    return await _post_reqxml(settings.firewall_dhcp_entity or "DHCPStaticEntry")


async def fetch_dhcp_map() -> dict[str, str]:
    """Fetch the firewall's DHCP IP→hostname mapping. Raises on config/transport
    errors so the caller can surface them (the resolver swallows + logs)."""
    status, text = await _post_reqxml(settings.firewall_dhcp_entity or "DHCPStaticEntry")
    if status >= 400:
        raise RuntimeError(f"firewall returned HTTP {status}")
    mapping, err = parse_dhcp(text)
    if err:
        raise RuntimeError(f"SFOS API: {err}")
    return mapping
