"""Sophos Firewall (SFOS) XML API transport.

One of two transports behind :mod:`app.sfos_client`; the other is the v23
REST API in :mod:`app.sfos_rest`. Callers should go through the facade
rather than importing a transport directly.

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
from app.sfos_common import (IP_RE, MAC_RE, NAME_KEYS, extract_host,
                             host_record, is_host_ip)

logger = logging.getLogger(__name__)

def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&apos;"))


def _build_reqxml(entity: str) -> str:
    user = _xml_escape(settings.firewall_api_user or "")
    pw = _xml_escape(settings.firewall_api_password or "")
    gets = "".join(f"<{e.strip()}/>" for e in (entity or "").split(",") if e.strip())
    return (f"<Request><Login><Username>{user}</Username>"
            f"<Password>{pw}</Password></Login><Get>{gets}</Get></Request>")


def _login_failure_hint(status: str) -> str:
    """Turn SFOS's one-line login rejection into something actionable.

    SFOS answers ``Authentication Failure`` for three unrelated causes, and the
    response says nothing about which: a wrong password, a source IP that is not
    on the API allow-list, and an account whose profile lacks API rights. An
    operator reading the bare status has no way to tell them apart and will
    almost always re-check the password — which is the least likely of the
    three, because the allow-list is per-IP and quietly invalidated whenever the
    address Warroom is seen from changes.

    Note the address the firewall sees is the *Docker host's* outbound IP, not
    this container's: outbound container traffic is SNATed. Allow-listing the
    container subnet therefore has no effect.
    """
    if "success" in status.lower():
        return status
    return (f"{status} — SFOS reports this for a wrong password, a source IP "
            f"that is not allow-listed, and a profile without API rights alike. "
            f"Check, in this order: Administration › API access (the firewall "
            f"must list the Docker HOST's IP, not the container's), "
            f"Profiles › Device access (API permission on the profile), then "
            f"the password.")


def parse_dhcp_records(xml_text: str) -> tuple[dict[str, dict], str | None]:
    """Parse an SFOS API response into {ip: {"hostname", "mac"}}. Returns
    (records, error).

    Generic: any element whose children include a host IPv4 value and a name-ish
    value is a host record; the MAC (if present) is captured too. Survives
    firmware schema drift; netmask/network/broadcast IPs are skipped."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {}, f"invalid XML from firewall: {e}"

    st = root.find(".//Login/status")
    if st is not None and "success" not in (st.text or "").lower():
        return {}, _login_failure_hint((st.text or "authentication failed").strip())

    out: dict[str, dict] = {}
    for rec in root.iter():
        kids = {c.tag.lower(): (c.text or "").strip() for c in list(rec)}
        if not kids:
            continue
        ip, name, mac = extract_host(kids)
        rec_out = host_record(ip, name, mac)
        if rec_out:
            out.setdefault(ip, rec_out)
    return out, None


def parse_dhcp(xml_text: str) -> tuple[dict[str, str], str | None]:
    """Parse into {ip: hostname} (compat wrapper over parse_dhcp_records)."""
    recs, err = parse_dhcp_records(xml_text)
    return {ip: r["hostname"] for ip, r in recs.items()}, err


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


# Candidate DHCP entity names across SFOS firmware versions. We query the
# configured entity plus these; invalid ones just return a harmless per-entity
# 529 while valid ones return their records in the same response.
_DHCP_CANDIDATES = ("DHCPServer", "DHCPStaticMACEntry", "DHCPStaticEntry",
                    "DHCPLease", "DHCPRelay")


def _entities() -> str:
    ordered: list[str] = []
    for e in [x.strip() for x in (settings.firewall_dhcp_entity or "").split(",") if x.strip()] \
            + list(_DHCP_CANDIDATES):
        if e not in ordered:
            ordered.append(e)
    return ",".join(ordered)


async def fetch_dhcp_raw() -> tuple[int, str]:
    """Diagnostic: the raw firewall response for the queried DHCP entities."""
    return await _post_reqxml(_entities())


def probe_entities(xml_text: str) -> dict[str, dict]:
    """Per top-level entity tag: its Status code/text and how many child fields —
    so the operator sees which entity name is valid + carries records."""
    out: dict[str, dict] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for child in root:
        if child.tag == "Login":
            continue
        st = child.find("Status")
        info = out.setdefault(child.tag, {"count": 0, "status": None, "code": None})
        if st is not None:
            info["status"] = (st.text or "").strip()
            info["code"] = st.get("code")
        # a real record has field children beyond a lone <Status>
        if any(c.tag != "Status" for c in child):
            info["count"] += 1
    return out


async def fetch_dhcp_records() -> dict[str, dict]:
    """Fetch the firewall's DHCP {ip: {hostname, mac}} records. Raises on
    config/transport errors so the caller can surface them."""
    status, text = await _post_reqxml(_entities())
    if status >= 400:
        raise RuntimeError(f"firewall returned HTTP {status}")
    recs, err = parse_dhcp_records(text)
    if err:
        raise RuntimeError(f"SFOS API: {err}")
    return recs


async def fetch_host_records() -> dict[str, dict]:
    """The same records as :func:`fetch_dhcp_records`.

    Present so the facade can ask either transport the same question. The REST
    transport answers it from four endpoints; the XML API exposes only DHCP
    reservations, so here the richer question has the narrower answer rather
    than no answer — and the facade does not need to know which transport it is
    talking to."""
    return await fetch_dhcp_records()


async def fetch_dhcp_map() -> dict[str, str]:
    """Fetch the firewall's DHCP IP→hostname mapping (hostname-only)."""
    return {ip: r["hostname"] for ip, r in (await fetch_dhcp_records()).items()}


# --- Device identity + interfaces (the firewall reporting on itself) ----------

def _iface_zone(el: ET.Element) -> str:
    return (el.findtext("NetworkZone") or el.findtext("Zone") or "").strip()


async def fetch_device_info() -> dict:
    """Read the firewall's own identity + interfaces directly from the XML API.

    Returns ``{"hostname": str|None, "interfaces": [{name, hardware, zone, ip,
    netmask, status, kind}]}``. Each entity is fetched best-effort, so a firmware
    that hides one (Interface/VLAN/AdminSettings) still yields the rest. Raises
    only when the API is not configured/reachable at all."""
    host = (settings.firewall_api_host or "").strip()
    if not host:
        raise RuntimeError("firewall_api_host is not set")

    hostname: str | None = None
    interfaces: list[dict] = []

    # 1) hostname from AdminSettings → HostnameSettings/HostName
    try:
        _, txt = await _post_reqxml("AdminSettings")
        root = ET.fromstring(txt)
        hn = (root.findtext(".//HostnameSettings/HostName")
              or root.findtext(".//HostName") or "").strip()
        hostname = hn or None
    except Exception as e:
        logger.warning(f"device info: AdminSettings failed: {e}")

    # 2) physical interfaces
    try:
        _, txt = await _post_reqxml("Interface")
        root = ET.fromstring(txt)
        for el in root.findall("Interface"):
            name = (el.findtext("Name") or el.findtext("Hardware") or "").strip()
            if not name:
                continue
            ip = (el.findtext(".//IPAddress") or "").strip()
            interfaces.append({
                "name": name,
                "hardware": (el.findtext("Hardware") or "").strip() or None,
                "zone": _iface_zone(el),
                "ip": ip if IP_RE.match(ip) else None,
                "netmask": (el.findtext(".//Netmask") or "").strip() or None,
                "status": (el.findtext("Status") or "").strip() or None,
                "kind": "physical",
            })
    except Exception as e:
        logger.warning(f"device info: Interface failed: {e}")

    # 3) VLAN interfaces (carry their own IP/zone)
    try:
        _, txt = await _post_reqxml("VLAN")
        root = ET.fromstring(txt)
        for el in root.findall("VLAN"):
            name = (el.findtext("Name") or "").strip()
            if not name:
                continue
            ip = (el.findtext("IPAddress") or "").strip()
            interfaces.append({
                "name": name,
                "hardware": (el.findtext("Hardware") or "").strip() or None,
                "zone": (el.findtext("Zone") or "").strip(),
                "ip": ip if IP_RE.match(ip) else None,
                "netmask": (el.findtext("Netmask") or "").strip() or None,
                "status": None,
                "kind": "vlan",
            })
    except Exception as e:
        logger.warning(f"device info: VLAN failed: {e}")

    return {"hostname": hostname, "interfaces": interfaces}


def device_ips(info: dict) -> set[str]:
    """The set of IPs configured on the firewall's own interfaces."""
    return {i["ip"] for i in info.get("interfaces", []) if i.get("ip")}
