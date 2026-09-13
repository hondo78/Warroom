"""Sophos Firewall (SFOS) v23 REST API transport.

One of two transports behind :mod:`app.sfos_client`; the other is the legacy XML
API in :mod:`app.sfos_xml`. Callers should go through the facade rather than
importing a transport directly.

SFOS v23 adds a JSON REST API alongside the XML one. Confirmed against a live
v23 firewall:

* Base URL is ``https://<host>:<port>/api/firewall-config/v1``. The ``/api``
  prefix is required — the documentation overview omits it and that path 404s.
* Authentication is ``Authorization: Bearer <api-key>``. HTTP Basic with the
  XML API's username/password is rejected with 401, so the REST transport needs
  its own credential (``firewall_api_key``) created in the firewall UI under
  the administrator profile that should own the access.
* Unauthenticated requests answer ``401`` with
  ``{"error":"unauthenticated","message":"Token missing or invalid."}``.

Responses are parsed the same way the XML transport parses entities: generically,
by shape rather than by a fixed schema. The published documentation renders its
response schemas client-side, so the exact field names per firmware are not
knowable ahead of time — and the XML transport already learned that lesson
across firmware versions. Any JSON object carrying a host IPv4 plus a name-ish
key is a host record, wherever it sits in the document.

The XML API is *not* removed in v23 — the REST API even exposes
``/administration/xml-api/settings`` to configure it — so this is a second
transport, not a replacement.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import settings
from app.sfos_common import (IP_RE, MAC_RE, NAME_KEYS, extract_host,
                             host_record, is_host_ip)

logger = logging.getLogger(__name__)

DEFAULT_BASE_PATH = "/api/firewall-config/v1"

# Read-only endpoints this client uses. Everything is best-effort: a firmware
# that does not expose one still yields the rest.
EP_DHCP_SERVERS = "/network/dhcp/servers/ipv4"
EP_DHCP_RELAYS = "/network/dhcp/relays/ipv4"
EP_DHCP_SETTINGS = "/network/dhcp/settings/ipv4"
EP_INTERFACES = "/network/interfaces/network-interfaces"
EP_ZONES = "/network/zones"
EP_SYSTEM_SETTINGS = "/administration/system-settings"

# Endpoints scanned for DHCP host records, in order. There is no DHCP *lease*
# endpoint in the v23 API surface — only servers, relays and settings — so
# static reservations are the reliable source, exactly as with the XML API.
DHCP_ENDPOINTS = (EP_DHCP_SERVERS, EP_DHCP_RELAYS, EP_DHCP_SETTINGS)

# Three more places the firewall already knows an internal host by name or MAC.
# The XML API exposed none of them, which is why hostname resolution has only
# ever seen DHCP reservations: a host with a static address and a DNS entry was
# invisible to it. All read-only.
EP_DNS_HOST_ENTRIES = "/network/dns/host-entries"
EP_STATIC_NEIGHBORS = "/network/neighbors/static/ipv4"
EP_MAC_ADDRESSES = "/network/addresses/mac"

# Scanned in order, first answer per IP wins. DHCP reservations lead because an
# operator maintains them deliberately; DNS entries follow; the neighbour and
# MAC tables come last, since they usually carry an address without a name and
# are there to fill in the MAC rather than to name anything.
HOST_RECORD_ENDPOINTS = DHCP_ENDPOINTS + (
    EP_DNS_HOST_ENTRIES, EP_STATIC_NEIGHBORS, EP_MAC_ADDRESSES,
)


class SfosRestError(RuntimeError):
    """A REST call failed in a way the caller should see."""


class SfosRestAuthError(SfosRestError):
    """401/403 — the API key is missing, wrong, or lacks the permission.

    Separate from the generic error so the facade can fall back to the XML
    transport on an auth failure without swallowing real transport errors."""


class SfosRestUnavailable(SfosRestError):
    """404 on the API root — this firmware has no REST API (pre-v23)."""


def configured() -> bool:
    """True when enough is set to attempt a REST call."""
    return bool((settings.firewall_api_host or "").strip()
                and (settings.firewall_api_key or "").strip())


def _base_url() -> str:
    host = (settings.firewall_api_host or "").strip()
    if not host:
        raise SfosRestError("firewall_api_host is not set")
    port = int(settings.firewall_api_port or 4444)
    path = (settings.firewall_rest_base_path or DEFAULT_BASE_PATH).strip()
    if not path.startswith("/"):
        path = "/" + path
    return f"https://{host}:{port}{path.rstrip('/')}"


async def _get(path: str) -> Any:
    """GET one endpoint and return the decoded JSON.

    Raises :class:`SfosRestAuthError` on 401/403 and
    :class:`SfosRestUnavailable` on 404 so the facade can tell "wrong or missing
    credential" and "no REST API here" apart from a genuine outage."""
    key = (settings.firewall_api_key or "").strip()
    if not key:
        raise SfosRestAuthError("firewall_api_key is not set")
    url = _base_url() + path
    verify = bool(settings.firewall_api_verify_tls)
    async with httpx.AsyncClient(verify=verify, timeout=20) as client:
        r = await client.get(url, headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        })
    if r.status_code in (401, 403):
        raise SfosRestAuthError(f"REST auth failed (HTTP {r.status_code})")
    if r.status_code == 404:
        raise SfosRestUnavailable(f"no REST endpoint at {path} (HTTP 404)")
    if r.status_code >= 400:
        raise SfosRestError(f"REST {path} returned HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as e:
        raise SfosRestError(f"invalid JSON from {path}: {e}") from e


# --- generic shape-based parsing --------------------------------------------

def _walk(node: Any):
    """Yield every dict in a JSON document, at any depth."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def _scalars(d: dict) -> dict[str, str]:
    """The dict's scalar fields as {lowercased key: string value}. Nested
    objects are skipped here — ``_walk`` visits them in their own right."""
    out = {}
    for k, v in d.items():
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            out[str(k).lower()] = str(v).strip()
    return out


def parse_dhcp_records(payload: Any) -> dict[str, dict]:
    """Parse a REST response into ``{ip: {"hostname", "mac"}}``.

    Shape-based, mirroring the XML transport: any object carrying a host IPv4
    and a name-ish field is a host record. Netmask/network/broadcast addresses
    are rejected by :func:`app.sfos_common.is_host_ip`, which keeps a DHCP
    server's own config row (name + subnet + gateway) from being read as a
    client."""
    out: dict[str, dict] = {}
    for obj in _walk(payload):
        flat = _scalars(obj)
        if not flat:
            continue
        ip, name, mac = extract_host(flat)
        rec = host_record(ip, name, mac)
        if rec:
            out.setdefault(ip, rec)
    return out


def parse_host_records(payload: Any) -> dict[str, dict]:
    """Like :func:`parse_dhcp_records`, but also keeps rows that carry an IP and
    a MAC without a name.

    That is the shape of a neighbour/ARP entry and of the MAC-address object
    table. Neither names a host, but both know its MAC — and the MAC is what
    host-identity monitoring watches for changes, so a nameless row is still
    worth having."""
    out: dict[str, dict] = {}
    for obj in _walk(payload):
        flat = _scalars(obj)
        if not flat:
            continue
        ip, name, mac = extract_host(flat)
        rec = host_record(ip, name, mac, require_name=False)
        if rec:
            out.setdefault(ip, rec)
    return out


def _merge_records(into: dict[str, dict], new: dict[str, dict]) -> None:
    """Fold ``new`` into ``into``, first non-empty value winning *per field*.

    Not first-record-wins: a DHCP reservation names a host but may carry no MAC,
    while the neighbour table has the MAC and no name. Merging whole records
    would throw one of the two away — which is the entire reason for consulting
    more than one endpoint."""
    for ip, rec in new.items():
        cur = into.setdefault(ip, {"hostname": None, "mac": None})
        for field in ("hostname", "mac"):
            if not cur.get(field) and rec.get(field):
                cur[field] = rec[field]


def _first(flat: dict[str, str], *keys: str) -> str:
    for k in keys:
        if flat.get(k):
            return flat[k]
    return ""


def _cidr_to_netmask(cidr) -> str | None:
    """24 -> "255.255.255.0". The REST API reports a prefix length where the XML
    API reported a dotted mask, and callers were written against the latter."""
    try:
        n = int(cidr)
    except (TypeError, ValueError):
        return None
    if not 0 < n <= 32:
        return None
    bits = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
    return ".".join(str((bits >> sh) & 0xFF) for sh in (24, 16, 8, 0))


def parse_interfaces(payload: Any) -> list[dict]:
    """Parse the interface list into the facade's interface shape.

    Verified against a live v23 firewall, whose records nest what the XML API
    kept flat::

        {"name": "Port3", "hardwareName": "Port3", "type": "physical",
         "enabled": true, "zone": {"name": "MGMT"},
         "ipv4": {"ipv4Address": "172.16.3.1", "cidr": 24,
                  "gatewayIpAddress": "", "assignmentType": "static"}}

    Two details matter. ``type`` already says physical/vlan/xfrm, so the kind is
    read rather than guessed from the name. And the address must be taken from
    ``ipv4Address`` specifically: a DHCP-assigned WAN port carries a populated
    ``gatewayIpAddress`` beside an empty address, so anything scanning the
    record for "an IP" adopts the gateway as the interface's own.

    Falls back to the older flat shape when a record does not look like this, so
    a firmware that reports differently still yields something."""
    out: list[dict] = []
    seen: set[str] = set()
    for obj in _walk(payload):
        if not isinstance(obj, dict):
            continue
        name = str(obj.get("name") or obj.get("hardwareName") or "").strip()
        if not name or name in seen:
            continue
        ipv4 = obj.get("ipv4") if isinstance(obj.get("ipv4"), dict) else None
        zone_obj = obj.get("zone") if isinstance(obj.get("zone"), dict) else None
        itype = str(obj.get("type") or "").strip().lower()

        if ipv4 is not None or zone_obj is not None or itype:
            ip = str((ipv4 or {}).get("ipv4Address") or "").strip()
            rec = {
                "name": name,
                "hardware": str(obj.get("hardwareName") or "").strip() or None,
                "zone": str((zone_obj or {}).get("name") or "").strip(),
                "ip": ip if IP_RE.match(ip) else None,
                "netmask": _cidr_to_netmask((ipv4 or {}).get("cidr")),
                "status": ("enabled" if obj.get("enabled") else "disabled")
                          if "enabled" in obj else None,
                "kind": itype or "physical",
            }
        else:
            flat = _scalars(obj)
            hardware = _first(flat, "hardware", "device", "port")
            zone = _first(flat, "zone", "networkzone", "network_zone")
            ip = _first(flat, "ipaddress", "ip_address", "ipv4address",
                        "ipv4_address", "ip")
            if not (hardware or zone or ip):
                continue
            vlan_id = _first(flat, "vlanid", "vlan_id", "vlan")
            rec = {
                "name": name,
                "hardware": hardware or None,
                "zone": zone,
                "ip": ip if IP_RE.match(ip) else None,
                "netmask": _first(flat, "netmask", "subnetmask", "subnet_mask") or None,
                "status": _first(flat, "status", "state") or None,
                "kind": "vlan" if (vlan_id or "vlan" in name.lower()) else "physical",
            }
        seen.add(name)
        out.append(rec)
    return out


def parse_hostname(payload: Any) -> str | None:
    """Pull the firewall's own hostname out of the system-settings document."""
    for obj in _walk(payload):
        flat = _scalars(obj)
        hn = _first(flat, "hostname", "host_name", "name")
        if hn:
            return hn
    return None


# --- public transport API (mirrors sfos_xml) ---------------------------------

async def fetch_dhcp_records() -> dict[str, dict]:
    """Fetch ``{ip: {hostname, mac}}`` over REST.

    Each DHCP endpoint is best-effort so one missing on a given firmware does
    not lose the others. An auth failure is raised, because falling back to an
    empty map would silently look like "the firewall has no DHCP records"."""
    out: dict[str, dict] = {}
    errors: list[str] = []
    for ep in DHCP_ENDPOINTS:
        try:
            out.update({ip: r for ip, r in parse_dhcp_records(await _get(ep)).items()
                        if ip not in out})
        except SfosRestAuthError:
            raise
        except SfosRestError as e:
            errors.append(f"{ep}: {e}")
    if not out and errors:
        raise SfosRestError("; ".join(errors)[:400])
    return out


async def fetch_host_records() -> dict[str, dict]:
    """Everything the firewall knows about internal hosts, from every endpoint
    that knows something: DHCP reservations, DNS host entries, the static
    neighbour table and the MAC-address objects.

    The XML API exposed only DHCP reservations, so a host with a static address
    and a DNS entry was invisible to hostname resolution. Fields are merged
    rather than records, so a name from one endpoint and a MAC from another end
    up on the same host."""
    out: dict[str, dict] = {}
    errors: list[str] = []
    for ep in HOST_RECORD_ENDPOINTS:
        try:
            _merge_records(out, parse_host_records(await _get(ep)))
        except SfosRestAuthError:
            raise
        except SfosRestError as e:
            errors.append(f"{ep}: {e}")
    if not out and errors:
        raise SfosRestError("; ".join(errors)[:400])
    # A row with neither a name nor a MAC helps nobody; parse_host_records
    # cannot produce one, but a merge of two empty halves could.
    return {ip: r for ip, r in out.items() if r.get("hostname") or r.get("mac")}


async def fetch_dhcp_map() -> dict[str, str]:
    return {ip: r["hostname"] for ip, r in (await fetch_dhcp_records()).items()
            if r.get("hostname")}


async def fetch_device_info() -> dict:
    """The firewall's own identity + interfaces over REST.

    Best-effort per endpoint, matching the XML transport: a firmware that hides
    one still yields the rest."""
    hostname: str | None = None
    interfaces: list[dict] = []
    try:
        hostname = parse_hostname(await _get(EP_SYSTEM_SETTINGS))
    except SfosRestError as e:
        logger.warning(f"device info (REST): system-settings failed: {e}")
    try:
        interfaces = parse_interfaces(await _get(EP_INTERFACES))
    except SfosRestError as e:
        logger.warning(f"device info (REST): interfaces failed: {e}")
    return {"hostname": hostname, "interfaces": interfaces}


async def fetch_raw() -> dict[str, dict]:
    """Diagnostic: the raw response per endpoint, for the admin UI.

    This is how an operator confirms the field mapping on their own firmware —
    the published schemas are rendered client-side and differ by version, so
    seeing the real document beats guessing."""
    out: dict[str, dict] = {}
    for ep in DHCP_ENDPOINTS + (EP_INTERFACES, EP_ZONES, EP_SYSTEM_SETTINGS):
        try:
            payload = await _get(ep)
            out[ep] = {"ok": True, "payload": payload}
        except SfosRestError as e:
            out[ep] = {"ok": False, "error": str(e)[:300]}
    return out


async def probe() -> dict:
    """Is the REST API present and does the key work? Used by mode detection
    and by the admin 'test connection' button."""
    try:
        await _get(EP_ZONES)
        return {"available": True, "authenticated": True, "error": None}
    except SfosRestAuthError as e:
        return {"available": True, "authenticated": False, "error": str(e)}
    except SfosRestUnavailable as e:
        return {"available": False, "authenticated": False, "error": str(e)}
    except SfosRestError as e:
        return {"available": False, "authenticated": False, "error": str(e)}
    except Exception as e:
        # _get() does not wrap the httpx call, so a ConnectError or timeout
        # arrives here as itself. Letting it escape would take auto-detection
        # down with it — and auto-detect exists precisely to survive a REST
        # side that is not answering.
        return {"available": False, "authenticated": False,
                "error": f"{type(e).__name__}: {e}"}
