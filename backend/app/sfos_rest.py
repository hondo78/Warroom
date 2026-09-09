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
from app.sfos_common import IP_RE, MAC_RE, NAME_KEYS, host_record, is_host_ip

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
        ip = next((v for v in flat.values() if IP_RE.match(v) and is_host_ip(v)), "")
        name = next((flat[k] for k in NAME_KEYS if flat.get(k)), "")
        mac = next((v for v in flat.values() if MAC_RE.match(v)), "")
        rec = host_record(ip, name, mac)
        if rec:
            out.setdefault(ip, rec)
    return out


def _first(flat: dict[str, str], *keys: str) -> str:
    for k in keys:
        if flat.get(k):
            return flat[k]
    return ""


def parse_interfaces(payload: Any) -> list[dict]:
    """Parse the interface list into the facade's interface shape.

    An object counts as an interface when it has a name and at least one of the
    interface-ish fields (hardware / zone / IP). VLANs arrive in the same list
    on the REST API rather than as a separate entity, so ``kind`` is derived
    from whatever the record says about itself."""
    out: list[dict] = []
    seen: set[str] = set()
    for obj in _walk(payload):
        flat = _scalars(obj)
        name = _first(flat, "name", "interfacename", "interface_name", "hardware")
        if not name or name in seen:
            continue
        hardware = _first(flat, "hardware", "device", "port")
        zone = _first(flat, "zone", "networkzone", "network_zone")
        ip = _first(flat, "ipaddress", "ip_address", "ipv4address", "ipv4_address", "ip")
        netmask = _first(flat, "netmask", "subnetmask", "subnet_mask", "prefix")
        if not (hardware or zone or ip):
            continue
        vlan_id = _first(flat, "vlanid", "vlan_id", "vlan")
        kind = "vlan" if (vlan_id or "vlan" in name.lower()) else "physical"
        seen.add(name)
        out.append({
            "name": name,
            "hardware": hardware or None,
            "zone": zone,
            "ip": ip if IP_RE.match(ip) else None,
            "netmask": netmask or None,
            "status": _first(flat, "status", "state") or None,
            "kind": kind,
        })
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


async def fetch_dhcp_map() -> dict[str, str]:
    return {ip: r["hostname"] for ip, r in (await fetch_dhcp_records()).items()}


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
