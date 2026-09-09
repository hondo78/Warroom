"""Primitives shared by the two Sophos Firewall (SFOS) transports.

The XML API (``sfos_xml``) and the v23 REST API (``sfos_rest``) return very
different documents but describe the same things: DHCP host records and the
firewall's own interfaces. Both parse *generically* — any record carrying a host
IPv4 plus a name-ish field is a host record — so firmware schema drift does not
break the mapping. Keeping the shape rules in one place is what lets the two
transports produce interchangeable results.
"""
from __future__ import annotations

import re

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

# Field names (lowercased) that hold the client/host name. The XML entities and
# the REST schemas spell this differently across firmware versions, so both
# transports check the same ordered list.
NAME_KEYS = ("hostname", "host_name", "name", "host", "clientname",
             "client_name", "devicename", "device_name")


def is_host_ip(ip: str) -> bool:
    """A real host address — not a netmask / network / broadcast (which appear
    in the DHCP server config record alongside the server's own name)."""
    o = ip.split(".")
    if len(o) != 4:
        return False
    try:
        a, b, c, d = (int(x) for x in o)
    except ValueError:
        return False
    if not all(0 <= x <= 255 for x in (a, b, c, d)):
        return False
    if a in (0, 255):          # 0.0.0.0 / 255.x netmask
        return False
    if d in (0, 255):          # network / broadcast address
        return False
    return True


def normalise_mac(mac: str) -> str | None:
    """Lowercase colon-separated MAC, or None when it is not one."""
    mac = (mac or "").strip()
    if not MAC_RE.match(mac):
        return None
    return mac.lower().replace("-", ":")


def host_record(ip: str, name: str, mac: str = "") -> dict | None:
    """Build one ``{"hostname", "mac"}`` record, or None when this is not a
    usable host row. Both transports funnel through here so a record means the
    same thing regardless of which API produced it."""
    ip = (ip or "").strip()
    name = (name or "").strip()
    if not ip or not name:
        return None
    if not IP_RE.match(ip) or not is_host_ip(ip):
        return None
    if name in ("-", "0.0.0.0"):
        return None
    return {"hostname": name[:255], "mac": normalise_mac(mac)}
