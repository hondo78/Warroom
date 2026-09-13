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


# Fields that describe a *scope* rather than a host: a DHCP server's own
# configuration row carries a name plus a subnet, a gateway and a lease range.
# Scanning such a row for "the first thing that looks like a host IP" lands on
# the gateway and invents a host there, named after the scope — usually the
# firewall itself, renamed to "lan-dhcp". is_host_ip() cannot catch it: a
# gateway address is a perfectly valid host address.
SCOPE_KEYS = (
    "subnetmask", "subnet_mask", "netmask", "startip", "start_ip", "endip",
    "end_ip", "rangestart", "range_start", "rangeend", "range_end", "gateway",
    "defaultgateway", "default_gateway", "leasetime", "lease_time",
    "primarydnsserver", "secondarydnsserver", "domainname", "domain_name",
)

# Where a host's own address is actually written, in preference order. Checked
# before falling back to "any value shaped like an IP".
IP_KEYS = ("ipaddress", "ip_address", "ipv4address", "ipv4_address", "ip",
           "hostip", "host_ip", "ipaddr", "address", "staticip", "static_ip")


def looks_like_scope(flat: dict[str, str]) -> bool:
    """True when this object describes a subnet/scope, not a single host."""
    return any(k in flat for k in SCOPE_KEYS)


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


def extract_host(flat: dict[str, str]) -> tuple[str, str, str]:
    """(ip, name, mac) for one flattened record, or empty strings.

    Shared by both transports because both had the same hole: scanning a record
    for "the first value that looks like a host IP" lands on a DHCP scope's
    *gateway* and invents a host there, named after the scope — in practice the
    firewall itself, renamed to something like "lan-dhcp". The address is
    therefore read from a field that actually names one first, and a scope row
    carrying no MAC is rejected outright: it describes a subnet, and every
    address in it belongs to the subnet rather than to any host.
    """
    mac = next((v for v in flat.values() if MAC_RE.match(v)), "")
    scope = looks_like_scope(flat)
    if scope and not mac:
        return "", "", ""
    name = next((flat[k] for k in NAME_KEYS if flat.get(k)), "")
    ip = next((flat[k] for k in IP_KEYS
               if IP_RE.match(flat.get(k, "")) and is_host_ip(flat[k])), "")
    if not ip and not scope:
        ip = next((v for v in flat.values() if IP_RE.match(v) and is_host_ip(v)), "")
    return ip, name, mac


def host_record(ip: str, name: str, mac: str = "",
                require_name: bool = True) -> dict | None:
    """Build one ``{"hostname", "mac"}`` record, or None when this is not a
    usable host row. Both transports funnel through here so a record means the
    same thing regardless of which API produced it.

    ``require_name=False`` accepts a row that carries an IP and a MAC but no
    name — the shape of a neighbour/ARP entry, which is worth having for the MAC
    alone. A MAC is what makes that safe: it is the thing a gateway address, a
    DHCP range bound or a netmask never has, so relaxing the name requirement
    does not start pulling infrastructure addresses in as if they were hosts.
    """
    ip = (ip or "").strip()
    name = (name or "").strip()
    mac_n = normalise_mac(mac)
    if not ip:
        return None
    if not IP_RE.match(ip) or not is_host_ip(ip):
        return None
    if name in ("-", "0.0.0.0"):
        name = ""
    if not name and (require_name or not mac_n):
        return None
    return {"hostname": name[:255] or None, "mac": mac_n}
