"""Resolve a NetFlow connection to the *service* behind it.

NetFlow only carries ``(dst_port, protocol)``. Anomaly detection that wants to
reason per service ("is this host odd *for HTTPS*?") needs a stable grouping key
derived from that pair — and it must not explode into thousands of one-member
groups, which is exactly what raw ports do: on this network the top port (443)
carries ~1800 connections while hundreds of ephemeral ports carry exactly one.

The resolution has three tiers:

1. **Well-known service** — the port is in :data:`PORT_SERVICES` → the service
   name ("https", "ssh") plus a coarse :data:`CATEGORY` for roll-ups.
2. **Registered port** — 1024–49151 and unknown → ``port-8123``. Still a stable
   identity: a service we don't have a name for is not the same as noise.
3. **Ephemeral / dynamic** — >= 49152 (or a known P2P range) → collapsed into a
   single ``ephemeral`` group. These are per-session client ports (BitTorrent,
   WebRTC media, passive FTP); treating each as its own service would produce
   groups of size 1, where no population-relative statement is possible.

``protocol`` matters: 53/udp is DNS, 53/tcp is DNS zone transfer; 3478/udp is
STUN media. Where a port means different things per protocol, the map is keyed
by ``(port, proto)`` and falls back to the port-only entry.
"""

from __future__ import annotations

# IANA protocol numbers as they appear in netflow_buckets.protocol.
PROTO_NAMES: dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
}

# Coarse buckets for roll-up views. Every service name maps into exactly one.
CATEGORY: dict[str, str] = {}


def _reg(port: int, name: str, category: str, proto: str | None = None) -> tuple:
    CATEGORY[name] = category
    return ((port, proto), name)


# (port, proto|None) -> service name. proto=None means "any protocol".
PORT_SERVICES: dict[tuple[int, str | None], str] = dict([
    # --- web -----------------------------------------------------------------
    _reg(80, "http", "web"),
    _reg(443, "https", "web"),
    _reg(8080, "http-alt", "web"),
    _reg(8443, "https-alt", "web"),
    _reg(8000, "http-alt", "web"),
    _reg(3000, "http-app", "web"),
    _reg(9443, "https-alt", "web"),
    # --- mail ----------------------------------------------------------------
    _reg(25, "smtp", "mail"),
    _reg(110, "pop3", "mail"),
    _reg(143, "imap", "mail"),
    _reg(465, "smtps", "mail"),
    _reg(587, "submission", "mail"),
    _reg(993, "imaps", "mail"),
    _reg(995, "pop3s", "mail"),
    # --- name resolution -----------------------------------------------------
    _reg(53, "dns", "dns"),
    _reg(853, "dns-tls", "dns"),
    _reg(5353, "mdns", "dns"),
    _reg(137, "netbios-ns", "dns"),
    _reg(138, "netbios-dgm", "dns"),
    # --- remote access -------------------------------------------------------
    _reg(22, "ssh", "remote"),
    _reg(23, "telnet", "remote"),
    _reg(3389, "rdp", "remote"),
    _reg(5900, "vnc", "remote"),
    _reg(5985, "winrm", "remote"),
    _reg(5986, "winrm-https", "remote"),
    _reg(1723, "pptp", "remote"),
    # --- file transfer / shares ----------------------------------------------
    _reg(20, "ftp-data", "file"),
    _reg(21, "ftp", "file"),
    _reg(69, "tftp", "file"),
    _reg(445, "smb", "file"),
    _reg(139, "netbios-ssn", "file"),
    _reg(2049, "nfs", "file"),
    _reg(873, "rsync", "file"),
    # --- databases -----------------------------------------------------------
    _reg(1433, "mssql", "db"),
    _reg(1521, "oracle", "db"),
    _reg(3306, "mysql", "db"),
    _reg(5432, "postgres", "db"),
    _reg(6379, "redis", "db"),
    _reg(9200, "elasticsearch", "db"),
    _reg(11211, "memcached", "db"),
    _reg(27017, "mongodb", "db"),
    # --- infrastructure ------------------------------------------------------
    _reg(67, "dhcp", "infra"),
    _reg(68, "dhcp", "infra"),
    _reg(123, "ntp", "infra"),
    _reg(161, "snmp", "infra"),
    _reg(162, "snmp-trap", "infra"),
    _reg(389, "ldap", "infra"),
    _reg(636, "ldaps", "infra"),
    _reg(514, "syslog", "infra"),
    _reg(1812, "radius", "infra"),
    _reg(1813, "radius-acct", "infra"),
    _reg(88, "kerberos", "infra"),
    _reg(464, "kpasswd", "infra"),
    _reg(546, "dhcpv6", "infra"),
    _reg(547, "dhcpv6", "infra"),
    _reg(1900, "ssdp", "infra"),
    # --- vpn / tunnels -------------------------------------------------------
    _reg(500, "ipsec-ike", "vpn"),
    _reg(4500, "ipsec-nat-t", "vpn"),
    _reg(51820, "wireguard", "vpn"),
    _reg(1194, "openvpn", "vpn"),
    # --- realtime / messaging ------------------------------------------------
    _reg(3478, "stun", "voip"),
    _reg(5349, "turns", "voip"),
    _reg(5060, "sip", "voip"),
    _reg(5061, "sips", "voip"),
    _reg(5222, "xmpp", "chat"),
    _reg(5223, "xmpp-push", "chat"),
    _reg(5228, "gcm", "chat"),
    # --- p2p / anonymity -----------------------------------------------------
    _reg(6881, "bittorrent", "p2p"),
    _reg(6969, "bittorrent-tracker", "p2p"),
    _reg(9001, "tor", "p2p"),
    _reg(9030, "tor-dir", "p2p"),
])

# Fallback identities that are not real services.
EPHEMERAL = "ephemeral"      # per-session client ports, collapsed into one group
UNKNOWN = "unknown"          # port missing from the flow record
CATEGORY[EPHEMERAL] = "ephemeral"
CATEGORY[UNKNOWN] = "other"
CATEGORY["registered"] = "other"

# Ports at/above this are dynamic/private per IANA — client-side session ports.
EPHEMERAL_MIN = 49152

# Ports whose regular cadence is benign by design (NTP, DNS, DHCP, mDNS, SSDP,
# SNMP, STUN, WireGuard keepalive). Kept here so beacon logic and service logic
# share one definition.
BENIGN_PERIODIC = frozenset({
    53, 67, 68, 123, 137, 138, 161, 500, 546, 547, 1900, 3478, 4500, 5353, 51820,
})


def proto_name(protocol: int | None) -> str | None:
    """IANA protocol number -> name ("TCP"), or ``proto-N`` when unmapped."""
    if protocol is None:
        return None
    return PROTO_NAMES.get(protocol) or f"proto-{protocol}"


def service_name(port: int | None, protocol: int | None = None) -> str | None:
    """Well-known service name for ``port`` (protocol-aware), else ``None``.

    Drop-in replacement for the old ``_PORT_SERVICES.get(port)`` lookups: it
    returns ``None`` for anything not well-known, so display code keeps showing
    a blank service column rather than a synthetic label."""
    if port is None:
        return None
    proto = (proto_name(protocol) or "").lower() or None
    return PORT_SERVICES.get((port, proto)) or PORT_SERVICES.get((port, None))


def resolve(port: int | None, protocol: int | None = None) -> dict:
    """Full service identity for one connection.

    Returns ``{key, label, category, well_known}`` where ``key`` is the stable
    grouping identity for per-service analysis:

    >>> resolve(443, 6)["key"]
    'https'
    >>> resolve(8123, 6)["key"]
    'port-8123'
    >>> resolve(54709, 6)["key"]
    'ephemeral'

    ``label`` is what the UI shows (``https (443/TCP)``); ``well_known`` says
    whether tier 1 matched, which callers use to decide how much to trust the
    service identity.

    Note the granularity: every unknown registered port stays its own key, which
    is what peer-group analysis needs (port 8082 is its own population). For
    *counting* distinct services use :func:`service_class`, which collapses those
    into one bucket — otherwise "number of services" just re-measures "number of
    ports"."""
    pn = proto_name(protocol)
    # Port 0 is NetFlow's "no port" (ICMP and friends), not a service.
    if port is None or port <= 0:
        return {"key": UNKNOWN, "label": UNKNOWN, "category": "other", "well_known": False}

    name = service_name(port, protocol)
    if name:
        return {
            "key": name,
            "label": f"{name} ({port}/{pn})" if pn else f"{name} ({port})",
            "category": CATEGORY.get(name, "other"),
            "well_known": True,
        }
    if port >= EPHEMERAL_MIN:
        return {"key": EPHEMERAL, "label": "ephemeral (>=49152)",
                "category": "ephemeral", "well_known": False}
    return {"key": f"port-{port}", "label": f"{port}/{pn}" if pn else str(port),
            "category": "other", "well_known": False}


REGISTERED = "registered"    # unknown but non-ephemeral port, as a single class


def service_class(port: int | None, protocol: int | None = None) -> str:
    """Coarse service identity for **counting distinct services**.

    Same as :func:`resolve`'s key for well-known services, but every unnamed
    registered port collapses into ``registered`` and every dynamic port into
    ``ephemeral``. Without this, "how many services does this host speak?"
    silently becomes "how many ports did it touch?" — one host with 6500
    ephemeral peers scored as 6500 distinct services, which is both wrong and a
    duplicate of the existing ports dimension."""
    key = resolve(port, protocol)["key"]
    return REGISTERED if key.startswith("port-") else key


def category_of(service_key: str) -> str:
    """Coarse category for a service key produced by :func:`resolve`."""
    if service_key.startswith("port-"):
        return "other"
    return CATEGORY.get(service_key, "other")
