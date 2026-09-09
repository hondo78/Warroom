from sqlalchemy import Boolean, Column, String, Text, Float, Integer, BigInteger, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(255), primary_key=True)
    alert_type = Column(String(255))
    severity = Column(String(50))
    category = Column(String(255))
    description = Column(Text)
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    tenant_id = Column(String(255))
    managed_agent_name = Column(String(255))
    created_at = Column(DateTime(timezone=True))
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    raw_data = Column(JSONB)
    attacker_lat = Column(Float)
    attacker_lon = Column(Float)
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged_action = Column(String(50), nullable=True)


class O365AuditLog(Base):
    """Microsoft 365 login audit records (Management Activity API,
    Audit.AzureActiveDirectory — UserLoggedIn / UserLoginFailed)."""

    __tablename__ = "o365_audit_logs"

    id = Column(String(255), primary_key=True)  # audit record GUID
    operation = Column(String(255))             # UserLoggedIn | UserLoginFailed
    workload = Column(String(100))
    user_id = Column(String(255))               # UPN
    client_ip = Column(String(64))
    result_status = Column(String(50))
    logon_error = Column(String(255))
    user_agent = Column(String(512))
    application_id = Column(String(255))
    created_at = Column(DateTime(timezone=True))
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    raw_data = Column(JSONB)
    attacker_lat = Column(Float)
    attacker_lon = Column(Float)
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))


class ShodanHost(Base):
    """Long-term store of Shodan host intelligence harvested via OSINT lookups —
    open ports and known CVEs per IP, geo-located for the map layers."""

    __tablename__ = "shodan_hosts"

    ip = Column(String(64), primary_key=True)
    lat = Column(Float)
    lon = Column(Float)
    country = Column(String(100))
    city = Column(String(255))
    org = Column(String(255))
    asn = Column(String(64))
    os = Column(String(120))
    ports = Column(JSONB)        # list[int]
    vulns = Column(JSONB)        # list[str]  (CVE ids)
    hostnames = Column(JSONB)    # list[str]
    tags = Column(JSONB)         # list[str]
    shodan_last_update = Column(String(64))   # Shodan's own "last_update" string
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class OsintResult(Base):
    """Long-term history of every OSINT lookup (IP / domain / URL). The cheap
    providers only live ~1h in Redis; this keeps a searchable record."""

    __tablename__ = "osint_results"

    value = Column(String(2048), primary_key=True)   # the IP / domain / URL
    indicator_type = Column(String(16))              # ip | domain | url
    abuse_score = Column(Integer)                    # AbuseIPDB confidence %
    vt_malicious = Column(Integer)                   # VirusTotal malicious count
    greynoise = Column(String(32))                   # classification
    intelix_category = Column(String(120))
    country = Column(String(100))
    city = Column(String(255))
    org = Column(String(255))
    asn = Column(String(64))
    lat = Column(Float)
    lon = Column(Float)
    raw = Column(JSONB)                              # full merged payload
    lookup_count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Event(Base):
    __tablename__ = "events"

    id = Column(String(255), primary_key=True)
    event_type = Column(String(255))
    severity = Column(String(50))
    name = Column(String(500))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    group_name = Column(String(255))
    created_at = Column(DateTime(timezone=True))
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    raw_data = Column(JSONB)
    attacker_lat = Column(Float)
    attacker_lon = Column(Float)
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))


class Detection(Base):
    __tablename__ = "detections"

    id = Column(String(255), primary_key=True)
    detection_type = Column(String(255))
    severity = Column(String(50))
    description = Column(Text)
    source_ip = Column(String(45))
    device_name = Column(String(255))
    created_at = Column(DateTime(timezone=True))
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    raw_data = Column(JSONB)
    attacker_lat = Column(Float)
    attacker_lon = Column(Float)
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))


class FirewallLocation(Base):
    __tablename__ = "firewall_locations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    ip = Column(String(45))
    lat = Column(Float, nullable=False)
    lon = Column(Float, nullable=False)
    country = Column(String(100))
    city = Column(String(255))


class FirewallLog(Base):
    __tablename__ = "firewall_logs"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    log_type = Column(String(50))
    log_subtype = Column(String(50))
    severity = Column(String(20))
    firewall_name = Column(String(255))
    firewall_ip = Column(String(45))
    source_ip = Column(String(45))
    source_port = Column(Integer)
    destination_ip = Column(String(45))
    destination_port = Column(Integer)
    protocol = Column(String(20))
    rule_name = Column(String(255))
    policy_name = Column(String(255))
    action = Column(String(50))
    message = Column(Text)
    threat_name = Column(String(255))
    user_name = Column(String(255))
    created_at = Column(DateTime(timezone=True))
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    raw_data = Column(JSONB)
    attacker_lat = Column(Float)
    attacker_lon = Column(Float)
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))
    attacker_asn = Column(String(255))
    attacker_org = Column(String(255))


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String(255), primary_key=True)
    hostname = Column(String(255))
    endpoint_type = Column(String(50))
    os_platform = Column(String(50))
    os_name = Column(String(255))
    os_major_version = Column(String(50))
    ipv4 = Column(String(45))
    mac = Column(String(20))
    last_seen_at = Column(DateTime(timezone=True))
    health_overall = Column(String(50))
    health_threats = Column(String(50))
    health_services = Column(String(50))
    isolation_status = Column(String(50))
    isolation_last_enabled_at = Column(DateTime(timezone=True))
    tamper_protection_enabled = Column(Boolean)
    encryption_status = Column(String(50))
    online = Column(Boolean)
    raw_data = Column(JSONB)
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class BlockedIp(Base):
    __tablename__ = "blocked_ips"

    ip = Column(String(45), primary_key=True)
    comment = Column(Text)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    # Specially flagged for connection monitoring — the monitor job tracks which
    # internal hosts talk to this IP and alerts on new sessions.
    monitored = Column(Boolean, nullable=False, default=False)
    # Provenance: who created the block ('human' | 'agent') and which detection
    # it originated from ('manual' | 'bulk' | 'chat' | 'anomaly' | 'connection' |
    # 'waf' | 'ips' | 'failed_login' | 'event' | 'triage' | …).
    blocked_by = Column(String(20), nullable=False, default="human")
    source = Column(String(40), nullable=False, default="manual")


class WatchlistIp(Base):
    """IPs we want to observe but NOT block. Like the blocklist, an entry can be
    flagged `monitored` to have the monitor job track host connections to it."""
    __tablename__ = "watchlist_ips"

    ip = Column(String(45), primary_key=True)
    comment = Column(Text)
    monitored = Column(Boolean, nullable=False, default=False)
    added_at = Column(DateTime(timezone=True), server_default=func.now())


class MonitoredConnection(Base):
    """Persistent baseline of (internal host ↔ monitored IP) pairs. NetFlow only
    keeps ~30 days, so this table is the long-lived memory of which host talks to
    which monitored IP, in which direction, and when — the basis for detecting
    new sessions."""
    __tablename__ = "monitored_connections"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    monitored_ip = Column(String(45), nullable=False)
    host_ip = Column(String(45), nullable=False)
    # 'outbound' = host → monitored IP, 'inbound' = monitored IP → host
    direction = Column(String(10), nullable=False)
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    flows = Column(BigInteger, nullable=False, default=0)
    bytes = Column(BigInteger, nullable=False, default=0)
    dst_port = Column(Integer)
    protocol = Column(Integer)
    country = Column(String(100))
    last_notified_at = Column(DateTime(timezone=True))
    notify_count = Column(Integer, nullable=False, default=0)


class MonitoredEvent(Base):
    """Append-only log of noteworthy monitor events (a new host↔IP pair, or a
    known pair resurfacing after a quiet gap). Powers the timeline + drives the
    Telegram/Teams notification."""
    __tablename__ = "monitored_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    monitored_ip = Column(String(45), nullable=False)
    host_ip = Column(String(45), nullable=False)
    direction = Column(String(10), nullable=False)
    # 'new_pair' | 'reappeared'
    event_type = Column(String(20), nullable=False)
    dst_port = Column(Integer)
    protocol = Column(Integer)
    country = Column(String(100))
    source_list = Column(String(20))   # 'blocked' | 'watchlist' | 'both'
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    notified = Column(Boolean, nullable=False, default=False)
    notify_error = Column(Text)


class BlockedDomain(Base):
    __tablename__ = "blocked_domains"

    domain = Column(String(255), primary_key=True)
    comment = Column(Text)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())


class BlockedUrl(Base):
    __tablename__ = "blocked_urls"

    url = Column(String(2048), primary_key=True)
    comment = Column(Text)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())


class WhitelistedIp(Base):
    __tablename__ = "whitelisted_ips"

    ip = Column(String(45), primary_key=True)
    # Where this entry came from: manual | firewall_location | firewall_log
    # | netflow | sophos. Manual entries persist across refresh; auto entries
    # get rewritten on every refresh.
    source = Column(String(50), nullable=False, default="manual")
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class KnownUserOverride(Base):
    """Operator correction to the self-learned known-user directory.

    The directory behind the invalid-username brute-force rule learns from
    successful logins, which leaves two gaps an operator must be able to close:
    a brand-new account that has never logged in yet would look invalid, and a
    generic/shared login that did succeed should not shield an attacker who
    guesses it. ``status`` is ``allow`` (treat as a real account) or ``deny``
    (never treat as real)."""

    __tablename__ = "known_user_overrides"

    user_name = Column(String(255), primary_key=True)   # stored lowercased
    status = Column(String(10), nullable=False, default="allow")   # allow | deny
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_by = Column(String(64))


class InvalidUsername(Base):
    """A username proven to be used in brute-force attempts against this network.

    The threshold rule needs an IP to try several non-existent names before it
    acts, which is deliberately conservative — but it means the *second* attacker
    reusing the very same word list gets the same grace period. Once a name is
    known to come from a spray, that grace is unwarranted: any source touching it
    is blocked on the first attempt.

    Names land here only via an IP that already met the threshold rule, never
    from a lone failed login. That is what keeps a real user's typo out of the
    list — a typo comes from a source that tried exactly one name, which never
    becomes an offender. ``status`` is ``active`` (blocks on sight) or
    ``ignored`` (kept for the record, never triggers)."""

    __tablename__ = "invalid_usernames"

    user_name = Column(String(255), primary_key=True)   # stored lowercased
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True))
    # The sprayer that put this name on the list — provenance for the operator
    # deciding whether a name belongs here.
    burned_by_ip = Column(String(45))
    # How often this name alone caused a block. Tells a productive entry from a
    # one-off that has never fired since.
    block_hits = Column(Integer, nullable=False, default=0)
    origin = Column(String(10), nullable=False, default="learned")   # learned | manual
    status = Column(String(10), nullable=False, default="active")    # active | ignored
    comment = Column(Text)
    created_by = Column(String(64))


class AnomalyVerdict(Base):
    """Analyst verdict on an anomalous IP surfaced by the firewall-anomaly
    analysis. Anomalies are recomputed on the fly (no stable id), so a verdict
    is keyed by the IP itself and persists across analyses."""
    __tablename__ = "anomaly_verdicts"

    ip = Column(String(45), primary_key=True)
    # 'malicious' (schädlich) | 'suspicious' (verdächtig) | 'benign' (unschädlich)
    verdict = Column(String(20), nullable=False)
    comment = Column(Text)
    # 'human' | 'agent' — the anomaly agent never overwrites human verdicts.
    created_by = Column(String(20), nullable=False, default="human")
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class M365LoginProfile(Base):
    """Per-user baseline of known M365 login devices and locations. The login
    watch alerts (with a revoke-sessions option) whenever a successful login
    uses a (user, kind, value) pair that isn't in this table yet."""
    __tablename__ = "m365_login_profiles"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(String(255), nullable=False)
    # 'device' (Entra device id / os|browser fingerprint) | 'location' (country)
    kind = Column(String(20), nullable=False)
    value = Column(String(255), nullable=False)
    label = Column(String(255))          # human-readable (device name, city…)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    seen_count = Column(BigInteger, nullable=False, default=1)


class Honeypot(Base):
    """A remote honeypot pod, managed by Warroom. Runs the honeypot agent on a
    Linux host, simulates decoy services and reports any access. The pod polls
    its desired service config on each heartbeat, so config is driven here."""
    __tablename__ = "honeypots"

    id = Column(String(36), primary_key=True)          # uuid4
    name = Column(String(120), nullable=False)
    token_hash = Column(String(64), nullable=False)    # sha256 of the pod token
    enabled = Column(Boolean, nullable=False, default=True)
    # Which decoy services to run: {"ssh": true, "http": true, ...}
    services = Column(JSONB)
    # Decoy files to plant + watch: [{"path": "/root/backup.sql", "kind": "db_dump"}]
    files = Column(JSONB)
    host_ip = Column(String(45))                       # last reported source IP
    host_info = Column(JSONB)                           # hostname, os, agent version
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class HoneypotEvent(Base):
    """A single access to a honeypot decoy service — by definition suspicious."""
    __tablename__ = "honeypot_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    honeypot_id = Column(String(36), nullable=False)
    service = Column(String(20))                        # ssh/telnet/http/...
    event_type = Column(String(20))                    # connect | login | http_request
    source_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    # Captured interaction: {username, password, http_method, path, data, ...}
    payload = Column(JSONB)
    # A whitelisted process's decoy-file access is stored but muted (no alarm).
    muted = Column(Boolean, nullable=False, default=False)
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))
    attacker_asn = Column(String(255))
    attacker_org = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class HoneypotLogin(Base):
    """A credential pair somebody typed into the decoy login page.

    Stored in the clear, deliberately. The point of the page is to learn *what*
    is being tried: whether an attacker is replaying credentials leaked from
    elsewhere, whether a guessed password is uncomfortably close to a real one,
    and which username lists are in circulation. A hash would answer none of
    that.

    Nobody legitimate has any reason to reach this page, so every row here is
    hostile by construction — which is what makes it safe to act on immediately.

    One exception, and it is the whole point of :class:`MonitoredPassword`: when
    the submitted password matches a password genuinely in use here, it is
    **redacted** rather than stored. At that moment it stops being an attacker's
    guess and becomes a live credential of ours, and writing it to this table
    would put a real password in the clear in the database — the precise outcome
    the feature exists to prevent. ``credential_alarm`` records that it happened
    without keeping what happened."""

    __tablename__ = "honeypot_logins"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    username = Column(String(255))
    password = Column(Text)                             # plaintext, on purpose
    source_ip = Column(String(45))
    user_agent = Column(Text)
    # Which decoy path was used — several can point at the same page, and the
    # one an attacker found says something about how they found it.
    path = Column(String(255))
    referer = Column(Text)
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))
    attacker_asn = Column(String(50))
    attacker_org = Column(String(255))
    # What Warroom did in response: "blocked", "burned", "blocked+burned", "none".
    action = Column(String(40))
    # "login" = credentials were submitted; "probe" = the page or the API path
    # was merely requested. A probe is reconnaissance, not yet an attempt, and
    # is deliberately not acted on by default.
    kind = Column(String(10), nullable=False, default="login")
    # The body exactly as it arrived, and the method it arrived with. Parsing
    # credentials out of arbitrary shapes will always have gaps; keeping the
    # original means a miss costs nothing but a second look.
    raw_body = Column(Text)
    method = Column(String(10))
    # Risk summary from the OSINT providers (abuse score, VirusTotal, GreyNoise,
    # Tor exit). Null unless honeypot_web_osint_enabled was on at capture time.
    osint = Column(JSONB)
    # Set when the submitted password matched a registered real password
    # (:class:`MonitoredPassword`). The id names which one, so a rotation can be
    # scoped to the credential that actually leaked.
    monitored_password_id = Column(BigInteger, nullable=True)
    # "high" = a real password was used; "critical" = with a real username too.
    # NULL for the overwhelming majority of rows, which are ordinary guessing.
    credential_alarm = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class HoneypotProcessWhitelist(Base):
    """A legitimate process (e.g. a virus scanner) allowed to touch decoy files.
    A matching file-honeypot access is still logged (as a muted event) but never
    raises an alarm. pod_id NULL = all pods; file_path NULL = all decoy files."""
    __tablename__ = "honeypot_process_whitelist"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    pod_id = Column(String(36))                         # NULL = all pods
    process = Column(String(500), nullable=False)       # comm name, e.g. "clamd"
    exe = Column(String(500))                           # full exe path (preferred match)
    file_path = Column(String(400))                    # NULL = all decoy files
    comment = Column(String(500))
    created_by = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class MonitoredPassword(Base):
    """A password that is genuinely in use here, registered so Warroom can tell
    when an attacker types it into a decoy.

    An attacker guessing at random never lands on a real password. If one turns
    up in a honeypot submission, it did not come from guessing — it leaked, and
    the only open questions are where from and how long ago. That makes this the
    highest-value signal the decoy can produce.

    Never stores the password. ``fingerprint`` is an HMAC-SHA256 keyed with a
    subkey derived from the master secret (which lives outside the database), so
    the table on its own reveals nothing and cannot be reversed. Registration
    takes the plaintext, fingerprints it, and drops it.

    The trade-off, stated plainly: an HMAC is fast, so an attacker holding *both*
    the database and the master key could test a dictionary against these
    fingerprints offline. A slow KDF would close that, but it would also mean one
    KDF per stored password per submission — during exactly the brute-force flood
    this feature exists to detect. Keeping the key out of the database is the
    defence that matters here."""

    __tablename__ = "monitored_passwords"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    # What this password is for, e.g. "Domain admin 2026". Operator-facing text;
    # deliberately never the password itself or a hint at it.
    label = Column(String(200), nullable=False)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    active = Column(Boolean, default=True, nullable=False)
    created_by = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # Set when a submission matched. Kept so a rotated-but-still-leaked password
    # keeps its history instead of looking newly compromised each time.
    last_hit_at = Column(DateTime(timezone=True), nullable=True)
    hit_count = Column(Integer, default=0, nullable=False)


class CveScore(Base):
    """CVSS / KEV / EPSS for a CVE, cached from the free Shodan CVE DB. Static
    per CVE, so this is a permanent lookup table shared across all IPs/hosts."""
    __tablename__ = "cve_scores"

    cve_id = Column(String(30), primary_key=True)
    cvss = Column(Float)
    cvss_v3 = Column(Float)
    severity = Column(String(12))       # critical | high | medium | low | none
    kev = Column(Boolean, nullable=False, default=False)   # CISA known-exploited
    epss = Column(Float)                # exploit-prediction score 0..1
    summary = Column(Text)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())


class IpHostname(Base):
    """Resolved hostname for an internal IP, cached across sources. Positive
    hits get a long TTL, misses a short one so a host that later comes online
    still gets picked up. Source: 'sophos' | 'dns' | 'netbios'."""
    __tablename__ = "ip_hostnames"

    ip = Column(String(45), primary_key=True)
    hostname = Column(String(255))       # NULL = resolved-but-nothing-found (negative)
    source = Column(String(20))
    mac = Column(String(17))             # MAC when known (firewall DHCP / NetBIOS)
    resolved_at = Column(DateTime(timezone=True), server_default=func.now())


class HostIdentity(Base):
    """Long-term record of an observed IP↔MAC↔hostname combination, so identity
    changes (e.g. an IP suddenly on a different MAC) can be detected across
    NetFlow retention."""
    __tablename__ = "host_identities"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    mac = Column(String(17), nullable=False)
    hostname = Column(String(255))
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    times_seen = Column(Integer, nullable=False, default=1)


class HostIdentityEvent(Base):
    """A detected change to a host identity (IP↔MAC↔hostname) — audit + alarm."""
    __tablename__ = "host_identity_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    ip = Column(String(45))
    mac = Column(String(17))
    hostname = Column(String(255))
    event_type = Column(String(30))      # ip_mac_change | mac_moved | new_device | hostname_change
    severity = Column(String(10))        # low | medium | high
    detail = Column(Text)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    notified = Column(Boolean, nullable=False, default=False)


class HostInventory(Base):
    """Long-term record of an internal host that has been port-scanned. Survives
    NetFlow retention so a host stays known with its scan history and open ports."""
    __tablename__ = "host_inventory"

    ip = Column(String(45), primary_key=True)
    hostname = Column(String(255))
    mac = Column(String(17))
    os_guess = Column(String(255))
    open_ports = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_scan_at = Column(DateTime(timezone=True))
    notes = Column(Text)


class HostScan(Base):
    """One nmap scan run against an internal host."""
    __tablename__ = "host_scans"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    profile = Column(String(20), nullable=False)         # quick | full | scripts
    status = Column(String(12), nullable=False, default="running")  # running|done|error
    arguments = Column(Text)
    ports_open = Column(Integer, nullable=False, default=0)
    os_guess = Column(String(255))
    duration_ms = Column(Integer)
    error = Column(Text)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True))


class HostPort(Base):
    """Current state of one (ip, port, proto), with first/last seen for history."""
    __tablename__ = "host_ports"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    proto = Column(String(8), nullable=False, default="tcp")
    state = Column(String(12), nullable=False, default="open")   # open | closed
    service = Column(String(64))
    product = Column(String(128))
    version = Column(String(128))
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_state_change = Column(DateTime(timezone=True), server_default=func.now())


class HostPortEvent(Base):
    """A detected change to a host's port (opened / closed / service_change)."""
    __tablename__ = "host_port_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    proto = Column(String(8), nullable=False, default="tcp")
    event_type = Column(String(20), nullable=False)     # opened | closed | service_change
    service = Column(String(64))
    detail = Column(Text)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    notified = Column(Boolean, nullable=False, default=False)


class HostPresence(Base):
    """Live reachability of an internal IP from an nmap ping-sweep, so the hosts
    list can show a current online/offline status."""
    __tablename__ = "host_presence"

    ip = Column(String(45), primary_key=True)
    last_online = Column(DateTime(timezone=True))
    last_checked = Column(DateTime(timezone=True))
    online = Column(Boolean)             # state at the last check (for transitions)


class HostPresenceEvent(Base):
    """An online↔offline transition for one host — the compact availability history."""
    __tablename__ = "host_presence_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    online = Column(Boolean, nullable=False)
    at = Column(DateTime(timezone=True), server_default=func.now())


class HostPresenceSnapshot(Base):
    """Fleet online-count per sweep — the trend time series."""
    __tablename__ = "host_presence_snapshots"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    total = Column(Integer, nullable=False, default=0)
    online = Column(Integer, nullable=False, default=0)


class KaliCommand(Base):
    """Audit + human-in-the-loop record for a command run on the Tor-only Kali
    box. Every MCP `tor_run` lands here first; status tracks its lifecycle."""
    __tablename__ = "kali_commands"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    command = Column(Text, nullable=False)
    targets = Column(Text)                               # extracted host targets (CSV)
    actor = Column(String(60))                           # who/what requested it
    # pending | approved | done | rejected | blocked | error
    status = Column(String(12), nullable=False, default="pending")
    reason = Column(Text)                                # block/reject reason
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    tor_exit_ip = Column(String(45))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    decided_at = Column(DateTime(timezone=True))
    decided_by = Column(String(60))


class GeoIPCache(Base):
    __tablename__ = "geoip_cache"

    ip = Column(String(45), primary_key=True)
    lat = Column(Float)
    lon = Column(Float)
    country = Column(String(100))
    city = Column(String(255))
    asn = Column(String(255))
    org = Column(String(255))
    abuse_score = Column(Integer)
    cached_at = Column(DateTime(timezone=True), server_default=func.now())


class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AgentDecision(Base):
    __tablename__ = "agent_decisions"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    alert_id = Column(String(255), nullable=False)
    action = Column(String(50), nullable=False)           # block_ip | acknowledge | isolate | no_action
    action_args = Column(JSONB)                            # e.g. {"ip": "1.2.3.4"} or {"endpoint_id": "..."}
    reasoning = Column(Text)
    status = Column(String(30), nullable=False, default="pending")  # pending | approved | rejected | executed | failed | superseded
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    decided_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text)
    model = Column(String(255))                            # which model produced this
    decided_by = Column(String(20), nullable=False, default="agent")   # agent | human
    human_comment = Column(Text)
    supersedes = Column(BigInteger, nullable=True)         # id of decision this manual one replaces
    # 'alert' = Sophos Central alert; 'waf' = WAF-event rule-based.
    source_type = Column(String(20), nullable=False, default="alert")
    source_ip = Column(String(45))                         # filled for WAF decisions (alerts use alert_id)
    # Telegram approval: message id of the sent approval prompt (also the
    # "already notified" guard — NULL means not yet pushed to Telegram).
    telegram_message_id = Column(BigInteger, nullable=True)


class AgentApprovalPattern(Base):
    """Self-learning auto-approval memory. One row per decision *signature*
    ("source_type|action|rule"). Human approvals/rejections accumulate here;
    once ``approvals - rejections`` reaches the configured threshold, matching
    new decisions are auto-approved and executed without asking."""
    __tablename__ = "agent_approval_patterns"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    signature = Column(String(300), nullable=False, unique=True)
    source_type = Column(String(20), nullable=False, default="alert")
    action = Column(String(50), nullable=False)
    rule = Column(String(200), nullable=False, default="")
    approvals = Column(Integer, nullable=False, default=0)
    rejections = Column(Integer, nullable=False, default=0)
    auto_approved = Column(Integer, nullable=False, default=0)   # times this pattern auto-approved
    last_decided_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class NetflowBucket(Base):
    __tablename__ = "netflow_buckets"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    bucket_start = Column(DateTime(timezone=True), nullable=False)
    firewall_ip = Column(String(45))
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    dst_port = Column(Integer)
    protocol = Column(Integer)
    bytes = Column(BigInteger, nullable=False, default=0)
    packets = Column(BigInteger, nullable=False, default=0)
    flows = Column(Integer, nullable=False, default=0)


class NetflowIfaceBucket(Base):
    __tablename__ = "netflow_iface_buckets"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    bucket_start = Column(DateTime(timezone=True), nullable=False)
    firewall_ip = Column(String(45))
    iface_idx = Column(Integer, nullable=False)
    direction = Column(String(3), nullable=False)  # 'in' or 'out'
    bytes = Column(BigInteger, nullable=False, default=0)
    packets = Column(BigInteger, nullable=False, default=0)
    flows = Column(Integer, nullable=False, default=0)


class LlmUsage(Base):
    """Per-day LLM-call counter, segmented by ``source`` (alert/waf/ips/
    failed_login/test/manual), ``status`` (success/error), and the model
    that was actually used at call time. Token counts are summed (divide by
    ``count`` for averages); ``duration_ms`` is the cumulative wall-clock
    spent across calls so the UI can chart average latency per source.
    """
    __tablename__ = "llm_usage"

    source = Column(String(20), primary_key=True)
    status = Column(String(20), primary_key=True)
    model = Column(String(120), primary_key=True)
    bucket_day = Column(DateTime(timezone=True), primary_key=True)
    count = Column(BigInteger, nullable=False, default=0)
    prompt_tokens = Column(BigInteger, nullable=False, default=0)
    completion_tokens = Column(BigInteger, nullable=False, default=0)
    duration_ms = Column(BigInteger, nullable=False, default=0)
    last_called_at = Column(DateTime(timezone=True), nullable=False)


class EmailMetric(Base):
    """Periodic snapshot of the Sophos Email API (long format: one row per
    metric/label per bucket). Populated by ``email_metrics.collect_email_metrics``
    every 15 min; consumed by the Grafana email dashboard.

    metric ∈ mailbox_total | mailbox_blocked | quarantine_total |
    postdelivery_total | quarantine_reason | postdelivery_reason. ``label`` holds
    the reason for the *_reason rows, '' for the scalar totals.
    """
    __tablename__ = "email_metrics"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    bucket = Column(DateTime(timezone=True), nullable=False)
    metric = Column(String(40), nullable=False)
    label = Column(String(160), nullable=False, default="")
    value = Column(BigInteger, nullable=False, default=0)


class OsintUsage(Base):
    """Per-day call counter for each outbound OSINT provider. Populated by
    ``osint_metrics.record`` (called from inside each provider wrapper) and
    flushed to DB once a minute by the scheduler. ``status`` is one of
    ``success`` / ``no_record`` / ``error`` / ``cache_hit`` so we can chart
    quota burn (real HTTP calls) separately from cache hits."""
    __tablename__ = "osint_usage"

    provider = Column(String(50), primary_key=True)
    status = Column(String(20), primary_key=True)
    bucket_day = Column(DateTime(timezone=True), primary_key=True)
    count = Column(BigInteger, nullable=False, default=0)
    last_called_at = Column(DateTime(timezone=True), nullable=False)


class ChatSession(Base):
    """A persisted AI-chat conversation. New sessions start with empty context;
    old ones are resumed by loading their messages."""
    __tablename__ = "chat_sessions"

    id = Column(BigInteger, primary_key=True)
    title = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(BigInteger, primary_key=True)
    session_id = Column(BigInteger, nullable=False, index=True)
    role = Column(Text, nullable=False)          # 'user' | 'assistant'
    content = Column(Text, nullable=False)
    tool = Column(Text)                          # resolved tool for assistant turns
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True)
    username = Column(Text, unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    role = Column(Text, nullable=False, default="analyst")   # viewer | analyst | admin
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(BigInteger, primary_key=True)
    username = Column(Text)
    role = Column(Text)
    method = Column(Text)
    path = Column(Text)
    status = Column(Integer)
    ip = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
