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
    attacker_country = Column(String(100))
    attacker_city = Column(String(255))
    attacker_asn = Column(String(255))
    attacker_org = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


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
