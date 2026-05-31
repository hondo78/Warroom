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
    confidence = Column(Float)                             # 0..1, from the model
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
