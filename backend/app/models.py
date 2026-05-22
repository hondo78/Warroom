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
