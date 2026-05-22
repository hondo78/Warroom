CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR(255) PRIMARY KEY,
    alert_type VARCHAR(255),
    severity VARCHAR(50),
    category VARCHAR(255),
    description TEXT,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    tenant_id VARCHAR(255),
    managed_agent_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    raw_data JSONB,
    attacker_lat DOUBLE PRECISION,
    attacker_lon DOUBLE PRECISION,
    attacker_country VARCHAR(100),
    attacker_city VARCHAR(255),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    acknowledged_action VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(255) PRIMARY KEY,
    event_type VARCHAR(255),
    severity VARCHAR(50),
    name VARCHAR(500),
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    group_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    raw_data JSONB,
    attacker_lat DOUBLE PRECISION,
    attacker_lon DOUBLE PRECISION,
    attacker_country VARCHAR(100),
    attacker_city VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS detections (
    id VARCHAR(255) PRIMARY KEY,
    detection_type VARCHAR(255),
    severity VARCHAR(50),
    description TEXT,
    source_ip VARCHAR(45),
    device_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    raw_data JSONB,
    attacker_lat DOUBLE PRECISION,
    attacker_lon DOUBLE PRECISION,
    attacker_country VARCHAR(100),
    attacker_city VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS firewall_locations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ip VARCHAR(45),
    lat DOUBLE PRECISION NOT NULL,
    lon DOUBLE PRECISION NOT NULL,
    country VARCHAR(100),
    city VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS geoip_cache (
    ip VARCHAR(45) PRIMARY KEY,
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION,
    country VARCHAR(100),
    city VARCHAR(255),
    asn VARCHAR(255),
    org VARCHAR(255),
    abuse_score INTEGER,
    cached_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS firewall_logs (
    id BIGSERIAL PRIMARY KEY,
    log_type VARCHAR(50),
    log_subtype VARCHAR(50),
    severity VARCHAR(20),
    firewall_name VARCHAR(255),
    firewall_ip VARCHAR(45),
    source_ip VARCHAR(45),
    source_port INTEGER,
    destination_ip VARCHAR(45),
    destination_port INTEGER,
    protocol VARCHAR(20),
    rule_name VARCHAR(255),
    policy_name VARCHAR(255),
    action VARCHAR(50),
    message TEXT,
    threat_name VARCHAR(255),
    user_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    raw_data JSONB,
    attacker_lat DOUBLE PRECISION,
    attacker_lon DOUBLE PRECISION,
    attacker_country VARCHAR(100),
    attacker_city VARCHAR(255),
    attacker_asn VARCHAR(255),
    attacker_org VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id VARCHAR(255) PRIMARY KEY,
    hostname VARCHAR(255),
    endpoint_type VARCHAR(50),
    os_platform VARCHAR(50),
    os_name VARCHAR(255),
    os_major_version VARCHAR(50),
    ipv4 VARCHAR(45),
    mac VARCHAR(20),
    last_seen_at TIMESTAMP WITH TIME ZONE,
    health_overall VARCHAR(50),
    health_threats VARCHAR(50),
    health_services VARCHAR(50),
    isolation_status VARCHAR(50),
    isolation_last_enabled_at TIMESTAMP WITH TIME ZONE,
    tamper_protection_enabled BOOLEAN,
    encryption_status VARCHAR(50),
    online BOOLEAN,
    raw_data JSONB,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_endpoints_hostname ON endpoints(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoints_health ON endpoints(health_overall);
CREATE INDEX IF NOT EXISTS idx_endpoints_isolation ON endpoints(isolation_status);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip VARCHAR(45) PRIMARY KEY,
    comment TEXT,
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_blocked_at ON blocked_ips(blocked_at DESC);

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_created ON alerts(severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_created ON detections(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_geoip_cached ON geoip_cache(cached_at);
CREATE INDEX IF NOT EXISTS idx_fw_logs_created ON firewall_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fw_logs_type_created ON firewall_logs(log_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fw_logs_src ON firewall_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_fw_logs_dst ON firewall_logs(destination_ip);
-- ILIKE '%…%' on a JSONB-extracted text needs trigram GIN to avoid seq-scans.
CREATE INDEX IF NOT EXISTS idx_fw_logs_log_component_trgm
    ON firewall_logs USING gin ((raw_data->>'log_component') gin_trgm_ops);
-- Most attacker/map endpoints filter on attacker_lat IS NOT NULL; partial
-- index stays small and cheap to maintain for non-geocoded rows.
CREATE INDEX IF NOT EXISTS idx_fw_logs_attacker_lat_created
    ON firewall_logs(created_at DESC)
    WHERE attacker_lat IS NOT NULL;
