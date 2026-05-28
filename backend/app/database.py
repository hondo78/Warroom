from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.config import settings

engine = create_async_engine(settings.database_url, echo=False, pool_size=10)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# Idempotent migrations applied at every backend startup. Each statement must
# tolerate being re-run; new columns use ADD COLUMN IF NOT EXISTS.
_MIGRATIONS = [
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_action VARCHAR(50)",
    """
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
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_endpoints_hostname ON endpoints(hostname)",
    "CREATE INDEX IF NOT EXISTS idx_endpoints_health ON endpoints(health_overall)",
    "CREATE INDEX IF NOT EXISTS idx_endpoints_isolation ON endpoints(isolation_status)",
    "CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip VARCHAR(45) PRIMARY KEY,
        comment TEXT,
        blocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_synced_at TIMESTAMP WITH TIME ZONE,
        sync_status VARCHAR(50),
        sync_error TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_blocked_ips_blocked_at ON blocked_ips(blocked_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS blocked_domains (
        domain VARCHAR(255) PRIMARY KEY,
        comment TEXT,
        blocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_blocked_domains_blocked_at ON blocked_domains(blocked_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS blocked_urls (
        url VARCHAR(2048) PRIMARY KEY,
        comment TEXT,
        blocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_blocked_urls_blocked_at ON blocked_urls(blocked_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS app_settings (
        key VARCHAR(100) PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS netflow_buckets (
        id BIGSERIAL PRIMARY KEY,
        bucket_start TIMESTAMP WITH TIME ZONE NOT NULL,
        firewall_ip VARCHAR(45),
        src_ip VARCHAR(45),
        dst_ip VARCHAR(45),
        dst_port INTEGER,
        protocol INTEGER,
        bytes BIGINT NOT NULL DEFAULT 0,
        packets BIGINT NOT NULL DEFAULT 0,
        flows INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_netflow_bucket ON netflow_buckets(bucket_start DESC)",
    "CREATE INDEX IF NOT EXISTS idx_netflow_src ON netflow_buckets(src_ip)",
    "CREATE INDEX IF NOT EXISTS idx_netflow_dst ON netflow_buckets(dst_ip)",
    "CREATE INDEX IF NOT EXISTS idx_netflow_fw ON netflow_buckets(firewall_ip)",
    "CREATE INDEX IF NOT EXISTS idx_netflow_dport ON netflow_buckets(dst_port)",
    """
    CREATE TABLE IF NOT EXISTS netflow_iface_buckets (
        id BIGSERIAL PRIMARY KEY,
        bucket_start TIMESTAMP WITH TIME ZONE NOT NULL,
        firewall_ip VARCHAR(45),
        iface_idx INTEGER NOT NULL,
        direction VARCHAR(3) NOT NULL,
        bytes BIGINT NOT NULL DEFAULT 0,
        packets BIGINT NOT NULL DEFAULT 0,
        flows INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_iface_bucket ON netflow_iface_buckets(bucket_start DESC)",
    "CREATE INDEX IF NOT EXISTS idx_iface_fw ON netflow_iface_buckets(firewall_ip, iface_idx)",
    """
    CREATE TABLE IF NOT EXISTS agent_decisions (
        id BIGSERIAL PRIMARY KEY,
        alert_id VARCHAR(255) NOT NULL,
        action VARCHAR(50) NOT NULL,
        action_args JSONB,
        reasoning TEXT,
        confidence DOUBLE PRECISION,
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        decided_at TIMESTAMP WITH TIME ZONE,
        error TEXT,
        model VARCHAR(255)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_agent_decisions_status ON agent_decisions(status)",
    "CREATE INDEX IF NOT EXISTS idx_agent_decisions_alert_id ON agent_decisions(alert_id)",
    "CREATE INDEX IF NOT EXISTS idx_agent_decisions_created_at ON agent_decisions(created_at DESC)",
    # Additive columns for Human-in-the-loop tracking.
    "ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS decided_by VARCHAR(20) NOT NULL DEFAULT 'agent'",
    "ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS human_comment TEXT",
    "ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS supersedes BIGINT",
    "CREATE INDEX IF NOT EXISTS idx_agent_decisions_decided_by ON agent_decisions(decided_by)",
    "ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS source_type VARCHAR(20) NOT NULL DEFAULT 'alert'",
    "ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS source_ip VARCHAR(45)",
    "CREATE INDEX IF NOT EXISTS idx_agent_decisions_source_type ON agent_decisions(source_type)",
    "CREATE INDEX IF NOT EXISTS idx_agent_decisions_source_ip ON agent_decisions(source_ip)",
    # alert_id is no longer mandatory for synthetic (WAF) decisions
    "ALTER TABLE agent_decisions ALTER COLUMN alert_id DROP NOT NULL",
    """
    CREATE TABLE IF NOT EXISTS whitelisted_ips (
        ip VARCHAR(45) PRIMARY KEY,
        source VARCHAR(50) NOT NULL DEFAULT 'manual',
        comment TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_whitelisted_ips_source ON whitelisted_ips(source)",
]


async def ensure_schema() -> None:
    async with engine.begin() as conn:
        for stmt in _MIGRATIONS:
            await conn.execute(text(stmt))


async def get_db():
    async with async_session() as session:
        yield session
