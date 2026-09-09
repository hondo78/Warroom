import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)

# --- Connection pools -------------------------------------------------------
# Two separate pools on purpose. Everything used to share one 10+10 pool, and
# the heavy background work (cache warmers, agent loops, rollups, collectors)
# competed for the very same connections the HTTP request path needs. Once the
# multi-minute firewall_logs aggregates filled it up, *every* endpoint — even
# trivial ones — died with "QueuePool limit of size 10 overflow 10 reached",
# which is what made the dashboard show partial or no data at all.
#
# statement_timeout is the second half of the fix: without it a query orphaned
# by a client disconnect (nginx 504 / browser navigation) keeps running server
# side and pins its connection for many minutes. Postgres now kills it.
#
#   request pool  — small, fail-fast, hard 45s statement cap (nginx gives up at
#                   60s anyway, so a longer query can only ever be wasted work)
#   background    — heavier queries allowed, but they can never starve requests

def _engine(pool_size: int, max_overflow: int, pool_timeout: int,
            statement_timeout_ms: int, app_name: str,
            idle_in_tx_ms: int = 60_000):
    return create_async_engine(
        settings.database_url,
        echo=False,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=1800,
        pool_pre_ping=True,
        connect_args={
            "server_settings": {
                "statement_timeout": str(statement_timeout_ms),
                "idle_in_transaction_session_timeout": str(idle_in_tx_ms),
                "application_name": app_name,
            },
            "command_timeout": statement_timeout_ms / 1000 + 15,
        },
    )


# Request path: Depends(get_db). Fail fast (5s) — an immediate error beats a
# 30s block that ties up the worker and times out in the browser regardless.
engine = _engine(
    pool_size=20, max_overflow=10, pool_timeout=5,
    statement_timeout_ms=45_000, app_name="warroom-api",
)

# Background path: cache warmers, schedulers, collectors, agent loops. These
# hold one transaction across a whole batch and do network work inside it —
# honeypot.ingest_events enriches up to 500 events with GeoIP/OSINT per commit —
# so the request path's 60s idle-in-transaction cap would abort the batch (and
# lose all of it) on one cold provider lookup. Still bounded: an abandoned
# transaction cannot sit open indefinitely.
bg_engine = _engine(
    pool_size=10, max_overflow=10, pool_timeout=30,
    statement_timeout_ms=600_000, app_name="warroom-bg",
    idle_in_tx_ms=300_000,
)

# `async_session` is what all background modules import; binding it to the
# background pool moves them off the request path without touching 100+ call
# sites.
async_session = async_sessionmaker(bg_engine, class_=AsyncSession, expire_on_commit=False)
request_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# Idempotent migrations applied at every backend startup. Each statement must
# tolerate being re-run; new columns use ADD COLUMN IF NOT EXISTS.
_MIGRATIONS = [
    # Operator overrides for the invalid-username brute-force rule: names that
    # count as real accounts even without a successful login yet ('allow'), and
    # names that must never count as real ('deny', e.g. shared/generic logins).
    """
    CREATE TABLE IF NOT EXISTS known_user_overrides (
        user_name VARCHAR(255) PRIMARY KEY,
        status VARCHAR(10) NOT NULL DEFAULT 'allow',
        comment TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
        created_by VARCHAR(64)
    )
    """,
    # Credentials typed into the decoy login page. Passwords are stored in the
    # clear on purpose — see models.HoneypotLogin for why a hash would defeat
    # the entire point of the page.
    """
    CREATE TABLE IF NOT EXISTS honeypot_logins (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(255),
        password TEXT,
        source_ip VARCHAR(45),
        user_agent TEXT,
        path VARCHAR(255),
        referer TEXT,
        attacker_country VARCHAR(100),
        attacker_city VARCHAR(255),
        attacker_asn VARCHAR(50),
        attacker_org VARCHAR(255),
        action VARCHAR(40),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_honeypot_logins_created ON honeypot_logins(created_at DESC)",
    # Probes (a bare GET on the decoy) share the table with credential
    # submissions: same source, same enrichment, same view — only the weight
    # differs, and that is what this column carries.
    "ALTER TABLE honeypot_logins ADD COLUMN IF NOT EXISTS kind VARCHAR(10) NOT NULL DEFAULT 'login'",
    # The request body verbatim. Field names differ per portal and per tool, so
    # parsing can always miss something — the raw payload cannot.
    "ALTER TABLE honeypot_logins ADD COLUMN IF NOT EXISTS raw_body TEXT",
    "ALTER TABLE honeypot_logins ADD COLUMN IF NOT EXISTS method VARCHAR(10)",
    # Filled in afterwards by a background lookup, only when the operator has
    # switched OSINT on — see honeypot_login.enrich_async for why it cannot run
    # inline.
    "ALTER TABLE honeypot_logins ADD COLUMN IF NOT EXISTS osint JSONB",
    "CREATE INDEX IF NOT EXISTS idx_honeypot_logins_ip ON honeypot_logins(source_ip)",
    # Usernames proven to come from a brute-force spray. Any source using one is
    # blocked on the first attempt — see models.InvalidUsername for why a name
    # only lands here via an IP that already tripped the threshold rule.
    """
    CREATE TABLE IF NOT EXISTS invalid_usernames (
        user_name VARCHAR(255) PRIMARY KEY,
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT now(),
        last_seen TIMESTAMP WITH TIME ZONE,
        burned_by_ip VARCHAR(45),
        block_hits INTEGER NOT NULL DEFAULT 0,
        origin VARCHAR(10) NOT NULL DEFAULT 'learned',
        status VARCHAR(10) NOT NULL DEFAULT 'active',
        comment TEXT,
        created_by VARCHAR(64)
    )
    """,
    # The block path looks up "is this name burned and active?" on every loop.
    "CREATE INDEX IF NOT EXISTS idx_invalid_usernames_status ON invalid_usernames(status)",
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
    # Provenance: who created the block (human vs the AI agent) and which
    # detection it came from (manual / anomaly / waf / ips / failed_login / …).
    "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS blocked_by VARCHAR(20) NOT NULL DEFAULT 'human'",
    "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS source VARCHAR(40) NOT NULL DEFAULT 'manual'",
    # One-time best-effort backfill of provenance for pre-existing rows from the
    # comment prefix the writers used. Guards make it a no-op after the first run
    # (and it never touches genuinely-manual rows or newly-tagged inserts).
    """
    UPDATE blocked_ips SET blocked_by='agent', source=CASE
        WHEN comment ILIKE 'agent[WAF%'        THEN 'waf'
        WHEN comment ILIKE 'agent[Login%'      THEN 'failed_login'
        WHEN comment ILIKE 'agent[IPS%'        THEN 'ips'
        WHEN comment ILIKE 'agent[Anomal%'     THEN 'anomaly'
        WHEN comment ILIKE 'agent[Verbindung%' OR comment ILIKE 'agent[Connection%' THEN 'connection'
        WHEN comment ILIKE 'agent[Event%'      THEN 'event'
        WHEN comment ILIKE 'agent[Triage%'     THEN 'triage'
        ELSE 'agent' END
      WHERE comment ILIKE 'agent[%' AND blocked_by = 'human'
    """,
    "UPDATE blocked_ips SET blocked_by='human', source='chat' WHERE comment ILIKE 'chat[%' AND source='manual'",
    "UPDATE blocked_ips SET blocked_by='human', source='bulk' WHERE comment ILIKE 'bulk:%' AND source='manual'",
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
    # confidence scoring removed — actions are chosen purely from per-source thresholds
    "ALTER TABLE agent_decisions DROP COLUMN IF EXISTS confidence",
    # Self-learning auto-approval: one row per decision "signature"
    # (source_type|action|rule). NET score = approvals − rejections; once it
    # reaches the configured threshold, matching new decisions auto-approve.
    """
    CREATE TABLE IF NOT EXISTS agent_approval_patterns (
        id BIGSERIAL PRIMARY KEY,
        signature VARCHAR(300) NOT NULL UNIQUE,
        source_type VARCHAR(20) NOT NULL DEFAULT 'alert',
        action VARCHAR(50) NOT NULL,
        rule VARCHAR(200) NOT NULL DEFAULT '',
        approvals INTEGER NOT NULL DEFAULT 0,
        rejections INTEGER NOT NULL DEFAULT 0,
        auto_approved INTEGER NOT NULL DEFAULT 0,
        last_decided_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_agent_approval_patterns_st ON agent_approval_patterns(source_type, action)",
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
    # Old inbound-API counter superseded by the outbound OSINT counter
    "DROP TABLE IF EXISTS api_usage",
    """
    CREATE TABLE IF NOT EXISTS osint_usage (
        provider VARCHAR(50) NOT NULL,
        status VARCHAR(20) NOT NULL,
        bucket_day TIMESTAMP WITH TIME ZONE NOT NULL,
        count BIGINT NOT NULL DEFAULT 0,
        last_called_at TIMESTAMP WITH TIME ZONE NOT NULL,
        PRIMARY KEY (provider, status, bucket_day)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_osint_usage_bucket ON osint_usage(bucket_day)",
    "CREATE INDEX IF NOT EXISTS idx_osint_usage_provider ON osint_usage(provider)",
    """
    CREATE TABLE IF NOT EXISTS llm_usage (
        source VARCHAR(20) NOT NULL,
        status VARCHAR(20) NOT NULL,
        model VARCHAR(120) NOT NULL,
        bucket_day TIMESTAMP WITH TIME ZONE NOT NULL,
        count BIGINT NOT NULL DEFAULT 0,
        prompt_tokens BIGINT NOT NULL DEFAULT 0,
        completion_tokens BIGINT NOT NULL DEFAULT 0,
        duration_ms BIGINT NOT NULL DEFAULT 0,
        last_called_at TIMESTAMP WITH TIME ZONE NOT NULL,
        PRIMARY KEY (source, status, model, bucket_day)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_llm_usage_bucket ON llm_usage(bucket_day)",
    "CREATE INDEX IF NOT EXISTS idx_llm_usage_source ON llm_usage(source)",
    # Periodic snapshots of the (live-proxied) Sophos Email API so Grafana can
    # chart quarantine / mailbox trends. Long format: one row per metric/label.
    """
    CREATE TABLE IF NOT EXISTS email_metrics (
        id BIGSERIAL PRIMARY KEY,
        bucket TIMESTAMP WITH TIME ZONE NOT NULL,
        metric VARCHAR(40) NOT NULL,
        label VARCHAR(160) NOT NULL DEFAULT '',
        value BIGINT NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_email_metrics_bucket ON email_metrics(bucket DESC)",
    "CREATE INDEX IF NOT EXISTS idx_email_metrics_metric ON email_metrics(metric)",
    # Microsoft 365 login audit records (Management Activity API).
    """
    CREATE TABLE IF NOT EXISTS o365_audit_logs (
        id VARCHAR(255) PRIMARY KEY,
        operation VARCHAR(255),
        workload VARCHAR(100),
        user_id VARCHAR(255),
        client_ip VARCHAR(64),
        result_status VARCHAR(50),
        logon_error VARCHAR(255),
        user_agent VARCHAR(512),
        application_id VARCHAR(255),
        created_at TIMESTAMP WITH TIME ZONE,
        ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        raw_data JSONB,
        attacker_lat FLOAT,
        attacker_lon FLOAT,
        attacker_country VARCHAR(100),
        attacker_city VARCHAR(255)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_o365_audit_created ON o365_audit_logs(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_o365_audit_user ON o365_audit_logs(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_o365_audit_ip ON o365_audit_logs(client_ip)",
    "CREATE INDEX IF NOT EXISTS idx_o365_audit_operation ON o365_audit_logs(operation)",
    # Telegram approval message id on agent decisions (idempotent add).
    "ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS telegram_message_id BIGINT",
    # Long-term Shodan host intelligence (open ports + CVEs per IP).
    """
    CREATE TABLE IF NOT EXISTS shodan_hosts (
        ip VARCHAR(64) PRIMARY KEY,
        lat FLOAT,
        lon FLOAT,
        country VARCHAR(100),
        city VARCHAR(255),
        org VARCHAR(255),
        asn VARCHAR(64),
        os VARCHAR(120),
        ports JSONB,
        vulns JSONB,
        hostnames JSONB,
        tags JSONB,
        shodan_last_update VARCHAR(64),
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_shodan_hosts_last_seen ON shodan_hosts(last_seen DESC)",
    # Long-term OSINT lookup history (cheap providers only live ~1h in Redis).
    """
    CREATE TABLE IF NOT EXISTS osint_results (
        value VARCHAR(2048) PRIMARY KEY,
        indicator_type VARCHAR(16),
        abuse_score INTEGER,
        vt_malicious INTEGER,
        greynoise VARCHAR(32),
        intelix_category VARCHAR(120),
        country VARCHAR(100),
        city VARCHAR(255),
        org VARCHAR(255),
        asn VARCHAR(64),
        lat FLOAT,
        lon FLOAT,
        raw JSONB,
        lookup_count INTEGER DEFAULT 1,
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_osint_results_last_seen ON osint_results(last_seen DESC)",
    "CREATE INDEX IF NOT EXISTS idx_osint_results_type ON osint_results(indicator_type)",
    "CREATE INDEX IF NOT EXISTS idx_osint_results_abuse ON osint_results(abuse_score DESC)",
    # Analyst verdicts on anomalous IPs (firewall-anomaly page). Anomalies are
    # recomputed on the fly, so a verdict is keyed by the IP and survives reruns.
    """
    CREATE TABLE IF NOT EXISTS anomaly_verdicts (
        ip VARCHAR(45) PRIMARY KEY,
        verdict VARCHAR(20) NOT NULL,
        comment TEXT,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_anomaly_verdicts_updated ON anomaly_verdicts(updated_at DESC)",
    # Who set the verdict — the anomaly agent never overwrites human verdicts.
    "ALTER TABLE anomaly_verdicts ADD COLUMN IF NOT EXISTS created_by VARCHAR(20) NOT NULL DEFAULT 'human'",
    # --- IP monitoring: watchlist + specially-flagged connection tracking ---
    # Observe-only list (never blocked). Entries can be flagged for monitoring.
    """
    CREATE TABLE IF NOT EXISTS watchlist_ips (
        ip VARCHAR(45) PRIMARY KEY,
        comment TEXT,
        monitored BOOLEAN NOT NULL DEFAULT FALSE,
        added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_watchlist_ips_added ON watchlist_ips(added_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_watchlist_ips_monitored ON watchlist_ips(monitored) WHERE monitored",
    # 'monitored' flag on the blocklist (additive, idempotent).
    "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS monitored BOOLEAN NOT NULL DEFAULT FALSE",
    "CREATE INDEX IF NOT EXISTS idx_blocked_ips_monitored ON blocked_ips(monitored) WHERE monitored",
    # Persistent baseline of host↔monitored-IP pairs (NetFlow only keeps ~30d).
    """
    CREATE TABLE IF NOT EXISTS monitored_connections (
        id BIGSERIAL PRIMARY KEY,
        monitored_ip VARCHAR(45) NOT NULL,
        host_ip VARCHAR(45) NOT NULL,
        direction VARCHAR(10) NOT NULL,
        first_seen TIMESTAMP WITH TIME ZONE,
        last_seen TIMESTAMP WITH TIME ZONE,
        flows BIGINT NOT NULL DEFAULT 0,
        bytes BIGINT NOT NULL DEFAULT 0,
        dst_port INTEGER,
        protocol INTEGER,
        country VARCHAR(100),
        last_notified_at TIMESTAMP WITH TIME ZONE,
        notify_count INTEGER NOT NULL DEFAULT 0,
        UNIQUE (monitored_ip, host_ip, direction)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_moncon_ip ON monitored_connections(monitored_ip)",
    "CREATE INDEX IF NOT EXISTS idx_moncon_last_seen ON monitored_connections(last_seen DESC)",
    # Append-only event log (new pair / reappeared) for the timeline + alerts.
    """
    CREATE TABLE IF NOT EXISTS monitored_events (
        id BIGSERIAL PRIMARY KEY,
        monitored_ip VARCHAR(45) NOT NULL,
        host_ip VARCHAR(45) NOT NULL,
        direction VARCHAR(10) NOT NULL,
        event_type VARCHAR(20) NOT NULL,
        dst_port INTEGER,
        protocol INTEGER,
        country VARCHAR(100),
        source_list VARCHAR(20),
        detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        notified BOOLEAN NOT NULL DEFAULT FALSE,
        notify_error TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_monevent_detected ON monitored_events(detected_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_monevent_ip ON monitored_events(monitored_ip)",
    # M365 login watch: per-user baseline of known devices / locations. A login
    # outside this baseline raises an alert with a revoke-sessions option.
    """
    CREATE TABLE IF NOT EXISTS m365_login_profiles (
        id BIGSERIAL PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        kind VARCHAR(20) NOT NULL,
        value VARCHAR(255) NOT NULL,
        label VARCHAR(255),
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        seen_count BIGINT NOT NULL DEFAULT 1,
        UNIQUE (user_id, kind, value)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_m365_profiles_user ON m365_login_profiles(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_m365_profiles_last_seen ON m365_login_profiles(last_seen DESC)",
    # CVE severity cache (cvss/KEV/EPSS from the free Shodan CVE DB). Scores are
    # static per CVE, so this is a permanent lookup cache shared across IPs.
    """
    CREATE TABLE IF NOT EXISTS cve_scores (
        cve_id VARCHAR(30) PRIMARY KEY,
        cvss DOUBLE PRECISION,
        cvss_v3 DOUBLE PRECISION,
        severity VARCHAR(12),
        kev BOOLEAN NOT NULL DEFAULT FALSE,
        epss DOUBLE PRECISION,
        summary TEXT,
        fetched_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_cve_scores_severity ON cve_scores(severity)",
    # Internal-IP → hostname cache (Sophos endpoints / reverse DNS / NetBIOS).
    """
    CREATE TABLE IF NOT EXISTS ip_hostnames (
        ip VARCHAR(45) PRIMARY KEY,
        hostname VARCHAR(255),
        source VARCHAR(20),
        resolved_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ip_hostnames_resolved ON ip_hostnames(resolved_at DESC)",
    # MAC address for the internal IP, when known (mainly from firewall DHCP
    # reservations, else the NetBIOS adapter status).
    "ALTER TABLE ip_hostnames ADD COLUMN IF NOT EXISTS mac VARCHAR(17)",
    # Long-term store of every observed IP↔MAC↔hostname combination, so identity
    # changes can be detected across NetFlow retention.
    """
    CREATE TABLE IF NOT EXISTS host_identities (
        id BIGSERIAL PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        mac VARCHAR(17) NOT NULL,
        hostname VARCHAR(255),
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        times_seen INTEGER NOT NULL DEFAULT 1,
        UNIQUE (ip, mac)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_host_identities_ip ON host_identities(ip)",
    "CREATE INDEX IF NOT EXISTS idx_host_identities_mac ON host_identities(mac)",
    # Detected identity changes (audit log + alarm source).
    """
    CREATE TABLE IF NOT EXISTS host_identity_events (
        id BIGSERIAL PRIMARY KEY,
        ip VARCHAR(45),
        mac VARCHAR(17),
        hostname VARCHAR(255),
        event_type VARCHAR(30),
        severity VARCHAR(10),
        detail TEXT,
        detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        notified BOOLEAN NOT NULL DEFAULT FALSE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_host_identity_events_at ON host_identity_events(detected_at DESC)",
    # Honeypot pods (remote decoy agents managed by Warroom) + their events.
    """
    CREATE TABLE IF NOT EXISTS honeypots (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        token_hash VARCHAR(64) NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        services JSONB,
        host_ip VARCHAR(45),
        host_info JSONB,
        last_seen TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_honeypots_token ON honeypots(token_hash)",
    "ALTER TABLE honeypots ADD COLUMN IF NOT EXISTS files JSONB",
    """
    CREATE TABLE IF NOT EXISTS honeypot_events (
        id BIGSERIAL PRIMARY KEY,
        honeypot_id VARCHAR(36) NOT NULL,
        service VARCHAR(20),
        event_type VARCHAR(20),
        source_ip VARCHAR(45),
        source_port INTEGER,
        dest_port INTEGER,
        payload JSONB,
        attacker_country VARCHAR(100),
        attacker_city VARCHAR(255),
        attacker_asn VARCHAR(255),
        attacker_org VARCHAR(255),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_honeypot_events_created ON honeypot_events(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_honeypot_events_pod ON honeypot_events(honeypot_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_honeypot_events_src ON honeypot_events(source_ip)",
    # Acknowledgement of honeypot alerts, keyed by source IP. A source counts as
    # acknowledged while acknowledged_at >= its latest event — new activity after
    # the ack re-surfaces it automatically.
    """
    CREATE TABLE IF NOT EXISTS honeypot_acks (
        source_ip VARCHAR(45) PRIMARY KEY,
        acknowledged_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        acknowledged_by VARCHAR(100)
    )
    """,
    # File-honeypot process whitelist: legitimate processes (e.g. a virus
    # scanner) touch decoy files routinely. A whitelisted process's access is
    # still logged (as a muted event) but never raises an alarm. Scope: pod_id
    # NULL = all pods, file_path NULL = all decoy files. Match prefers the exe
    # full path when present, else the process (comm) name.
    "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS muted BOOLEAN NOT NULL DEFAULT FALSE",
    """
    CREATE TABLE IF NOT EXISTS honeypot_process_whitelist (
        id BIGSERIAL PRIMARY KEY,
        pod_id VARCHAR(36),
        process VARCHAR(500) NOT NULL,
        exe VARCHAR(500),
        file_path VARCHAR(400),
        comment VARCHAR(500),
        created_by VARCHAR(100),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    """CREATE UNIQUE INDEX IF NOT EXISTS idx_hp_procwl_uniq ON honeypot_process_whitelist
        (COALESCE(pod_id,''), lower(process), COALESCE(exe,''), COALESCE(file_path,''))""",
    # --- Attack-map rollup ---------------------------------------------------
    # Daily pre-aggregation of the geo-located firewall_logs that feed the attack
    # map. The map used to aggregate 4-11M raw rows per request (13-30s cold);
    # reading this rollup instead scans thousands. Maintained incrementally by
    # id-watermark (see app/map_rollup.py). Actual first/last-seen timestamps are
    # kept precise even though the bucket is a day.
    """
    CREATE TABLE IF NOT EXISTS fw_map_daily (
        day DATE NOT NULL,
        threat_ip TEXT NOT NULL,
        lat DOUBLE PRECISION NOT NULL,
        lon DOUBLE PRECISION NOT NULL,
        country TEXT,
        city TEXT,
        cnt BIGINT NOT NULL DEFAULT 0,
        max_severity TEXT,
        first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
        last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
        asn TEXT,
        org TEXT,
        has_inbound BOOLEAN NOT NULL DEFAULT FALSE,
        has_outbound BOOLEAN NOT NULL DEFAULT FALSE,
        threats TEXT[] NOT NULL DEFAULT '{}',
        actions TEXT[] NOT NULL DEFAULT '{}',
        log_types TEXT[] NOT NULL DEFAULT '{}',
        dest_ports TEXT[] NOT NULL DEFAULT '{}',
        users TEXT[] NOT NULL DEFAULT '{}',
        firewalls TEXT[] NOT NULL DEFAULT '{}',
        PRIMARY KEY (day, threat_ip, lat, lon)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_fw_map_daily_day ON fw_map_daily(day)",
    # Watermark store for incremental rollups (id of the last firewall_logs row
    # folded into fw_map_daily).
    """
    CREATE TABLE IF NOT EXISTS rollup_state (
        name TEXT PRIMARY KEY,
        last_id BIGINT NOT NULL DEFAULT 0,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    # Aggregate that concatenates arrays across grouped rows (Postgres has no
    # built-in). Used to union the per-day metadata arrays at query time.
    "CREATE OR REPLACE AGGREGATE array_cat_agg(anycompatiblearray) (sfunc = array_cat, stype = anycompatiblearray)",
    # --- AI chat sessions ----------------------------------------------------
    # Persist chat conversations so old sessions can be resumed. Each session has
    # its own message history; a new session starts with a fresh, empty context.
    """
    CREATE TABLE IF NOT EXISTS chat_sessions (
        id BIGSERIAL PRIMARY KEY,
        title TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS chat_messages (
        id BIGSERIAL PRIMARY KEY,
        session_id BIGINT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        tool TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated ON chat_sessions(updated_at DESC)",
    # --- Users, roles & audit log (opt-in auth, gated by auth_enabled) --------
    """
    CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_login TIMESTAMP WITH TIME ZONE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY,
        username TEXT,
        role TEXT,
        method TEXT,
        path TEXT,
        status INTEGER,
        ip TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC)",
    # Durable state for the MDR threat-feed delta push: per-firewall composite
    # cursors (blocked_at, value) live here instead of Redis so a cache flush
    # can't lose delivery progress (which would silently skip indicators).
    """
    CREATE TABLE IF NOT EXISTS mdr_feed_state (
        key VARCHAR(60) PRIMARY KEY,
        value JSONB,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    # --- nmap port scanning of internal hosts ---------------------------------
    # Long-term inventory of scanned internal hosts (survives NetFlow retention).
    """
    CREATE TABLE IF NOT EXISTS host_inventory (
        ip VARCHAR(45) PRIMARY KEY,
        hostname VARCHAR(255),
        mac VARCHAR(17),
        os_guess VARCHAR(255),
        open_ports INTEGER NOT NULL DEFAULT 0,
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_scan_at TIMESTAMP WITH TIME ZONE,
        notes TEXT
    )
    """,
    # One row per scan run.
    """
    CREATE TABLE IF NOT EXISTS host_scans (
        id BIGSERIAL PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        profile VARCHAR(20) NOT NULL,
        status VARCHAR(12) NOT NULL DEFAULT 'running',   -- running | done | error
        arguments TEXT,
        ports_open INTEGER NOT NULL DEFAULT 0,
        os_guess VARCHAR(255),
        duration_ms INTEGER,
        error TEXT,
        started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        finished_at TIMESTAMP WITH TIME ZONE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_host_scans_ip ON host_scans(ip, started_at DESC)",
    # Current state per (ip, port, proto), with first/last seen for history.
    """
    CREATE TABLE IF NOT EXISTS host_ports (
        id BIGSERIAL PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        port INTEGER NOT NULL,
        proto VARCHAR(8) NOT NULL DEFAULT 'tcp',
        state VARCHAR(12) NOT NULL DEFAULT 'open',       -- open | closed
        service VARCHAR(64),
        product VARCHAR(128),
        version VARCHAR(128),
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_state_change TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_host_ports_uniq ON host_ports(ip, port, proto)",
    # Transitions (opened / closed / service_change) — the long-term timeline.
    """
    CREATE TABLE IF NOT EXISTS host_port_events (
        id BIGSERIAL PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        port INTEGER NOT NULL,
        proto VARCHAR(8) NOT NULL DEFAULT 'tcp',
        event_type VARCHAR(20) NOT NULL,                 -- opened | closed | service_change
        service VARCHAR(64),
        detail TEXT,
        detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        notified BOOLEAN NOT NULL DEFAULT FALSE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_host_port_events_ip ON host_port_events(ip, detected_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_host_port_events_time ON host_port_events(detected_at DESC)",
    # --- Tor-only Kali box: command audit + human-in-the-loop -----------------
    """
    CREATE TABLE IF NOT EXISTS kali_commands (
        id BIGSERIAL PRIMARY KEY,
        command TEXT NOT NULL,
        targets TEXT,
        actor VARCHAR(60),
        status VARCHAR(12) NOT NULL DEFAULT 'pending',
        reason TEXT,
        exit_code INTEGER,
        stdout TEXT,
        stderr TEXT,
        tor_exit_ip VARCHAR(45),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        decided_at TIMESTAMP WITH TIME ZONE,
        decided_by VARCHAR(60)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kali_commands_created ON kali_commands(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_kali_commands_status ON kali_commands(status, created_at DESC)",
    # Live online status of internal hosts (nmap ping-sweep presence). Kept
    # separate from host_inventory so any internal IP (also NetFlow-only, never
    # port-scanned) can carry a last-online timestamp.
    """
    CREATE TABLE IF NOT EXISTS host_presence (
        ip VARCHAR(45) PRIMARY KEY,
        last_online TIMESTAMP WITH TIME ZONE,
        last_checked TIMESTAMP WITH TIME ZONE
    )
    """,
    # Current online state at the last check (drives transition detection).
    "ALTER TABLE host_presence ADD COLUMN IF NOT EXISTS online BOOLEAN",
    # Per-host online/offline transition log — compact history for availability
    # (%) and flapping analysis over time.
    """
    CREATE TABLE IF NOT EXISTS host_presence_events (
        id BIGSERIAL PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        online BOOLEAN NOT NULL,
        at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_host_presence_events_ip ON host_presence_events(ip, at)",
    "CREATE INDEX IF NOT EXISTS idx_host_presence_events_at ON host_presence_events(at)",
    # Fleet snapshot per sweep — the online-count time series for the trend chart.
    """
    CREATE TABLE IF NOT EXISTS host_presence_snapshots (
        id BIGSERIAL PRIMARY KEY,
        checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        total INTEGER NOT NULL DEFAULT 0,
        online INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_host_presence_snapshots_at ON host_presence_snapshots(checked_at DESC)",
    # --- Partial indexes for the WAF / IPS dashboards -------------------------
    # These predicates are extremely selective: over a 7-day window only ~13k of
    # ~29M firewall_logs rows are WAF events (0.045%). Without a matching partial
    # index every WAF/IPS widget scanned the whole window and de-JSONB'd each row
    # — minutes per query, and it pinned a pool connection the whole time.
    #
    # The predicates must stay CHARACTER-FOR-CHARACTER identical to
    # _WAF_FILTER_SQL / _IPS_FILTER_SQL in main.py, otherwise Postgres cannot
    # prove the query implies the index predicate and silently falls back to a
    # sequential scan.
    #
    # On an existing large table build these with CREATE INDEX CONCURRENTLY by
    # hand — the statements here run inside a transaction (CONCURRENTLY is not
    # allowed there) and would take an exclusive lock. On a fresh deployment the
    # table is empty, so this is instant.
    """
    CREATE INDEX IF NOT EXISTS idx_fw_logs_waf_created ON firewall_logs (created_at DESC)
    WHERE log_type = 'WAF'
       OR (raw_data->>'log_component') ILIKE '%waf%'
       OR (raw_data->>'log_component') ILIKE '%web app%'
       OR (raw_data->>'log_component') ILIKE '%web server protection%'
       OR (raw_data->>'log_subtype') ILIKE '%waf%'
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_fw_logs_ips_created ON firewall_logs (created_at DESC)
    WHERE log_type IN ('IDP', 'IPS')
       OR (raw_data->>'log_component') ILIKE '%intrusion%'
       OR (raw_data->>'log_component') ILIKE '%idp%'
       OR (raw_data->>'log_component') = 'IPS'
    """,
    # Passwords genuinely in use here, stored only as a keyed fingerprint, so a
    # honeypot submission can be recognised as a leaked credential rather than a
    # lucky guess. The plaintext is never written — see models.MonitoredPassword.
    """
    CREATE TABLE IF NOT EXISTS monitored_passwords (
        id BIGSERIAL PRIMARY KEY,
        label VARCHAR(200) NOT NULL,
        fingerprint VARCHAR(64) NOT NULL UNIQUE,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_by VARCHAR(100),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_hit_at TIMESTAMP WITH TIME ZONE,
        hit_count INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_monitored_pw_fingerprint ON monitored_passwords (fingerprint)",
    # Which registered password a honeypot submission matched, and how loud the
    # alarm was. NULL on the ordinary rows, which are plain guessing.
    "ALTER TABLE honeypot_logins ADD COLUMN IF NOT EXISTS monitored_password_id BIGINT",
    "ALTER TABLE honeypot_logins ADD COLUMN IF NOT EXISTS credential_alarm VARCHAR(20)",
]


async def ensure_schema() -> None:
    # Each migration runs in its own transaction so a transient failure on one
    # statement (e.g. a lock at startup) can't roll back the others. Failures
    # are logged, not fatal — all statements are idempotent and retried next boot.
    # Runs on the background engine: index creation on the large tables can
    # exceed the request pool's 45s statement_timeout.
    for stmt in _MIGRATIONS:
        try:
            async with bg_engine.begin() as conn:
                await conn.execute(text(stmt))
        except Exception as e:
            logger.warning(f"migration failed (will retry next start): {str(e)[:160]} | {stmt[:70].strip()}")


async def get_db():
    """HTTP request path — uses the dedicated request pool."""
    async with request_session() as session:
        yield session
