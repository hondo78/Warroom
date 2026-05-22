-- Performance migration 001: composite + trigram + partial indexes.
--
-- Apply on a running DB without blocking writes:
--   docker compose exec -T postgres psql -U warroom -d warroom < db/migrations/001_perf_indexes.sql
--
-- CREATE INDEX CONCURRENTLY cannot run inside an explicit transaction; psql
-- runs each top-level statement in autocommit mode, so the script as written
-- is safe. Do NOT wrap it in BEGIN/COMMIT.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 1. Alerts severity+time composite (replaces single-col severity index).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_severity_created
    ON alerts(severity, created_at DESC);

-- 2. Firewall-logs log_type+time composite (replaces single-col log_type index).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fw_logs_type_created
    ON firewall_logs(log_type, created_at DESC);

-- 3. Trigram GIN on raw_data->>'log_component' for the ILIKE '%waf%' /
--    '%intrusion%' / '%auth%' filters used by WAF, IPS and failed-login stats.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fw_logs_log_component_trgm
    ON firewall_logs USING gin ((raw_data->>'log_component') gin_trgm_ops);

-- 4. Partial index for the top-attackers / map endpoints (attacker_lat IS NOT NULL).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fw_logs_attacker_lat_created
    ON firewall_logs(created_at DESC)
    WHERE attacker_lat IS NOT NULL;

-- 5. Drop the now-redundant single-column indexes (the composites above cover
--    'WHERE severity = ?' / 'WHERE log_type = ?' on their first column).
DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_fw_logs_type;

-- 6. Refresh planner stats so the new indexes actually get picked.
ANALYZE alerts;
ANALYZE firewall_logs;
