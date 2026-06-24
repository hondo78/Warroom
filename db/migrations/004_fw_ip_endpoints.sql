-- Performance migration 004: source_ip / destination_ip lookup indexes.
--
-- Apply on a running DB without blocking writes:
--   docker compose exec -T postgres psql -U warroom -d warroom < db/migrations/004_fw_ip_endpoints.sql
--
-- WHY: db/init.sql declares idx_fw_logs_src / idx_fw_logs_dst, but init.sql only
-- runs on a FRESH postgres volume — databases created before never got them. As
-- a result ANY query filtering firewall_logs by source_ip or destination_ip
-- (e.g. the OSINT "Bekannte Verbindungen → Firewall: geblockte Versuche" panel,
-- /api/ip/{ip}/connections) fell back to a parallel seq scan of the whole ~40 GB
-- table (60 s+ → timeout). These composite indexes (ip, created_at DESC) turn
-- the per-IP + time-window lookups into fast index range scans.
--
-- CREATE INDEX CONCURRENTLY must NOT run inside a transaction; psql autocommits
-- each top-level statement, so this script is safe. Do NOT wrap in BEGIN/COMMIT.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fw_logs_src_created
    ON firewall_logs(source_ip, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fw_logs_dst_created
    ON firewall_logs(destination_ip, created_at DESC);

ANALYZE firewall_logs;
