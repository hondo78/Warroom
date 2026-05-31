-- Performance migration 002: plain created_at index on firewall_logs.
--
-- Apply on a running DB without blocking writes:
--   docker compose exec -T postgres psql -U warroom -d warroom < db/migrations/002_fw_created_index.sql
--
-- WHY: db/init.sql already declares idx_fw_logs_created, but init.sql only runs
-- on a FRESH postgres volume. Databases created before that line was added never
-- got the index. The composite idx_fw_logs_type_created(log_type, created_at)
-- does NOT help queries that filter/sort by created_at WITHOUT a log_type — so
-- the Grafana panels "Letzte Firewall-Logs" (ORDER BY created_at DESC LIMIT) and
-- the time-range counts fell back to a full seq scan + sort of the whole 40 GB
-- table (30-40 s each). With this index they become sub-second index scans.
--
-- CREATE INDEX CONCURRENTLY must NOT run inside a transaction; psql autocommits
-- each top-level statement, so this script is safe. Do NOT wrap in BEGIN/COMMIT.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fw_logs_created
    ON firewall_logs(created_at DESC);

ANALYZE firewall_logs;
