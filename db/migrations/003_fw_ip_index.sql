-- Performance migration 003: covering index on firewall_logs(firewall_ip).
--
-- Apply on a running DB without blocking writes:
--   docker compose exec -T postgres psql -U warroom -d warroom < db/migrations/003_fw_ip_index.sql
--
-- WHY: /api/firewalls/extended (the Firewall-Übersicht page, refreshed every
-- 60s) runs
--     SELECT firewall_ip, max(firewall_name), count(*), max(created_at)
--     FROM firewall_logs WHERE firewall_ip IS NOT NULL GROUP BY firewall_ip
-- There was NO index on firewall_ip, and max(firewall_name) forces firewall_name
-- to be read for every row, so this was a full seq scan of the ~40 GB heap on
-- every page load (tens of seconds).
--
-- This index covers all three aggregated columns (firewall_ip + created_at as
-- key, firewall_name as INCLUDE payload), so the GROUP BY becomes an index-only
-- scan — no heap access. count(*)/max(created_at)/max(firewall_name) per
-- firewall are all answered straight from the index.
--
-- CREATE INDEX CONCURRENTLY must NOT run inside a transaction; psql autocommits
-- each top-level statement, so this script is safe. Do NOT wrap in BEGIN/COMMIT.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fw_logs_ip_created
    ON firewall_logs(firewall_ip, created_at DESC) INCLUDE (firewall_name);

ANALYZE firewall_logs;
