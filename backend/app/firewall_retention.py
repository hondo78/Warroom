"""Retention purge for the fast-growing ``firewall_logs`` table.

High-volume connection logs (``log_type='Firewall'``) are kept only
``firewall_log_connection_retention_days`` days; all other (security-relevant)
rows are kept ``firewall_log_retention_days`` days.

Deletes run in small batches with a COMMIT per batch, so writers (the syslog
receiver) are never blocked by one long transaction. A per-phase cap bounds the
worst-case runtime; the scheduled job re-runs and catches up over time.

Note: deleting rows frees space for reuse by future inserts but does not shrink
the table file on disk — that needs a VACUUM FULL / pg_repack in a maintenance
window. Retention is about bounding growth and keeping queries fast.
"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.config import settings
from app.database import async_session

logger = logging.getLogger(__name__)

BATCH = 25_000           # rows per delete batch
MAX_PER_RUN = 20_000_000  # safety cap per phase per invocation


async def _purge(where_sql: str, cut: datetime, label: str) -> int:
    """Delete rows matching ``where_sql`` (which references :cut) in batches."""
    deleted = 0
    async with async_session() as db:
        while deleted < MAX_PER_RUN:
            res = await db.execute(
                text(
                    f"DELETE FROM firewall_logs WHERE ctid IN "
                    f"(SELECT ctid FROM firewall_logs WHERE {where_sql} LIMIT :batch)"
                ),
                {"cut": cut, "batch": BATCH},
            )
            await db.commit()
            n = res.rowcount or 0
            deleted += n
            if n < BATCH:
                break
    if deleted:
        logger.info(f"firewall_retention[{label}]: deleted {deleted} row(s) older than {cut.date()}")
    return deleted


async def purge_firewall_logs() -> dict:
    if not settings.firewall_log_retention_enabled:
        return {"skipped": True}

    now = datetime.now(timezone.utc)
    conn_days = max(1, int(settings.firewall_log_connection_retention_days or 14))
    sec_days = max(1, int(settings.firewall_log_retention_days or 90))
    conn_cut = now - timedelta(days=conn_days)
    sec_cut = now - timedelta(days=sec_days)

    # Phase 1: high-volume connection logs past the shorter window
    # (uses idx_fw_logs_type_created).
    conn_deleted = await _purge(
        "log_type = 'Firewall' AND created_at < :cut", conn_cut, "connection"
    )
    # Phase 2: any remaining rows past the longer security window
    # (uses idx_fw_logs_created).
    sec_deleted = await _purge("created_at < :cut", sec_cut, "security")

    # Phase 3: keep the attack-map rollup bounded in step with the logs — the map
    # never queries beyond 90 days anyway, so older rollup days are dead weight.
    async with async_session() as db:
        rollup_deleted = (await db.execute(
            text("DELETE FROM fw_map_daily WHERE day < :cut"),
            {"cut": sec_cut.date()},
        )).rowcount or 0
        await db.commit()
    if rollup_deleted:
        logger.info(f"firewall_retention[map_rollup]: deleted {rollup_deleted} day-row(s) older than {sec_cut.date()}")

    if not (conn_deleted or sec_deleted):
        logger.debug("firewall_retention: nothing to purge")
    return {
        "connection_deleted": conn_deleted,
        "security_deleted": sec_deleted,
        "rollup_deleted": rollup_deleted,
        "connection_cutoff": conn_cut.isoformat(),
        "security_cutoff": sec_cut.isoformat(),
    }
