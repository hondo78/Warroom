"""Periodic snapshot of the Sophos Email Management API into ``email_metrics``.

The Email page is a live proxy (nothing is persisted), so Grafana — which reads
PostgreSQL — has nothing to chart. This collector polls the Email API every
15 min and writes a long-format snapshot (quarantine / post-delivery counts +
reason breakdown, mailbox totals) so the email dashboard can show trends.

Read-only, and a no-op when Sophos credentials are missing or the tenant has no
mailboxes (i.e. no Email Security license / unused).
"""
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.config import settings
from app.database import async_session
from app.models import EmailMetric
from app.sophos_client import sophos_client

logger = logging.getLogger(__name__)

# Drop snapshots older than this so the table can't grow unbounded.
RETENTION_DAYS = 60


def _reason(msg: dict) -> str:
    return str(msg.get("reason") or "unknown")[:160]


async def collect_email_metrics() -> None:
    if not (settings.sophos_client_id and settings.sophos_client_secret):
        return

    try:
        mailboxes = await sophos_client.email_list_mailboxes()
    except Exception as e:
        logger.info(f"email_metrics: mailbox query failed ({e}); skipping snapshot")
        return
    # No mailboxes → tenant has no Email Security (or it's unused). Nothing to
    # record, and we avoid writing misleading zero-rows every cycle.
    if not mailboxes:
        return

    now = datetime.now(timezone.utc)
    begin = now - timedelta(hours=24)

    async def _safe_list(post_delivery: bool) -> list[dict]:
        try:
            return await sophos_client.email_list_quarantine(
                post_delivery=post_delivery, begin_date=begin, end_date=now
            )
        except Exception as e:
            logger.warning(
                f"email_metrics: {'post-delivery ' if post_delivery else ''}"
                f"quarantine query failed: {e}"
            )
            return []

    quarantine = await _safe_list(False)
    postdelivery = await _safe_list(True)

    rows = [
        EmailMetric(bucket=now, metric="mailbox_total", value=len(mailboxes)),
        EmailMetric(bucket=now, metric="mailbox_blocked",
                    value=sum(1 for m in mailboxes if m.get("blocked"))),
        EmailMetric(bucket=now, metric="quarantine_total", value=len(quarantine)),
        EmailMetric(bucket=now, metric="postdelivery_total", value=len(postdelivery)),
    ]
    for reason, cnt in Counter(_reason(m) for m in quarantine).items():
        rows.append(EmailMetric(bucket=now, metric="quarantine_reason", label=reason, value=cnt))
    for reason, cnt in Counter(_reason(m) for m in postdelivery).items():
        rows.append(EmailMetric(bucket=now, metric="postdelivery_reason", label=reason, value=cnt))

    async with async_session() as db:
        db.add_all(rows)
        await db.execute(
            text("DELETE FROM email_metrics WHERE bucket < :cut"),
            {"cut": now - timedelta(days=RETENTION_DAYS)},
        )
        await db.commit()

    logger.info(
        f"email_metrics: snapshot — mailboxes={len(mailboxes)}, "
        f"quarantine_24h={len(quarantine)}, post_delivery_24h={len(postdelivery)}"
    )
