"""Push the blocklists to Sophos firewalls via the Central Firewall API.

This is the *alternative* to the pull-based plaintext IOC feeds (/ioc_IP,
/ioc_domain, /ioc_url). Instead of the firewall polling those, we push the
blocked IPs / domains / URLs to each Central-managed firewall's **MDR threat
feed** with
    POST /firewall/v1/firewalls/{firewallId}/mdr-threat-feed/indicators
using the existing Sophos Central OAuth credentials.

Only the DELTA is pushed: each run sends solely the blocklist entries added
since the last successful push (never the whole list). Progress is tracked by a
tie-safe per-table cursor (blocked_at, value) in Redis — see ``_WATERMARK_KEY``.

Both delivery methods are independently toggled in the admin settings
(``firewall_threat_feed_enabled`` / ``firewall_mdr_feed_enabled``).

NOTE: the exact request-body schema for the indicators endpoint is built in
``_build_indicators_body`` below — the one place to adjust field names / the
type enum if Sophos expects something other than {"indicators":[{type,value}]}.
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import and_, or_, select

from app.config import settings
from app.database import async_session
from app.geoip_service import get_redis
from app.models import BlockedDomain, BlockedIp, BlockedUrl
from app.sophos_client import sophos_client

logger = logging.getLogger(__name__)

# The MDR threat-feed endpoint accepts at most 100 indicators per request.
_CHUNK = 100
# Redis key holding the transaction IDs of the most recent MDR push, so the
# admin can verify afterwards whether the firewall applied them.
_LAST_PUSH_KEY = "firewall:mdr:last_push"
_LAST_PUSH_TTL = 24 * 3600

# Indicator-type strings sent in the payload. The firewall-v1 MDR threat-feed
# endpoint expects STIX-style cyber-observable type names (verified live against
# the API): IPv4 → "ipv4-addr", domain → "domain-name", URL → "url" (must be a
# full URL incl. scheme). IPv6 / file hashes are not accepted.
_TYPE_IP = "ipv4-addr"
_TYPE_DOMAIN = "domain-name"
_TYPE_URL = "url"


def _build_indicators_body(ips: list[str], domains: list[str], urls: list[str]) -> dict:
    """Build the POST body for the MDR threat-feed indicators endpoint.

    Best-effort shape — confirm against the firewall-v1 doc and adjust here only.
    """
    indicators: list[dict] = []
    indicators.extend({"type": _TYPE_IP, "value": v} for v in ips)
    indicators.extend({"type": _TYPE_DOMAIN, "value": v} for v in domains)
    indicators.extend({"type": _TYPE_URL, "value": v} for v in urls)
    return {"indicators": indicators}


def _chunks(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


async def _target_firewall_ids() -> list[str]:
    """Configured firewall IDs (CSV) or, if empty, all Central-managed firewalls."""
    raw = (settings.firewall_mdr_feed_firewall_ids or "").strip()
    if raw:
        return [fid.strip() for fid in raw.split(",") if fid.strip()]
    firewalls = None
    for attempt in (1, 2):
        try:
            firewalls = await sophos_client.get_firewalls()
            break
        except Exception as e:
            # On a cold client the first call can hit the default region with a
            # not-yet-region-scoped token (401); the failed call triggers a
            # re-auth + region resolve, so a single retry succeeds.
            logger.warning(f"firewall_feed: list firewalls attempt {attempt} failed: {e}")
    if not firewalls:
        return []
    return [str(fw.get("id")) for fw in firewalls if fw.get("id")]


# Redis key holding the per-table delta cursor. Value is a composite
# (blocked_at, value) per list, which is tie-safe: a bulk block (block_ips /
# block_subnet) writes many rows sharing ONE blocked_at, so a plain
# ``blocked_at >`` cursor would skip its siblings. No TTL (persistent). If it's
# ever lost (Redis flush) we re-initialize to the CURRENT newest entry and push
# nothing — so the whole list is never sent.
_WATERMARK_KEY = "firewall:mdr:watermark"


async def _load_watermark(r) -> dict | None:
    raw = await r.get(_WATERMARK_KEY)
    if not raw:
        return None
    try:
        wm = json.loads(raw)
        return wm if isinstance(wm, dict) else None
    except Exception:
        return None


async def _save_watermark(r, wm: dict) -> None:
    await r.set(_WATERMARK_KEY, json.dumps(wm))


async def _current_cursor(db, val_col, ts_col) -> dict | None:
    """Composite cursor (blocked_at, value) of the newest row, or None if the
    table is empty (then any future row is a fresh delta)."""
    row = (await db.execute(
        select(val_col, ts_col).where(ts_col.isnot(None))
        .order_by(ts_col.desc(), val_col.desc()).limit(1)
    )).first()
    return {"ts": row[1].isoformat(), "value": row[0]} if row else None


async def _fetch_delta(db, val_col, ts_col, wm) -> list[tuple]:
    """Rows strictly after the composite cursor ``wm``, tie-safe, oldest first."""
    q = select(val_col, ts_col).where(ts_col.isnot(None))
    if wm:
        ts = datetime.fromisoformat(wm["ts"])
        q = q.where(or_(ts_col > ts, and_(ts_col == ts, val_col > wm["value"])))
    q = q.order_by(ts_col.asc(), val_col.asc())
    return [(row[0], row[1]) for row in (await db.execute(q)).all()]


async def sync_mdr_threat_feed(force: bool = False) -> dict:
    """Push ONLY the newly-added blocklist entries (the delta since the last
    successful push) to every targeted firewall's MDR threat feed — never the
    whole list. A per-table composite cursor (blocked_at, value) is kept in
    Redis; on the first run (or after the cursor is lost) it initializes to the
    current newest entry and pushes nothing, so a full list is never sent.

    ``force=True`` runs even when the feature is disabled (manual admin trigger)
    but still pushes only the delta. Never raises — logs/reports errors so a
    single firewall failure doesn't abort the rest."""
    if not settings.firewall_mdr_feed_enabled and not force:
        return {"skipped": "firewall_mdr_feed_enabled is off"}

    firewall_ids = await _target_firewall_ids()
    if not firewall_ids:
        logger.info("firewall_feed: no target firewalls; nothing pushed")
        return {"firewalls": [], "indicators": 0, "note": "no target firewalls"}

    # The delta cursor lives in Redis. If Redis is unavailable we can't know what
    # was already delivered — skip rather than risk sending the whole list.
    try:
        r = await get_redis()
    except Exception:
        r = None
    if r is None:
        logger.warning("firewall_feed: Redis unavailable — MDR delta push skipped")
        return {"skipped": "redis unavailable — delta cursor not accessible"}

    wm = await _load_watermark(r)
    async with async_session() as db:
        if wm is None:
            # First run / cursor lost: treat everything currently blocked as
            # already delivered; only future additions become deltas.
            wm = {
                "ip": await _current_cursor(db, BlockedIp.ip, BlockedIp.blocked_at),
                "domain": await _current_cursor(db, BlockedDomain.domain, BlockedDomain.blocked_at),
                "url": await _current_cursor(db, BlockedUrl.url, BlockedUrl.blocked_at),
            }
            await _save_watermark(r, wm)
            logger.info("firewall_feed: initialized MDR delta cursor — only new "
                        "blocks are pushed from now on")
            return {"firewalls": [], "indicators": 0, "initialized": True,
                    "note": "delta cursor initialized — only new blocks are pushed from now on"}

        ip_delta = await _fetch_delta(db, BlockedIp.ip, BlockedIp.blocked_at, wm.get("ip"))
        dom_delta = await _fetch_delta(db, BlockedDomain.domain, BlockedDomain.blocked_at, wm.get("domain"))
        url_delta = await _fetch_delta(db, BlockedUrl.url, BlockedUrl.blocked_at, wm.get("url"))

    total = len(ip_delta) + len(dom_delta) + len(url_delta)
    if total == 0:
        logger.debug("firewall_feed: MDR delta empty — nothing new to push")
        return {"firewalls": [], "indicators": 0, "note": "no new indicators"}

    ips = [v for v, _ in ip_delta]
    domains = [v for v, _ in dom_delta]
    urls = [v for v, _ in url_delta]

    # The MDR feed rejects wildcard domains (e.g. *.evil.com). Skip them up front
    # (still covered by the pull feed); the cursor advances past them so they're
    # not retried forever.
    wildcard_domains = [d for d in domains if "*" in d]
    domains = [d for d in domains if "*" not in d]
    pre_skipped = [
        {"type": _TYPE_DOMAIN, "value": d,
         "reason": "wildcard domains are not supported by the MDR feed (use the pull feed)"}
        for d in wildcard_domains
    ]

    all_inds = _build_indicators_body(ips, domains, urls)["indicators"]
    results: list[dict] = []
    for fid in firewall_ids:
        pushed = 0
        rejected: list[dict] = list(pre_skipped)  # unsupported values (e.g. wildcards)
        tx_ids: list[str] = []      # transaction IDs to verify the push landed
        error: str | None = None    # transport/auth failure (whole firewall)

        def _record_tx(resp):
            if isinstance(resp, dict) and resp.get("transactionId"):
                tx_ids.append(resp["transactionId"])

        try:
            for chunk in _chunks(all_inds, _CHUNK):
                try:
                    _record_tx(await sophos_client.post_mdr_indicators(fid, {"indicators": chunk}))
                    pushed += len(chunk)
                except Exception as chunk_err:
                    # One invalid value fails the whole chunk — retry item-by-item
                    # so the valid indicators still go through and we can report
                    # exactly which values were rejected.
                    if len(chunk) == 1:
                        rejected.append({**chunk[0], "reason": str(chunk_err)[:200]})
                        continue
                    for ind in chunk:
                        try:
                            _record_tx(await sophos_client.post_mdr_indicators(fid, {"indicators": [ind]}))
                            pushed += 1
                        except Exception as item_err:
                            rejected.append({**ind, "reason": str(item_err)[:200]})
        except Exception as e:
            # Non-recoverable (auth/network) — abort this firewall.
            error = str(e)[:600]
            logger.warning(f"firewall_feed: push to firewall {fid} aborted: {e}")
        results.append({"firewall_id": fid, "pushed": pushed,
                        "rejected": rejected, "transaction_ids": tx_ids, "error": error})

    ok = sum(1 for x in results if x["error"] is None)
    rej = sum(len(x["rejected"]) for x in results)
    logger.info(
        f"firewall_feed: MDR delta push — {total} new indicator(s) to {ok}/{len(firewall_ids)} "
        f"firewall(s), {rej} value(s) rejected"
    )

    # Advance the cursor to the newest fetched entry per table — but only once at
    # least one firewall accepted the push, so a total failure retries the same
    # delta next cycle instead of silently dropping it.
    if ok >= 1:
        new_wm = dict(wm)
        if ip_delta:
            new_wm["ip"] = {"ts": ip_delta[-1][1].isoformat(), "value": ip_delta[-1][0]}
        if dom_delta:
            new_wm["domain"] = {"ts": dom_delta[-1][1].isoformat(), "value": dom_delta[-1][0]}
        if url_delta:
            new_wm["url"] = {"ts": url_delta[-1][1].isoformat(), "value": url_delta[-1][0]}
        try:
            await _save_watermark(r, new_wm)
        except Exception as e:
            logger.warning(f"firewall_feed: could not persist MDR delta cursor: {e}")

    # Stash the transaction IDs so a later /verify can confirm the firewall
    # actually applied them (best-effort — never break the push on a Redis error).
    try:
        r = await get_redis()
        await r.setex(_LAST_PUSH_KEY, _LAST_PUSH_TTL, json.dumps({
            "pushed_at": datetime.now(timezone.utc).isoformat(),
            "indicators": total,
            "firewalls": [
                {"firewall_id": x["firewall_id"], "pushed": x["pushed"],
                 "transaction_ids": x["transaction_ids"]}
                for x in results
            ],
        }))
    except Exception as e:
        logger.debug(f"firewall_feed: could not store last-push tx ids: {e}")

    return {"firewalls": results, "indicators": total, "delta": True}


async def verify_last_push() -> dict:
    """Poll the transactions from the most recent MDR push and report, per
    firewall, how many the firewall has applied (completed) vs. are still
    pending / failed. ``applied`` is True once every transaction completed."""
    try:
        r = await get_redis()
        raw = await r.get(_LAST_PUSH_KEY)
    except Exception as e:
        return {"error": f"redis unavailable: {e}"}
    if not raw:
        return {"error": "no recent MDR push found (push first, then verify)"}
    data = json.loads(raw)

    firewalls = []
    for fw in data.get("firewalls", []):
        fid = fw["firewall_id"]
        tx_ids = fw.get("transaction_ids", [])
        counts = {"completed": 0, "pending": 0, "failed": 0, "unknown": 0}
        last_error = None
        for tx in tx_ids:
            try:
                t = await sophos_client.get_firewall_transaction(fid, tx)
                status = (t.get("status") or "").lower()
                result = (t.get("result") or "").lower()
                if status == "completed" and result in ("success", ""):
                    counts["completed"] += 1
                elif status in ("pending", "inprogress"):
                    counts["pending"] += 1
                elif status == "failed" or result == "failed":
                    counts["failed"] += 1
                    last_error = t.get("response") or result or "failed"
                else:
                    counts["unknown"] += 1
            except Exception as e:
                counts["unknown"] += 1
                last_error = str(e)[:200]
        firewalls.append({
            "firewall_id": fid,
            "pushed": fw.get("pushed", 0),
            "transactions": len(tx_ids),
            **counts,
            "applied": len(tx_ids) > 0 and counts["completed"] == len(tx_ids),
            "last_error": last_error,
        })
    return {"pushed_at": data.get("pushed_at"), "indicators": data.get("indicators"),
            "firewalls": firewalls}
