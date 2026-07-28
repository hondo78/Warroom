"""Push the blocklists to Sophos firewalls via the Central Firewall API.

This is the *alternative* to the pull-based plaintext IOC feeds (/ioc_IP,
/ioc_domain, /ioc_url). Instead of the firewall polling those, we push the
blocked IPs / domains / URLs to each Central-managed firewall's **MDR threat
feed** with
    POST /firewall/v1/firewalls/{firewallId}/mdr-threat-feed/indicators
using the existing Sophos Central OAuth credentials.

Only the DELTA is pushed: each run sends solely the blocklist entries added
since the last successful push (never the whole list). Progress is tracked by a
tie-safe composite cursor (blocked_at, value) per table and PER FIREWALL,
stored durably in Postgres (``mdr_feed_state``) — so a Redis flush can't lose
it, and one unreachable firewall only stalls its own cursor while the others
keep advancing. The one deliberate exception is ``full=True`` (manual admin
"seed" action) which pushes the entire current blocklists once, e.g. to
provision a newly added firewall.

Push errors are classified: an HTTP 400/409/413/422 is a permanent indicator
rejection (recorded, cursor advances past it), everything else (auth, 429,
5xx, network) is transient — the firewall's cursor does NOT advance and the
same delta is retried next cycle.

Both delivery methods are independently toggled in the admin settings
(``firewall_threat_feed_enabled`` / ``firewall_mdr_feed_enabled``).

NOTE: the exact request-body schema for the indicators endpoint is built in
``_build_indicators_body`` below — the one place to adjust field names / the
type enum if Sophos expects something other than {"indicators":[{type,value}]}.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select, text

from app.config import settings
from app.database import async_session
from app.geoip_service import get_redis
from app.models import BlockedDomain, BlockedIp, BlockedUrl
from app.sophos_client import sophos_client

logger = logging.getLogger(__name__)

# The MDR threat-feed endpoint accepts at most 100 indicators per request.
_CHUNK = 100
# Redis key holding the transaction IDs of the most recent MDR push, so the
# admin can verify afterwards whether the firewall applied them (best-effort).
_LAST_PUSH_KEY = "firewall:mdr:last_push"
_LAST_PUSH_TTL = 24 * 3600

# Postgres row (mdr_feed_state) holding the per-firewall delta cursors:
# {"<firewall_id>": {"ip": {ts, value}|null, "domain": …, "url": …}, …}
_STATE_KEY = "mdr_watermarks"

# blocked_at is assigned in Python BEFORE the row's transaction commits, so a
# row can become visible with a timestamp older than rows we already fetched.
# The delta therefore only considers rows older than this safety lag — anything
# newer waits for the next cycle, closing the out-of-order-commit race.
_COMMIT_LAG_SECONDS = 15

# Only one sync at a time (scheduler vs. manual admin trigger): a concurrent
# call returns "skipped" instead of double-pushing the same delta.
_SYNC_LOCK = asyncio.Lock()

# Auto-discovered firewall-id cache so the steady-state "nothing new" cycle
# doesn't burn a Central list-firewalls API call every interval.
_FW_IDS_TTL = 900
_fw_ids_cache: tuple[float, list[str]] | None = None

# post_mdr_indicators surfaces API errors as RuntimeError("HTTP <code>: …").
# These codes mean the indicator itself was rejected (permanent) — everything
# else is transient and must be retried with the same cursor.
_PERMANENT_HTTP = ("HTTP 400", "HTTP 409", "HTTP 413", "HTTP 422")

# Indicator-type strings sent in the payload. The firewall-v1 MDR threat-feed
# endpoint expects STIX-style cyber-observable type names (verified live against
# the API): IPv4 → "ipv4-addr", domain → "domain-name", URL → "url" (must be a
# full URL incl. scheme). IPv6 / file hashes are not accepted.
_TYPE_IP = "ipv4-addr"
_TYPE_DOMAIN = "domain-name"
_TYPE_URL = "url"


def _is_permanent_reject(exc: BaseException) -> bool:
    """True when the API permanently rejected the indicator value(s) — safe to
    record and move past. False for auth/429/5xx/network (transient)."""
    return isinstance(exc, RuntimeError) and str(exc).startswith(_PERMANENT_HTTP)


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
    """Configured firewall IDs (CSV) or, if empty, all Central-managed firewalls
    (cached for _FW_IDS_TTL so idle cycles don't hit the Central API)."""
    global _fw_ids_cache
    raw = (settings.firewall_mdr_feed_firewall_ids or "").strip()
    if raw:
        return [fid.strip() for fid in raw.split(",") if fid.strip()]
    if _fw_ids_cache and time.monotonic() - _fw_ids_cache[0] < _FW_IDS_TTL:
        return list(_fw_ids_cache[1])
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
    ids = [str(fw.get("id")) for fw in firewalls if fw.get("id")]
    if ids:
        _fw_ids_cache = (time.monotonic(), ids)
    return ids


# --- durable per-firewall cursor (Postgres) ----------------------------------

async def _load_watermarks(db) -> dict:
    row = (await db.execute(
        text("SELECT value FROM mdr_feed_state WHERE key = :k"), {"k": _STATE_KEY}
    )).first()
    val = row[0] if row else None
    if isinstance(val, str):
        try:
            val = json.loads(val)
        except Exception:
            logger.warning("firewall_feed: corrupt MDR cursor state — re-initializing")
            val = None
    return val if isinstance(val, dict) else {}


async def _save_watermarks(db, wms: dict) -> None:
    await db.execute(text("""
        INSERT INTO mdr_feed_state (key, value, updated_at)
        VALUES (:k, CAST(:v AS jsonb), NOW())
        ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS jsonb), updated_at = NOW()
    """), {"k": _STATE_KEY, "v": json.dumps(wms)})
    await db.commit()


async def _current_cursor(db, val_col, ts_col, horizon) -> dict | None:
    """Composite cursor (blocked_at, value) of the newest row at/before the
    horizon, or None if there is none (then any future row is a fresh delta)."""
    row = (await db.execute(
        select(val_col, ts_col)
        .where(ts_col.isnot(None), ts_col <= horizon)
        .order_by(ts_col.desc(), val_col.desc()).limit(1)
    )).first()
    return {"ts": row[1].isoformat(), "value": row[0]} if row else None


async def _fetch_delta(db, val_col, ts_col, wm, horizon) -> list[tuple]:
    """Rows strictly after the composite cursor ``wm`` and at/before the
    commit-lag horizon, tie-safe, oldest first. ``wm=None`` returns everything
    up to the horizon (used by the full seed push)."""
    q = select(val_col, ts_col).where(ts_col.isnot(None), ts_col <= horizon)
    if wm:
        ts = datetime.fromisoformat(wm["ts"])
        q = q.where(or_(ts_col > ts, and_(ts_col == ts, val_col > wm["value"])))
    q = q.order_by(ts_col.asc(), val_col.asc())
    return [(row[0], row[1]) for row in (await db.execute(q)).all()]


async def _push_to_firewall(fid: str, all_inds: list[dict],
                            pre_skipped: list[dict]) -> dict:
    """Push the indicator list to one firewall. Permanent API rejections
    (HTTP 400/409/413/422) are recorded per value; any transient error (auth,
    429, 5xx, network) aborts THIS firewall with ``error`` set so its cursor is
    not advanced and the delta is retried next cycle."""
    pushed = 0
    rejected: list[dict] = list(pre_skipped)  # unsupported values (e.g. wildcards)
    tx_ids: list[str] = []      # transaction IDs to verify the push landed
    error: str | None = None    # transient failure (whole firewall, retried)

    def _record_tx(resp):
        if isinstance(resp, dict) and resp.get("transactionId"):
            tx_ids.append(resp["transactionId"])

    try:
        for chunk in _chunks(all_inds, _CHUNK):
            try:
                _record_tx(await sophos_client.post_mdr_indicators(fid, {"indicators": chunk}))
                pushed += len(chunk)
            except Exception as chunk_err:
                if not _is_permanent_reject(chunk_err):
                    raise  # transient → abort firewall, keep cursor
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
                        if not _is_permanent_reject(item_err):
                            raise
                        rejected.append({**ind, "reason": str(item_err)[:200]})
    except Exception as e:
        error = str(e)[:600]
        logger.warning(f"firewall_feed: push to firewall {fid} aborted (will retry): {e}")
    return {"firewall_id": fid, "pushed": pushed, "rejected": rejected,
            "transaction_ids": tx_ids, "error": error}


async def sync_mdr_threat_feed(force: bool = False, full: bool = False) -> dict:
    """Push the blocklist delta to every targeted firewall's MDR threat feed.

    Normal mode sends ONLY entries added since each firewall's last successful
    push — never the whole list. A firewall without a cursor yet is initialized
    to "now" (nothing pushed); use ``full=True`` (manual admin seed) to push the
    entire current blocklists once, e.g. for a newly added firewall.

    ``force=True`` runs even when the feature is disabled (manual admin trigger).
    Never raises — logs and reports errors; one firewall's failure doesn't abort
    the rest, and a failed firewall keeps its cursor so its delta is retried."""
    if not settings.firewall_mdr_feed_enabled and not force:
        return {"skipped": "firewall_mdr_feed_enabled is off"}
    if _SYNC_LOCK.locked():
        return {"skipped": "another MDR sync is already running"}
    async with _SYNC_LOCK:
        try:
            return await _sync(full)
        except Exception as e:  # keep the "never raises" contract for the scheduler
            logger.warning(f"firewall_feed: MDR sync failed: {e}")
            return {"error": str(e)[:600]}


async def _sync(full: bool) -> dict:
    firewall_ids = await _target_firewall_ids()
    if not firewall_ids:
        logger.info("firewall_feed: no target firewalls; nothing pushed")
        return {"firewalls": [], "indicators": 0, "note": "no target firewalls"}

    horizon = datetime.now(timezone.utc) - timedelta(seconds=_COMMIT_LAG_SECONDS)

    # Phase 1 (DB): load cursors and compute each firewall's delta up front, so
    # no DB session is held across the network pushes.
    plans: list[dict] = []
    async with async_session() as db:
        wms = await _load_watermarks(db)
        snapshot = {
            "ip": await _current_cursor(db, BlockedIp.ip, BlockedIp.blocked_at, horizon),
            "domain": await _current_cursor(db, BlockedDomain.domain, BlockedDomain.blocked_at, horizon),
            "url": await _current_cursor(db, BlockedUrl.url, BlockedUrl.blocked_at, horizon),
        }
        for fid in firewall_ids:
            wm = wms.get(fid)
            if wm is None and not full:
                # New firewall (or first ever run): mark everything current as
                # delivered; only future additions become deltas. Seeding the
                # existing list is the explicit full=True admin action.
                plans.append({"fid": fid, "init": True})
                continue
            base = None if full else wm
            plans.append({"fid": fid, "init": False, "deltas": {
                "ip": await _fetch_delta(db, BlockedIp.ip, BlockedIp.blocked_at,
                                         (base or {}).get("ip"), horizon),
                "domain": await _fetch_delta(db, BlockedDomain.domain, BlockedDomain.blocked_at,
                                             (base or {}).get("domain"), horizon),
                "url": await _fetch_delta(db, BlockedUrl.url, BlockedUrl.blocked_at,
                                          (base or {}).get("url"), horizon),
            }})

    # Phase 2 (network): push per firewall; advance ONLY that firewall's cursor
    # and only when its push had no transient error.
    new_wms = dict(wms)
    changed = False
    results: list[dict] = []
    attempted_total = 0
    wildcards_total = 0
    for plan in plans:
        fid = plan["fid"]
        if plan["init"]:
            new_wms[fid] = snapshot
            changed = True
            logger.info(f"firewall_feed: initialized MDR delta cursor for firewall {fid} "
                        f"— only new blocks are pushed from now on (use the full seed "
                        f"push to deliver the existing lists)")
            results.append({"firewall_id": fid, "pushed": 0, "rejected": [],
                            "transaction_ids": [], "error": None, "initialized": True})
            continue

        deltas = plan["deltas"]
        if not any(deltas.values()):
            results.append({"firewall_id": fid, "pushed": 0, "rejected": [],
                            "transaction_ids": [], "error": None, "no_new": True})
            continue

        ips = [v for v, _ in deltas["ip"]]
        domains = [v for v, _ in deltas["domain"]]
        urls = [v for v, _ in deltas["url"]]
        # The MDR feed rejects wildcard domains (e.g. *.evil.com). Skip them up
        # front (still covered by the pull feed); the cursor advances past them
        # so they're not retried forever.
        wildcard_domains = [d for d in domains if "*" in d]
        domains = [d for d in domains if "*" not in d]
        pre_skipped = [
            {"type": _TYPE_DOMAIN, "value": d,
             "reason": "wildcard domains are not supported by the MDR feed (use the pull feed)"}
            for d in wildcard_domains
        ]
        all_inds = _build_indicators_body(ips, domains, urls)["indicators"]
        attempted_total += len(all_inds)
        wildcards_total += len(wildcard_domains)

        res = await _push_to_firewall(fid, all_inds, pre_skipped)
        if res["error"] is None:
            adv = dict(new_wms.get(fid) or {})
            for key, rows in deltas.items():
                if rows:
                    adv[key] = {"ts": rows[-1][1].isoformat(), "value": rows[-1][0]}
            new_wms[fid] = adv
            changed = True
        results.append(res)

    if changed:
        try:
            async with async_session() as db:
                await _save_watermarks(db, new_wms)
        except Exception as e:
            # Cursor not saved → the same delta is re-pushed next cycle
            # (duplicates, but never data loss).
            logger.warning(f"firewall_feed: could not persist MDR delta cursor: {e}")

    ok = sum(1 for x in results if x["error"] is None)
    rej = sum(len(x["rejected"]) for x in results)
    if attempted_total or rej:
        logger.info(
            f"firewall_feed: MDR {'full seed' if full else 'delta'} push — "
            f"{attempted_total} indicator(s) attempted to {ok}/{len(firewall_ids)} "
            f"firewall(s), {rej} value(s) rejected"
            + (f", {wildcards_total} wildcard(s) skipped" if wildcards_total else "")
        )

    # Stash the transaction IDs so a later /verify can confirm the firewall
    # actually applied them (best-effort — never break the push on a Redis error).
    if attempted_total:
        try:
            r = await get_redis()
            await r.setex(_LAST_PUSH_KEY, _LAST_PUSH_TTL, json.dumps({
                "pushed_at": datetime.now(timezone.utc).isoformat(),
                "indicators": attempted_total,
                "firewalls": [
                    {"firewall_id": x["firewall_id"], "pushed": x["pushed"],
                     "transaction_ids": x["transaction_ids"]}
                    for x in results if x["transaction_ids"]
                ],
            }))
        except Exception as e:
            logger.debug(f"firewall_feed: could not store last-push tx ids: {e}")

    out = {"firewalls": results, "indicators": attempted_total,
           "skipped_wildcards": wildcards_total, "delta": not full, "full": full}
    if results and all(x.get("initialized") for x in results):
        out["initialized"] = True
        out["note"] = "delta cursor initialized — only new blocks are pushed from now on"
    elif results and all(x.get("no_new") for x in results):
        out["no_new"] = True
        out["note"] = "no new indicators"
    return out


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
