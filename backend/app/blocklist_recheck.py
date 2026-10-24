"""Weekly OSINT re-check of blocks that were made on OSINT evidence.

The triage and anomaly agents block an IP because AbuseIPDB, VirusTotal,
GreyNoise, Intelix or Shodan said it was malicious. That verdict ages: a
compromised host gets cleaned up, a vulnerable service gets patched, a dynamic
address moves on to a new customer. This job asks the same providers again,
once per interval per IP. If none of them flags the IP any more, the block is
lifted and the entry moves to ``released_ips`` — history only, so it stays
traceable that there was a problem and what it was.

The rules mirror the triage agent's block rules, so "no longer malicious" means
exactly "the rule that blocked it would not block it today". No LLM is involved.

Fail-safe in every direction: a provider that did not answer, an exhausted
quota or an unreadable payload leaves the block in place ("inconclusive") and
the IP is retried at the next interval. Only an affirmative clean result from
enough providers releases an IP.
"""
import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select

from app.config import settings
from app.database import async_session
from app.models import AgentDecision, BlockedIp, OsintResult, ReleasedIp, ShodanHost

logger = logging.getLogger(__name__)

# Same thresholds as the triage agent's block rules (DEFAULT_TRIAGE_PROMPT).
ABUSE_THRESHOLD = 75
VT_THRESHOLD = 2
INTELIX_SCORE_THRESHOLD = 70

# Intelix IP categories that describe what an address is, not that it is bad.
# Every other category (botnet, spam_mta, anything new) counts as a hit — an
# unknown label keeps the block rather than lifting it.
INTELIX_BENIGN = {
    "enduser_network", "clean_mta", "bulk_mta", "bulk_mta_grey",
    "news_mta", "notifications_mta",
}

# The providers that can make an IP count as malicious. A clean verdict needs
# every provider that flagged the IP when it was blocked to answer clean now,
# and at least two of them overall, one of which must be AbuseIPDB or
# VirusTotal — GreyNoise and Intelix alone see too little to clear an IP.
VERDICT_PROVIDERS = ("abuseipdb", "virustotal", "greynoise", "intelix")
MIN_ANSWERED = 2

# VirusTotal's public API allows 4 requests a minute.
PAUSE_BETWEEN_IPS_SECONDS = 16

LAST_RUN_KEY = "blocklist_recheck:last_run"

# Providers a block comment names. The comment is written once, at block time,
# while osint_results only holds the latest lookup — so the comment is the
# durable record of which providers the block rested on. Naming a provider in
# passing ("no Intelix hit") only makes the check stricter.
_PROVIDER_IN_COMMENT = {
    "abuseipdb": re.compile(r"abuseipdb", re.IGNORECASE),
    "virustotal": re.compile(r"virustotal|\bVT\b", re.IGNORECASE),
    "greynoise": re.compile(r"greynoise", re.IGNORECASE),
    "intelix": re.compile(r"intelix", re.IGNORECASE),
}

# A block comment that cites CVEs: the block rested on Shodan even when no
# Shodan record was stored for the IP (only records with ports/CVEs are kept).
_CVE_REASON = re.compile(r"CVE-\d|has_high_critical|high/critical", re.IGNORECASE)


def _sources() -> list[str]:
    raw = getattr(settings, "blocklist_recheck_sources", "") or ""
    return [s.strip() for s in raw.split(",") if s.strip()]


def _interval() -> timedelta:
    return timedelta(days=max(1, int(getattr(settings, "blocklist_recheck_interval_days", 7) or 7)))


def _intelix_hits(intel: dict[str, Any]) -> list[str]:
    hits: list[str] = []
    if intel.get("security_category"):
        hits.append(f"Intelix security category '{intel['security_category']}'")
    score = intel.get("score")
    if isinstance(score, (int, float)) and score >= INTELIX_SCORE_THRESHOLD:
        hits.append(f"Intelix score {score}")
    cats = [c.strip() for c in str(intel.get("category") or "").split(",") if c.strip()]
    bad = [c for c in cats if c.lower() not in INTELIX_BENIGN]
    if bad:
        hits.append(f"Intelix category {', '.join(bad)}")
    return hits


def evaluate(payload: dict[str, Any]) -> tuple[list[tuple[str, str]], list[str]]:
    """Return (hits, answered): the block rules this OSINT payload triggers as
    (provider, explanation) pairs, and which verdict providers answered."""
    hits: list[tuple[str, str]] = []
    answered: list[str] = []

    ab = payload.get("abuseipdb") or {}
    if ab.get("available"):
        answered.append("abuseipdb")
        score = ab.get("abuse_score")
        if isinstance(score, (int, float)) and score >= ABUSE_THRESHOLD:
            hits.append(("abuseipdb", f"AbuseIPDB score {score}"))

    vt = payload.get("virustotal") or {}
    if vt.get("available"):
        answered.append("virustotal")
        mal = vt.get("malicious")
        if isinstance(mal, (int, float)) and mal >= VT_THRESHOLD:
            hits.append(("virustotal", f"VirusTotal {mal}× malicious"))

    gn = payload.get("greynoise") or {}
    if gn.get("available"):
        answered.append("greynoise")
        if gn.get("classification") == "malicious":
            hits.append(("greynoise", "GreyNoise 'malicious'"))

    intel = payload.get("intelix") or {}
    if intel.get("available"):
        answered.append("intelix")
        hits.extend(("intelix", h) for h in _intelix_hits(intel))

    return hits, answered


def _shodan_hits(shodan: dict[str, Any]) -> list[str]:
    sev = shodan.get("cve_severity") or {}
    hits: list[str] = []
    if sev.get("has_high_critical"):
        worst = (sev.get("top") or [{}])[0]
        hits.append(f"Shodan {sev.get('high_critical', 0)} High/Critical CVE(s)"
                    + (f", worst {worst.get('cve')} (CVSS {worst.get('cvss')})" if worst.get("cve") else ""))
    if sev.get("kev"):
        hits.append(f"Shodan {sev['kev']} actively exploited CVE(s) (CISA KEV)")
    return hits


def _snapshot(payload: dict[str, Any], shodan: dict[str, Any] | None = None) -> dict[str, Any]:
    """The values a human needs to see why an IP was or is (not) malicious."""
    ab = payload.get("abuseipdb") or {}
    vt = payload.get("virustotal") or {}
    gn = payload.get("greynoise") or {}
    intel = payload.get("intelix") or {}
    out = {
        "abuse_score": ab.get("abuse_score") if ab.get("available") else None,
        "abuse_reports": ab.get("total_reports") if ab.get("available") else None,
        "vt_malicious": vt.get("malicious") if vt.get("available") else None,
        "greynoise": gn.get("classification") if gn.get("available") else None,
        "intelix_category": (intel.get("security_category") or intel.get("category"))
                            if intel.get("available") else None,
    }
    if shodan is not None and shodan.get("available"):
        sev = shodan.get("cve_severity") or {}
        out["shodan_cves"] = len(shodan.get("vulns") or [])
        out["shodan_high_critical"] = sev.get("high_critical", 0)
    return out


async def _stored_evidence(db, ip: str, comment: str | None) -> tuple[dict[str, Any], set[str], bool]:
    """The OSINT evidence on record before this run (for the history entry),
    the providers the block rested on (each must answer clean now), and
    whether the block may have rested on high/critical Shodan CVEs."""
    before: dict[str, Any] = {}
    flagged_before = {p for p, rx in _PROVIDER_IN_COMMENT.items() if rx.search(comment or "")}
    row = await db.get(OsintResult, ip)
    if row is not None:
        # The stored columns keep each provider's last real answer (a failed
        # lookup does not overwrite them), unlike raw, which is the last payload.
        if (row.abuse_score or 0) >= ABUSE_THRESHOLD:
            flagged_before.add("abuseipdb")
        if (row.vt_malicious or 0) >= VT_THRESHOLD:
            flagged_before.add("virustotal")
        if row.greynoise == "malicious":
            flagged_before.add("greynoise")
        if row.intelix_category and _intelix_hits({"category": row.intelix_category}):
            flagged_before.add("intelix")
        before = {
            "abuse_score": row.abuse_score,
            "vt_malicious": row.vt_malicious,
            "greynoise": row.greynoise,
            "intelix_category": row.intelix_category,
            "checked_at": row.last_seen.isoformat() if row.last_seen else None,
        }
    needs_shodan = bool(_CVE_REASON.search(comment or ""))
    sh = await db.get(ShodanHost, ip)
    if sh is not None and sh.vulns:
        before["shodan_cves"] = len(sh.vulns)
        try:
            from app.cve_severity import enrich_cves
            sev = await enrich_cves(list(sh.vulns))
            before["shodan_high_critical"] = sev.get("high_critical", 0)
            needs_shodan = needs_shodan or bool(sev.get("has_high_critical") or sev.get("kev"))
        except Exception as e:
            # Can't tell whether the CVEs mattered — assume they did.
            logger.warning(f"blocklist recheck: CVE severity for {ip} failed: {e}")
            needs_shodan = True
    return before, flagged_before, needs_shodan


async def _decision_for(db, ip: str) -> int | None:
    """The executed agent decision that most likely created this block."""
    q = (select(AgentDecision.id)
         .where(AgentDecision.status == "executed")
         .where(or_(AgentDecision.source_ip == ip,
                    AgentDecision.action_args["target_ip"].astext == ip))
         .order_by(AgentDecision.id.desc()).limit(1))
    return (await db.execute(q)).scalar()


async def recheck_ip(ip: str) -> dict[str, Any]:
    """Re-check one blocked IP and act on the result. Returns
    {"ip", "result": released|malicious|inconclusive|gone, "note"}."""
    from app.osint import lookup, shodan_enrich

    async with async_session() as db:
        entry = await db.get(BlockedIp, ip)
        if entry is None:
            return {"ip": ip, "result": "gone", "note": "no longer on the blocklist"}
        before, flagged_before, needs_shodan = await _stored_evidence(db, ip, entry.comment)

    payload = await lookup(ip, force=True, context="recheck")
    hits, answered = evaluate(payload)
    # A provider that flagged the IP back then has to say "clean" itself: a
    # silent GreyNoise must not count as a GreyNoise that changed its mind.
    missing = sorted(flagged_before - set(answered))
    shodan: dict[str, Any] | None = None

    if hits:
        result, note = "malicious", "Still flagged: " + "; ".join(h for _, h in hits)
    elif missing:
        result = "inconclusive"
        note = f"{', '.join(missing)} did not answer, but the block rested on it — keeping the block"
    elif len(answered) < MIN_ANSWERED or not ({"abuseipdb", "virustotal"} & set(answered)):
        result = "inconclusive"
        note = (f"Only {', '.join(answered) or 'no provider'} answered — "
                f"not enough to clear the IP, keeping the block")
    elif needs_shodan:
        # The other providers are clean, but the block may have rested on
        # Shodan CVEs: only a fresh Shodan answer can clear that.
        from app.osint_metrics import quota_exhausted
        if await quota_exhausted("shodan"):
            result, note = "inconclusive", "Shodan quota reached — CVE status unknown, keeping the block"
        else:
            shodan = await shodan_enrich(ip)
            if not shodan.get("available"):
                result = "inconclusive"
                note = f"Shodan did not answer ({shodan.get('reason') or 'unavailable'}) — keeping the block"
            elif _shodan_hits(shodan):
                result, note = "malicious", "Still flagged: " + "; ".join(_shodan_hits(shodan))
            else:
                result = "released"
    else:
        result = "released"

    now = datetime.now(timezone.utc)
    async with async_session() as db:
        entry = await db.get(BlockedIp, ip)
        if entry is None:
            return {"ip": ip, "result": "gone", "note": "removed while being checked"}
        if result != "released":
            entry.recheck_at = now
            entry.recheck_status = result
            entry.recheck_note = note[:1000]
            await db.commit()
            return {"ip": ip, "result": result, "note": note}

        after = _snapshot(payload, shodan)
        note = (f"Clean on re-check ({', '.join(answered)}"
                + (", shodan" if shodan is not None else "") + "): "
                + ", ".join(f"{k}={v}" for k, v in after.items() if v is not None))
        db.add(ReleasedIp(
            ip=ip, blocked_at=entry.blocked_at, blocked_by=entry.blocked_by,
            source=entry.source, block_comment=entry.comment,
            decision_id=await _decision_for(db, ip),
            released_at=now, released_by="recheck", release_note=note[:2000],
            osint_before=before, osint_after=after,
        ))
        await db.delete(entry)
        await db.commit()
    logger.info(f"blocklist recheck: released {ip} — {note}")
    return {"ip": ip, "result": "released", "note": note}


def due_query():
    """Agent blocks from the configured sources whose last check (or the block
    itself) is older than the interval. Monitored IPs are left alone — someone
    flagged them on purpose."""
    cutoff = datetime.now(timezone.utc) - _interval()
    return (select(BlockedIp.ip)
            .where(BlockedIp.blocked_by == "agent")
            .where(BlockedIp.source.in_(_sources()))
            .where(BlockedIp.monitored.is_(False))
            .where(BlockedIp.blocked_at < cutoff)
            .where(or_(BlockedIp.recheck_at.is_(None), BlockedIp.recheck_at < cutoff)))


async def blocklist_recheck_job(force: bool = False) -> dict[str, Any]:
    """Scheduler entry point (hourly). Works through up to batch_size due IPs,
    oldest first, so the weekly pass is spread across the week instead of
    hitting the providers' rate limits in one burst."""
    if not force and not getattr(settings, "blocklist_recheck_enabled", True):
        return {"skipped": "disabled"}
    if not _sources():
        return {"skipped": "no sources configured"}

    from sqlalchemy import func
    from app.osint_metrics import quota_exhausted

    batch = max(1, int(getattr(settings, "blocklist_recheck_batch_size", 25) or 25))
    async with async_session() as db:
        q = due_query()
        ips = (await db.execute(
            q.order_by(func.coalesce(BlockedIp.recheck_at, BlockedIp.blocked_at).asc()).limit(batch)
        )).scalars().all()

    summary: dict[str, Any] = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checked": 0, "released": 0, "malicious": 0, "inconclusive": 0,
        "released_ips": [], "stopped": None,
    }
    for i, ip in enumerate(ips):
        # Stop rather than burn the rest of the day's allowance: a quota-less
        # provider would only turn every remaining IP "inconclusive" anyway.
        for provider in ("abuseipdb", "virustotal"):
            if await quota_exhausted(provider):
                summary["stopped"] = f"{provider} quota reached"
                break
        if summary["stopped"]:
            break
        if i:
            await asyncio.sleep(PAUSE_BETWEEN_IPS_SECONDS)
        try:
            r = await recheck_ip(ip)
        except Exception as e:
            logger.warning(f"blocklist recheck: {ip} failed: {e}")
            continue
        if r["result"] == "gone":
            continue
        summary["checked"] += 1
        summary[r["result"]] += 1
        if r["result"] == "released":
            summary["released_ips"].append(ip)

    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    if summary["checked"] or summary["stopped"]:
        logger.info(f"blocklist recheck: {summary['checked']} checked, {summary['released']} released, "
                    f"{summary['malicious']} still malicious, {summary['inconclusive']} inconclusive"
                    + (f" — stopped: {summary['stopped']}" if summary["stopped"] else ""))
    try:
        from app.geoip_service import get_redis
        redis = await get_redis()
        if redis:
            await redis.set(LAST_RUN_KEY, json.dumps(summary))
    except Exception as e:
        logger.warning(f"blocklist recheck: storing run summary failed: {e}")
    return summary


async def last_run() -> dict[str, Any] | None:
    try:
        from app.geoip_service import get_redis
        redis = await get_redis()
        raw = await redis.get(LAST_RUN_KEY) if redis else None
        return json.loads(raw) if raw else None
    except Exception:
        return None
