"""CVE severity enrichment via the free Shodan CVE DB (cvedb.shodan.io).

Shodan's host lookup returns CVE *ids* but no severity, so a host with 150
low-impact CVEs (e.g. a patched Microsoft service) looks the same as one with a
single Critical, actively-exploited flaw. This module resolves each CVE to its
CVSS score, severity band, CISA-KEV flag (actively exploited in the wild) and
EPSS (exploit-probability), so block decisions can key on **High/Critical**
CVEs instead of a raw count.

The CVE DB is free and unauthenticated. Scores are static per CVE, so they are
cached permanently in ``cve_scores``; only unseen CVEs hit the network, capped
per call so a host with hundreds of CVEs can't stall the analysis.
"""
import asyncio
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from app.database import async_session
from app.models import CveScore

logger = logging.getLogger(__name__)

_CVEDB = "https://cvedb.shodan.io/cve/{cve}"
_MAX_FETCH_PER_CALL = 60          # network lookups for unseen CVEs per enrich call
_CONCURRENCY = 8


def severity_band(cvss: float | None) -> str:
    """CVSS 3.1 qualitative band."""
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "none"


def _row_to_dict(r: CveScore) -> dict:
    return {"cve": r.cve_id, "cvss": r.cvss, "cvss_v3": r.cvss_v3,
            "severity": r.severity, "kev": bool(r.kev), "epss": r.epss}


async def _fetch_one(client: httpx.AsyncClient, cve: str) -> dict | None:
    try:
        r = await client.get(_CVEDB.format(cve=cve))
        if r.status_code != 200:
            return None
        d = r.json() or {}
    except Exception as e:
        logger.debug(f"cve lookup failed for {cve}: {e}")
        return None
    v3 = d.get("cvss_v3")
    v2 = d.get("cvss_v2")
    base = d.get("cvss")
    # Prefer CVSS v3 for the band; fall back to the generic/most-recent score.
    score = v3 if isinstance(v3, (int, float)) else (base if isinstance(base, (int, float)) else v2)
    return {
        "cve": cve,
        "cvss": base if isinstance(base, (int, float)) else score,
        "cvss_v3": v3 if isinstance(v3, (int, float)) else None,
        "severity": severity_band(score),
        "kev": bool(d.get("kev")),
        "epss": d.get("ranking_epss") if isinstance(d.get("ranking_epss"), (int, float)) else None,
        "summary": (d.get("summary") or "")[:500] or None,
    }


async def enrich_cves(cve_ids: list[str]) -> dict:
    """Resolve a list of CVE ids to a severity summary.

    Returns::

        {
          "total": int, "scored": int, "truncated": bool,
          "counts": {"critical":n,"high":n,"medium":n,"low":n,"none":n,"unknown":n},
          "high_critical": int,          # critical + high
          "kev": int,                    # actively-exploited (CISA KEV)
          "max_cvss": float|None,
          "has_high_critical": bool,     # the block-decision signal
          "top": [ {cve,cvss,severity,kev,epss}, ... up to 12, worst first ]
        }
    """
    # Normalise + dedupe (CVE ids only).
    ids = []
    seen = set()
    for c in cve_ids or []:
        c = str(c).strip().upper()
        if c.startswith("CVE-") and c not in seen:
            seen.add(c)
            ids.append(c)
    empty = {"total": 0, "scored": 0, "truncated": False,
             "counts": {}, "high_critical": 0, "kev": 0,
             "max_cvss": None, "has_high_critical": False, "top": []}
    if not ids:
        return empty

    # 1) cache
    scores: dict[str, dict] = {}
    async with async_session() as db:
        rows = (await db.execute(select(CveScore).where(CveScore.cve_id.in_(ids)))).scalars().all()
        for r in rows:
            scores[r.cve_id] = _row_to_dict(r)

    # 2) fetch the unseen ones (capped), then persist
    missing = [c for c in ids if c not in scores]
    truncated = len(missing) > _MAX_FETCH_PER_CALL
    to_fetch = missing[:_MAX_FETCH_PER_CALL]
    if to_fetch:
        sem = asyncio.Semaphore(_CONCURRENCY)
        async with httpx.AsyncClient(timeout=12.0) as client:
            async def _guarded(cve):
                async with sem:
                    return await _fetch_one(client, cve)
            fetched = await asyncio.gather(*[_guarded(c) for c in to_fetch])
        now = datetime.now(timezone.utc)
        async with async_session() as db:
            for f in fetched:
                if not f:
                    continue
                scores[f["cve"]] = {k: f[k] for k in ("cve", "cvss", "cvss_v3", "severity", "kev", "epss")}
                db.add(CveScore(
                    cve_id=f["cve"], cvss=f["cvss"], cvss_v3=f["cvss_v3"],
                    severity=f["severity"], kev=f["kev"], epss=f["epss"],
                    summary=f["summary"], fetched_at=now,
                ))
            await db.commit()

    # 3) summarise
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "none", "unknown")}
    kev = 0
    max_cvss = None
    scored_list = []
    for c in ids:
        s = scores.get(c)
        if not s:
            counts["unknown"] += 1
            continue
        band = s.get("severity") or "unknown"
        counts[band] = counts.get(band, 0) + 1
        if s.get("kev"):
            kev += 1
        cv = s.get("cvss_v3") or s.get("cvss")
        if isinstance(cv, (int, float)):
            max_cvss = cv if max_cvss is None else max(max_cvss, cv)
        scored_list.append(s)

    _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": -1}
    scored_list.sort(key=lambda s: (s.get("kev", False),
                                    _rank.get(s.get("severity"), -1),
                                    s.get("cvss_v3") or s.get("cvss") or 0), reverse=True)
    high_critical = counts["critical"] + counts["high"]
    return {
        "total": len(ids),
        "scored": sum(1 for c in ids if c in scores),
        "truncated": truncated,
        "counts": counts,
        "high_critical": high_critical,
        "kev": kev,
        "max_cvss": max_cvss,
        "has_high_critical": high_critical > 0,
        "top": scored_list[:12],
    }
