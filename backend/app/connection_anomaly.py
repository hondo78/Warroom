"""Per-connection (src→dst pair) NetFlow anomaly detection.

Where ``anomaly.py`` scores whole IPs with an Isolation Forest, this module
looks at **individual connections between one internal host and one external
IP**. The unit of analysis is the ordered pair ``(internal_src, external_dst)``
— not an aggregate over an IP's whole traffic.

The design goal is to catch two specific threats:

* **C2 beaconing** — malware phoning home: many *small*, *regularly spaced*
  flows to a *rare/new* external destination, sustained over a long span.
* **Atypical uploads (exfiltration)** — a host suddenly pushing a *large*,
  *upload-skewed* volume to a destination it does not normally talk to.

Normal vs. anomalous is decided from a **baseline** of the same NetFlow data:

Parameters that mark a connection as NORMAL (recurring / expected)
  * ``baseline_days``  – the exact (src→dst) pair recurred on many distinct
    days of history → an established, regular connection.
  * ``dst_popularity`` – the destination is contacted by *many* internal hosts
    → a shared service (updates, CDN, M365, DNS), not a per-host secret channel.

Parameters that mark a connection as ANOMALOUS (new / atypical)
  * ``is_new``         – the pair is absent from the baseline (or seen on <2
    days with negligible volume) → it "suddenly appeared".
  * ``dst_rarity``     – the destination is contacted by only this one host.
  * exfil signature    – large ``out_bytes`` with a high ``upload_ratio``
    (out ≫ in), especially to a new/rare destination or far above the host's
    own baseline upload.
  * beacon signature   – many flows, small & consistent ``bytes_per_flow``,
    low variance of inter-arrival gaps (``regularity``), spread over a long
    ``span`` — to a rare/new destination.
  * ``night_ratio``    – share of activity in off-hours (a mild booster).

Everything is interpretable: each flagged connection carries the concrete
signal codes + values that triggered it, so the UI and the agent can explain
*why* without re-deriving anything.
"""

from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# --- Internal/external classification (matches main.py PRIVATE_CIDRS) ---------

_PRIVATE_CIDRS = (
    "'10.0.0.0/8'", "'172.16.0.0/12'", "'192.168.0.0/16'",
    "'127.0.0.0/8'", "'169.254.0.0/16'", "'0.0.0.0/8'", "'100.64.0.0/10'",
)


def _priv(col: str) -> str:
    """SQL predicate: is *col* a private/internal address (regex-guarded cast)."""
    checks = " OR ".join(f"{col}::inet <<= inet {c}" for c in _PRIVATE_CIDRS)
    return f"({col} ~ '^[0-9.]+$' AND ({checks}))"


# --- Tunable thresholds -------------------------------------------------------
# Overridable per call (wired to managed settings by the endpoint / agent).

DEFAULTS: dict[str, float] = {
    # Baseline / novelty
    "baseline_days_known": 3,     # pair seen on >= this many days = established
    "dst_shared_hosts": 3,        # dst contacted by >= this many internal hosts = shared service
    # Exfil (atypical upload)
    "exfil_min_bytes": 8 * 1024 * 1024,   # >= 8 MB upload to even consider exfil
    "exfil_ref_bytes": 200 * 1024 * 1024,  # volume that scores ~1.0
    "exfil_upload_ratio": 0.75,   # out/(out+in) must exceed this
    "exfil_dev_factor": 5.0,      # or out_bytes >= this * host's baseline typical upload
    # C2 beaconing
    "beacon_min_buckets": 8,      # active in >= this many distinct minutes
    "beacon_min_intervals": 6,    # >= this many inter-arrival gaps to judge regularity
    "beacon_small_bytes": 4096,   # avg bytes/flow at/below this = "small" (score 1.0)
    "beacon_span_min": 45,        # minutes of span that scores ~1.0
    "beacon_min_regularity": 0.6,  # 1-CoV of gaps must exceed this
    # P2P / noise suppression: a host that fans out to many *rare* external
    # destinations is BitTorrent/P2P or a scanner — the opposite of stealthy C2
    # (which targets 1–2 hosts). Above this many rare peers, C2/new signals for
    # that source are damped out so P2P seeding doesn't drown real beacons.
    "p2p_fanout": 15,
    # Output gate
    "min_score": 0.5,             # keep connections scoring >= this ...
    "new_floor_bytes": 1024 * 1024,  # ... or new+rare pairs moving >= this many bytes
}

# Ports whose periodicity is benign by design (NTP, DNS, DHCP, mDNS, SSDP, SNMP,
# STUN, WireGuard keepalive). A regular cadence on these is a service, not C2.
BENIGN_BEACON_PORTS: frozenset[int] = frozenset({
    53, 67, 68, 123, 137, 138, 161, 500, 546, 547,
    1900, 3478, 4500, 5353, 51820,
})

# In-process baseline cache: the baseline aggregation is heavy (~4 s over 30 d),
# but changes slowly. Key by window signature; TTL keeps it fresh enough.
_BASELINE_TTL = 1800  # 30 min
_baseline_cache: dict[str, tuple[float, dict]] = {}


def _night(hour_col: str) -> str:
    return f"(EXTRACT(hour FROM {hour_col}) < 6 OR EXTRACT(hour FROM {hour_col}) >= 22)"


async def _load_baseline(db: AsyncSession, baseline_start: datetime,
                         recent_start: datetime) -> dict:
    """Aggregate known internal→external pairs over the baseline window.

    Returns dicts used to judge novelty/rarity of recent connections:
      * ``pairs``   : (src, dst) -> {days, bytes} for established pairs
      * ``dst_hosts``: dst -> count of distinct internal hosts that contacted it
      * ``src_up``  : src -> typical (median-ish) per-destination upload bytes
    Cached in-process for ``_BASELINE_TTL`` seconds.
    """
    key = f"{baseline_start:%Y%m%d%H}-{recent_start:%Y%m%d%H}"
    hit = _baseline_cache.get(key)
    if hit and (time.monotonic() - hit[0]) < _BASELINE_TTL:
        return hit[1]

    rows = (await db.execute(text(f"""
        SELECT src_ip AS src, dst_ip AS dst,
               COUNT(DISTINCT date_trunc('day', bucket_start)) AS days,
               SUM(bytes) AS bytes
        FROM netflow_buckets
        WHERE bucket_start >= :bstart AND bucket_start < :rstart
          AND {_priv('src_ip')} AND NOT {_priv('dst_ip')}
        GROUP BY src_ip, dst_ip
    """), {"bstart": baseline_start, "rstart": recent_start})).all()

    pairs: dict[tuple[str, str], dict] = {}
    dst_hosts: dict[str, int] = {}
    src_bytes: dict[str, list[int]] = {}
    for src, dst, days, byts in rows:
        byts = int(byts or 0)
        pairs[(src, dst)] = {"days": int(days or 0), "bytes": byts}
        dst_hosts[dst] = dst_hosts.get(dst, 0) + 1
        src_bytes.setdefault(src, []).append(byts)

    # Per-host "typical" upload per destination = median of its baseline pair
    # volumes. Robust reference for exfil deviation (mean is skewed by one big).
    src_up: dict[str, float] = {}
    for src, vals in src_bytes.items():
        vals.sort()
        n = len(vals)
        src_up[src] = float(vals[n // 2]) if n else 0.0

    out = {"pairs": pairs, "dst_hosts": dst_hosts, "src_up": src_up}
    _baseline_cache[key] = (time.monotonic(), out)
    return out


async def _recent_candidates(db: AsyncSession, recent_start: datetime,
                             min_flows: int) -> list[dict]:
    """Aggregate recent outbound connections (internal src → external dst) with
    per-pair features + the minute-timeline needed for beacon cadence, plus the
    reverse (download) bytes for the upload ratio."""
    out_rows = (await db.execute(text(f"""
        SELECT n.src_ip AS src, n.dst_ip AS dst,
               SUM(n.bytes)   AS out_bytes,
               SUM(n.flows)   AS out_flows,
               SUM(n.packets) AS out_packets,
               COUNT(DISTINCT n.dst_port) AS dports,
               mode() WITHIN GROUP (ORDER BY n.dst_port) AS top_port,
               COUNT(DISTINCT n.bucket_start) AS buckets,
               MIN(n.bucket_start) AS first_seen,
               MAX(n.bucket_start) AS last_seen,
               SUM(CASE WHEN {_night('n.bucket_start')} THEN n.flows ELSE 0 END) AS night_flows,
               array_agg(DISTINCT (extract(epoch FROM n.bucket_start))::bigint) AS epochs,
               MAX(g.country) AS country
        FROM netflow_buckets n
        LEFT JOIN geoip_cache g ON g.ip = n.dst_ip
        WHERE n.bucket_start >= :rstart
          AND {_priv('n.src_ip')} AND NOT {_priv('n.dst_ip')}
        GROUP BY n.src_ip, n.dst_ip
        HAVING SUM(n.flows) >= :min_flows
    """), {"rstart": recent_start, "min_flows": min_flows})).all()

    # Reverse direction (external → internal) = bytes downloaded, for the ratio.
    in_rows = (await db.execute(text(f"""
        SELECT n.dst_ip AS internal, n.src_ip AS external, SUM(n.bytes) AS in_bytes
        FROM netflow_buckets n
        WHERE n.bucket_start >= :rstart
          AND NOT {_priv('n.src_ip')} AND {_priv('n.dst_ip')}
        GROUP BY n.dst_ip, n.src_ip
    """), {"rstart": recent_start})).all()
    in_bytes = {(r[0], r[1]): int(r[2] or 0) for r in in_rows}

    cands: list[dict] = []
    for r in out_rows:
        (src, dst, out_b, out_f, out_p, dports, top_port, buckets,
         first_seen, last_seen, night_flows, epochs, country) = r
        out_f = int(out_f or 0) or 1
        cands.append({
            "src": src, "dst": dst,
            "out_bytes": int(out_b or 0), "out_flows": out_f,
            "out_packets": int(out_p or 0),
            "in_bytes": in_bytes.get((src, dst), 0),
            "dports": int(dports or 0), "top_port": int(top_port or 0),
            "buckets": int(buckets or 0),
            "first_seen": first_seen, "last_seen": last_seen,
            "night_ratio": round(int(night_flows or 0) / out_f, 3),
            "epochs": sorted(int(e) for e in (epochs or [])),
            "country": country,
        })
    return cands


def _beacon_metrics(epochs: list[int]) -> dict:
    """Cadence regularity from active-minute timestamps.

    ``regularity`` = 1 − coefficient-of-variation of inter-arrival gaps
    (1.0 = perfectly periodic). ``span_min`` = minutes from first to last.
    ``period_s`` = median gap (the apparent beacon interval)."""
    if len(epochs) < 2:
        return {"regularity": 0.0, "span_min": 0.0, "period_s": 0, "intervals": 0}
    gaps = [epochs[i + 1] - epochs[i] for i in range(len(epochs) - 1)]
    gaps = [g for g in gaps if g > 0]
    if not gaps:
        return {"regularity": 0.0, "span_min": 0.0, "period_s": 0, "intervals": 0}
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cov = (math.sqrt(var) / mean) if mean > 0 else 1.0
    sg = sorted(gaps)
    return {
        "regularity": round(max(0.0, 1.0 - min(cov, 1.0)), 3),
        "span_min": round((epochs[-1] - epochs[0]) / 60.0, 1),
        "period_s": int(sg[len(sg) // 2]),
        "intervals": len(gaps),
    }


def _classify(c: dict, base: dict, cfg: dict, fanout: int) -> dict | None:
    """Score one candidate connection for exfil / C2 / new-rare. Returns an
    enriched dict (or ``None`` if it stays below the output gate).

    ``fanout`` = how many *rare* external destinations this source contacts in
    the window; high fanout = P2P/scanner, which damps the C2/new/novelty
    signals so peer-swarm noise doesn't masquerade as targeted C2."""
    src, dst = c["src"], c["dst"]
    bp = base["pairs"].get((src, dst))
    baseline_days = int(bp["days"]) if bp else 0
    baseline_bytes = int(bp["bytes"]) if bp else 0
    is_new = bp is None or (baseline_days < 2 and baseline_bytes < 65536)
    dst_pop = base["dst_hosts"].get(dst, 0)
    shared = dst_pop >= cfg["dst_shared_hosts"]
    rare = dst_pop <= 1
    benign_port = c["top_port"] in BENIGN_BEACON_PORTS and c["dports"] <= 2

    # Fanout focus: 1.0 for a host targeting ≤3 rare peers, ramping to 0.0 at the
    # P2P threshold. Multiplies the "this is a secret channel" signals.
    p2p_n = max(4, cfg["p2p_fanout"])
    focus = 1.0 if fanout <= 3 else max(0.0, (p2p_n - fanout) / (p2p_n - 3))

    out_b, in_b = c["out_bytes"], c["in_bytes"]
    total = out_b + in_b
    upload_ratio = (out_b / total) if total else 1.0
    bytes_per_flow = out_b / c["out_flows"]

    novelty = 1.0 if is_new else (0.5 if not shared else 0.0)

    # --- Exfil (atypical upload) ---
    exfil = 0.0
    typ_up = base["src_up"].get(src, 0.0)
    dev = out_b / (typ_up + 1.0)
    exfil_trigger = (
        out_b >= cfg["exfil_min_bytes"]
        and upload_ratio >= cfg["exfil_upload_ratio"]
        and (is_new or not shared or dev >= cfg["exfil_dev_factor"])
    )
    if exfil_trigger:
        vol = min(1.0, math.log1p(out_b) / math.log1p(cfg["exfil_ref_bytes"]))
        nov = min(1.0, novelty + (0.4 if not shared else 0.0)) * focus
        exfil = vol * upload_ratio * (0.5 + 0.5 * nov)

    # --- C2 beaconing ---
    bm = _beacon_metrics(c["epochs"])
    c2 = 0.0
    beacon_trigger = (
        c["buckets"] >= cfg["beacon_min_buckets"]
        and bm["intervals"] >= cfg["beacon_min_intervals"]
        and bm["regularity"] >= cfg["beacon_min_regularity"]
        and bytes_per_flow <= cfg["beacon_small_bytes"] * 4
        and not shared and not benign_port and focus > 0
    )
    if beacon_trigger:
        smallness = min(1.0, cfg["beacon_small_bytes"] / max(1.0, bytes_per_flow))
        span_f = min(1.0, bm["span_min"] / cfg["beacon_span_min"])
        c2 = bm["regularity"] * (0.5 + 0.5 * smallness) * (0.4 + 0.6 * span_f)
        c2 *= (0.7 + 0.3 * (1.0 if rare else 0.0)) * focus

    # --- New / rare (fallback, lower severity) ---
    new_rare = 0.0
    if is_new and rare and not shared and not benign_port and focus > 0:
        vol_f = min(1.0, math.log1p(out_b) / math.log1p(cfg["exfil_min_bytes"]))
        new_rare = (0.35 + 0.25 * vol_f + 0.1 * c["night_ratio"]) * focus

    # Pick the dominant interpretation.
    kind, score = max(
        (("exfil", exfil), ("c2", c2), ("new", new_rare)),
        key=lambda kv: kv[1],
    )
    night_boost = 1.0 + 0.15 * c["night_ratio"]
    score = min(1.0, score * night_boost)

    keep = score >= cfg["min_score"] or (
        is_new and rare and out_b >= cfg["new_floor_bytes"]
    )
    if not keep or score <= 0:
        return None

    # Interpretable signal codes (frontend/agent localize these).
    signals: list[dict] = []
    if is_new:
        signals.append({"code": "new_pair"})
    elif not shared:
        signals.append({"code": "uncommon_pair", "days": baseline_days})
    if rare:
        signals.append({"code": "rare_dst"})
    elif shared:
        signals.append({"code": "shared_dst", "hosts": dst_pop})
    if kind == "exfil":
        signals.append({"code": "upload", "bytes": out_b,
                        "ratio": round(upload_ratio, 2), "dev": round(dev, 1)})
    if kind == "c2":
        signals.append({"code": "beacon", "period_s": bm["period_s"],
                        "regularity": bm["regularity"], "span_min": bm["span_min"],
                        "bytes_per_flow": int(bytes_per_flow), "count": c["out_flows"]})
    if c["night_ratio"] >= 0.5:
        signals.append({"code": "offhours", "ratio": c["night_ratio"]})

    return {
        "src": src, "dst": dst,
        "kind": kind, "score": round(score, 3),
        "out_bytes": out_b, "in_bytes": in_b,
        "upload_ratio": round(upload_ratio, 3),
        "flows": c["out_flows"], "packets": c["out_packets"],
        "top_port": c["top_port"], "dst_ports": c["dports"],
        "buckets": c["buckets"],
        "is_new": is_new, "baseline_days": baseline_days,
        "dst_hosts": dst_pop,
        "night_ratio": c["night_ratio"],
        "beacon": bm if kind == "c2" else None,
        "country": c["country"],
        "first_seen": c["first_seen"].isoformat() if c["first_seen"] else None,
        "last_seen": c["last_seen"].isoformat() if c["last_seen"] else None,
        "signals": signals,
    }


async def analyze(db: AsyncSession, *, hours: int = 24, min_flows: int = 5,
                  baseline_days: int = 30, limit: int = 200,
                  overrides: dict | None = None) -> dict:
    """Run the full per-connection anomaly analysis.

    Splits NetFlow into a recent window (``hours``) and a baseline window
    (``baseline_days`` back, up to the recent window), scores every recent
    outbound connection, and returns the ranked anomalies with the interpretable
    signals that flagged each one."""
    cfg = dict(DEFAULTS)
    if overrides:
        cfg.update({k: v for k, v in overrides.items() if v is not None})

    now = datetime.now(timezone.utc)
    recent_start = now - timedelta(hours=hours)
    baseline_start = now - timedelta(days=baseline_days)

    base = await _load_baseline(db, baseline_start, recent_start)
    cands = await _recent_candidates(db, recent_start, min_flows)

    # Per-source rare-destination fanout: how many rare external peers each host
    # talks to this window. High = P2P/scanner → damps its C2/new signals.
    fanout: dict[str, int] = {}
    for c in cands:
        if base["dst_hosts"].get(c["dst"], 0) <= 1:
            fanout[c["src"]] = fanout.get(c["src"], 0) + 1

    found = [x for x in (_classify(c, base, cfg, fanout.get(c["src"], 0))
                         for c in cands) if x]
    found.sort(key=lambda a: a["score"], reverse=True)

    by_kind: dict[str, int] = {}
    for a in found:
        by_kind[a["kind"]] = by_kind.get(a["kind"], 0) + 1

    return {
        "as_of": now.isoformat(),
        "window_hours": hours,
        "baseline_days": baseline_days,
        "source": "netflow",
        "analyzed": len(cands),
        "baseline_pairs": len(base["pairs"]),
        "anomaly_count": len(found),
        "by_kind": by_kind,
        "params": {"min_flows": min_flows, "min_score": cfg["min_score"]},
        "anomalies": found[:limit],
    }
