"""Per-service (peer-group) NetFlow anomaly detection.

The two existing engines answer different questions:

* ``anomaly.py`` + ``/api/firewall/anomalies`` — Isolation Forest over **whole
  IPs** in a freely chosen 3-D space. Finds hosts that stand out *from the
  network as a whole*.
* ``connection_anomaly.py`` — rule-based scoring of **one (src→dst) pair** for
  two named threats (C2 beaconing, exfil upload).

Neither can say *"this connection is odd **for this service**"*. A host pushing
400 MB over HTTPS disappears among all the other HTTPS traffic; the same 400 MB
over SSH or SMTP is glaring. Averaged over the whole network, both look alike.

This module closes that gap with **peer-group scoring**: connections are grouped
by the service behind them (see :mod:`services`), and an Isolation Forest runs
*inside each group separately*. Every connection is therefore scored against its
own peers — HTTPS against HTTPS, DNS against DNS — so "normal" is defined per
service instead of network-wide.

Why the grouping key is not the raw port
----------------------------------------
Raw ``dst_port`` produces useless groups: on a real network one port (443) holds
thousands of connections while hundreds of ephemeral ports hold exactly one, and
a population of one supports no statement about being an outlier.
:func:`services.resolve` therefore collapses dynamic ports into one
``ephemeral`` group and keeps unknown registered ports as ``port-N``.

Groups below ``min_group`` members are **not scored** — with 5 peers, "outlier"
is noise. They are reported in ``skipped_groups`` rather than silently dropped,
so the UI can show what was not covered.

Attribution is two-sided
------------------------
``anomaly.attribute_drivers`` assumes every feature is "higher = more
anomalous". That does not hold here: for beaconing, *small* and *uniform* bytes
per flow is the signal, and a *low* download share is what makes an upload
suspicious. :func:`_attribute` therefore ranks each feature by how far it sits
from the group's median in **either** direction and reports the direction
("hoch" / "niedrig") plus the factor against the median — which is also what
makes a finding explainable to an analyst without re-deriving anything.
"""

from __future__ import annotations

import asyncio
import bisect
import math
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import services
from app.anomaly import isolation_forest_scores
# Same internal/external definition as the per-connection engine — one source of
# truth for what counts as "our network".
from app.connection_anomaly import _priv

# --- Feature space ------------------------------------------------------------
# Each entry: key -> (label key for i18n, how to read a high value).
# The forest consumes the f_* values; the UI localizes DIM_LABELS[key].
FEATURES: list[str] = [
    "out_bytes",      # uploaded volume (log)
    "in_bytes",       # downloaded volume (log)
    "upload_ratio",   # out / (out + in)
    "bytes_per_flow",  # payload size per flow (log) — small+uniform = beacon-ish
    "flows",          # number of flows (log)
    "buckets",        # distinct active minutes (log) — session persistence
    "night_ratio",    # share of off-hours activity
    "dst_spread",     # internal hosts that also talk to this destination (log, inverted)
]

DEFAULTS: dict[str, float] = {
    "min_group": 15,        # a peer group needs this many members to be scorable
    "threshold": 0.62,      # Isolation-Forest score at/above which we flag
    "min_extremity": 0.90,  # ... and at least one feature this far out (percentile)
    "n_trees": 120,
    "sample_size": 256,
}

_BASELINE_TTL = 1800
# Keyed by window bounds, so a new entry appears every hour and the old one is
# never looked at again. Each holds the full 30-day (host, service) map — left
# to accumulate, the worker's memory climbed by one such map per hour with
# nothing ever released. Only the newest few can still be hit; the rest are
# dropped on write.
_BASELINE_CACHE_MAX = 4
_baseline_cache: dict[str, tuple[float, dict]] = {}


def _night(col: str) -> str:
    return f"(EXTRACT(hour FROM {col}) < 6 OR EXTRACT(hour FROM {col}) >= 22)"


async def _load_baseline(db: AsyncSession, baseline_start: datetime,
                         recent_start: datetime) -> dict:
    """Which (host, service) combinations are established, per the baseline window.

    Returns ``{"host_service": {(src, service_key): days}, "service_hosts":
    {service_key: n_hosts}}``. Used for the *novelty* signals: a host using a
    service it never used before is interesting even when its volume is
    unremarkable — the peer-group forest alone would not catch that."""
    key = f"svc-{baseline_start:%Y%m%d%H}-{recent_start:%Y%m%d%H}"
    hit = _baseline_cache.get(key)
    if hit and (time.monotonic() - hit[0]) < _BASELINE_TTL:
        return hit[1]

    rows = (await db.execute(text(f"""
        SELECT src_ip AS src, dst_port AS port, protocol AS proto,
               COUNT(DISTINCT date_trunc('day', bucket_start)) AS days
        FROM netflow_buckets
        WHERE bucket_start >= :bstart AND bucket_start < :rstart
          AND {_priv('src_ip')} AND NOT {_priv('dst_ip')}
        GROUP BY src_ip, dst_port, protocol
    """), {"bstart": baseline_start, "rstart": recent_start})).all()

    host_service: dict[tuple[str, str], int] = {}
    service_hosts: dict[str, set[str]] = {}
    for src, port, proto, days in rows:
        skey = services.resolve(port, proto)["key"]
        k = (src, skey)
        host_service[k] = max(host_service.get(k, 0), int(days or 0))
        service_hosts.setdefault(skey, set()).add(src)

    out = {"host_service": host_service,
           "service_hosts": {k: len(v) for k, v in service_hosts.items()}}
    _baseline_cache[key] = (time.monotonic(), out)
    for stale in list(_baseline_cache)[:-_BASELINE_CACHE_MAX]:
        _baseline_cache.pop(stale, None)
    return out


async def _recent(db: AsyncSession, recent_start: datetime, min_flows: int) -> list[dict]:
    """Aggregate recent outbound traffic per (src, dst, port, protocol).

    Returns one row per connection *and service*, already carrying the reverse
    (download) volume so the upload ratio is available per service rather than
    only per host pair."""
    out_rows = (await db.execute(text(f"""
        SELECT n.src_ip AS src, n.dst_ip AS dst,
               n.dst_port AS port, n.protocol AS proto,
               SUM(n.bytes)   AS out_bytes,
               SUM(n.flows)   AS out_flows,
               SUM(n.packets) AS out_packets,
               COUNT(DISTINCT n.bucket_start) AS buckets,
               MIN(n.bucket_start) AS first_seen,
               MAX(n.bucket_start) AS last_seen,
               SUM(CASE WHEN {_night('n.bucket_start')} THEN n.flows ELSE 0 END) AS night_flows,
               MAX(g.country) AS country
        FROM netflow_buckets n
        LEFT JOIN geoip_cache g ON g.ip = n.dst_ip
        WHERE n.bucket_start >= :rstart
          AND {_priv('n.src_ip')} AND NOT {_priv('n.dst_ip')}
        GROUP BY n.src_ip, n.dst_ip, n.dst_port, n.protocol
        HAVING SUM(n.flows) >= :min_flows
    """), {"rstart": recent_start, "min_flows": min_flows})).all()

    # Reverse flows carry the *client's* ephemeral port, so they cannot be keyed
    # by service — the download volume is attributed per (internal, external) pair.
    in_rows = (await db.execute(text(f"""
        SELECT dst_ip AS internal, src_ip AS external, SUM(bytes) AS in_bytes
        FROM netflow_buckets
        WHERE bucket_start >= :rstart
          AND NOT {_priv('src_ip')} AND {_priv('dst_ip')}
        GROUP BY dst_ip, src_ip
    """), {"rstart": recent_start})).all()
    in_bytes = {(r[0], r[1]): int(r[2] or 0) for r in in_rows}

    # Roll the per-port rows up to the unit of analysis: (src, dst, service).
    # Several ports can map to one service — every dynamic port collapses into
    # ``ephemeral`` — and a P2P peer spread over 40 ports must not enter the
    # forest 40 times. Volumes/flows add up; ``buckets`` (distinct active
    # minutes) is taken as the max across ports, a lower bound, since distinct
    # timestamps cannot be summed. ``in_bytes`` is per (src, dst) and is
    # attached once per group — summing it per port would inflate the download
    # side and skew every upload ratio.
    merged: dict[tuple[str, str, str], dict] = {}
    for (src, dst, port, proto, out_b, out_f, out_p, buckets,
         first_seen, last_seen, night_flows, country) in out_rows:
        svc = services.resolve(port, proto)
        key = (src, dst, svc["key"])
        it = merged.get(key)
        if it is None:
            it = merged[key] = {
                "src": src, "dst": dst,
                "service": svc["key"], "service_label": svc["label"],
                "category": svc["category"], "well_known": svc["well_known"],
                "ports": set(), "protocols": set(),
                "out_bytes": 0, "in_bytes": in_bytes.get((src, dst), 0),
                "flows": 0, "packets": 0, "buckets": 0, "night_flows": 0,
                "country": country,
                "first_seen": first_seen, "last_seen": last_seen,
            }
        if port is not None:
            it["ports"].add(int(port))
        pn = services.proto_name(proto)
        if pn:
            it["protocols"].add(pn)
        it["out_bytes"] += int(out_b or 0)
        it["flows"] += int(out_f or 0)
        it["packets"] += int(out_p or 0)
        it["buckets"] = max(it["buckets"], int(buckets or 0))
        it["night_flows"] += int(night_flows or 0)
        it["country"] = it["country"] or country
        if first_seen and (not it["first_seen"] or first_seen < it["first_seen"]):
            it["first_seen"] = first_seen
        if last_seen and (not it["last_seen"] or last_seen > it["last_seen"]):
            it["last_seen"] = last_seen

    items: list[dict] = []
    for it in merged.values():
        flows = it["flows"] or 1
        ports = sorted(it["ports"])
        it["flows"] = flows
        it["port"] = ports[0] if len(ports) == 1 else None
        it["ports"] = ports[:8]
        it["port_count"] = len(ports)
        it["protocol"] = "/".join(sorted(it["protocols"])) or None
        it.pop("protocols")
        it["night_ratio"] = round(it.pop("night_flows") / flows, 3)
        items.append(it)
    return items


def _featurize(items: list[dict], dst_spread: dict[str, int]) -> None:
    """Attach the f_* forest inputs, plus the raw value of every feature.

    Log-scaling for the heavy-tailed volume and count metrics, plain ratios
    otherwise. Nothing is inverted: an Isolation Forest isolates extremes in
    *both* directions, so flipping a feature's sign would gain the model nothing
    while breaking the raw-value attribution (``value`` vs ``median``) that
    :func:`_attribute` reports. Every ``FEATURES`` entry therefore exists twice:
    ``it[name]`` as the human number, ``it["f_"+name]`` as the model input."""
    for it in items:
        out_b, in_b = it["out_bytes"], it["in_bytes"]
        total = out_b + in_b
        it["upload_ratio"] = round(out_b / total, 3) if total else 1.0
        it["bytes_per_flow"] = round(out_b / it["flows"], 2)
        it["dst_hosts"] = dst_spread.get(it["dst"], 1)
        it["dst_spread"] = it["dst_hosts"]

        it["f_out_bytes"] = math.log1p(out_b)
        it["f_in_bytes"] = math.log1p(in_b)
        it["f_upload_ratio"] = it["upload_ratio"]
        it["f_bytes_per_flow"] = math.log1p(it["bytes_per_flow"])
        it["f_flows"] = math.log1p(it["flows"])
        it["f_buckets"] = math.log1p(it["buckets"])
        it["f_night_ratio"] = it["night_ratio"]
        it["f_dst_spread"] = math.log1p(it["dst_spread"])


def _median(sorted_vals: list[float]) -> float:
    n = len(sorted_vals)
    if not n:
        return 0.0
    mid = n // 2
    if n % 2:
        return sorted_vals[mid]
    return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0


def _attribute(group: list[dict]) -> None:
    """Two-sided attribution within one peer group.

    For every feature, an item's percentile rank inside the group is turned into
    an ``extremity`` in [0, 1] measuring distance from the median in *either*
    direction (0 = median, 1 = at the edge). The dominant features become
    ``drivers`` with a direction and the factor against the group median, e.g.
    "out_bytes hoch, 143× Median" — a statement an analyst can check."""
    n = len(group)
    cols = {f: sorted(float(it.get(f"f_{f}") or 0.0) for it in group) for f in FEATURES}
    raw_cols = {f: sorted(float(it.get(f) or 0.0) for it in group) for f in FEATURES}
    medians = {f: _median(raw_cols[f]) for f in FEATURES}

    for it in group:
        ranks = []
        for f in FEATURES:
            v = float(it.get(f"f_{f}") or 0.0)
            below = bisect.bisect_left(cols[f], v)
            above = n - bisect.bisect_right(cols[f], v)
            pct = below / n                      # fraction strictly below
            # Distance from the median, normalised: 1.0 = nothing on one side.
            extremity = max(below, above) / n if n else 0.0
            direction = "high" if below >= above else "low"
            ranks.append((f, extremity, direction, pct))
        ranks.sort(key=lambda x: x[1], reverse=True)

        drivers = []
        for f, ext, direction, pct in ranks[:3]:
            med = medians[f]
            val = float(it.get(f) or 0.0)
            factor = (val / med) if med > 0 else None
            if factor is not None:
                # Round relative to magnitude: a value far BELOW the median has a
                # factor < 1, and rounding that to one decimal collapses it to
                # 0.0 — which reads as "infinitely smaller" in the UI instead of
                # "a fifth of the median".
                factor = round(factor, 1 if factor >= 1 else 4)
            drivers.append({
                "dim": f, "dir": direction,
                "extremity": round(ext, 3), "pct": round(pct, 3),
                "value": round(val, 3), "median": round(med, 3),
                "factor": factor,
            })
        it["drivers"] = drivers
        it["extremity"] = round(ranks[0][1], 3) if ranks else 0.0


def _signals(it: dict, base: dict, group_size: int) -> list[dict]:
    """Interpretable codes on top of the forest score. These carry the *reasons*
    a connection is interesting beyond "the model isolated it": first use of a
    service by this host, a service rare on this network, an off-hours push."""
    out: list[dict] = []
    hs = base["host_service"]
    days = hs.get((it["src"], it["service"]), 0)
    if days == 0:
        out.append({"code": "new_service_for_host", "service": it["service"]})
    elif days <= 2:
        out.append({"code": "uncommon_service_for_host", "days": days})

    net_hosts = base["service_hosts"].get(it["service"], 0)
    if net_hosts <= 1:
        out.append({"code": "rare_service_on_network", "hosts": net_hosts})

    if not it["well_known"]:
        # ``port`` is None once several ports rolled up into one service (the
        # ephemeral bucket), so pass the count too — "(Port null)" is no label.
        out.append({"code": "unidentified_service", "port": it["port"],
                    "port_count": it["port_count"]})
    if it["dst_hosts"] <= 1:
        out.append({"code": "rare_dst"})
    if it["night_ratio"] >= 0.5:
        out.append({"code": "offhours", "ratio": it["night_ratio"]})
    if it["upload_ratio"] >= 0.9 and it["out_bytes"] >= 1024 * 1024:
        out.append({"code": "upload_skew", "ratio": it["upload_ratio"],
                    "bytes": it["out_bytes"]})
    out.append({"code": "peer_group", "service": it["service"], "size": group_size})
    return out


def _score_groups(items: list[dict], base: dict, cfg: dict,
                  min_group: int) -> tuple[list[dict], list[dict], list[dict]]:
    """Run one Isolation Forest per service group. Pure CPU, no I/O — callers
    hand this to a worker thread. Returns ``(found, scored_groups,
    skipped_groups)``; groups below ``min_group`` are skipped and reported."""
    groups: dict[str, list[dict]] = {}
    for it in items:
        groups.setdefault(it["service"], []).append(it)

    feature_keys = [f"f_{f}" for f in FEATURES]
    found: list[dict] = []
    scored_groups: list[dict] = []
    skipped_groups: list[dict] = []

    for skey, group in groups.items():
        if len(group) < min_group:
            skipped_groups.append({
                "service": skey, "size": len(group),
                "category": services.category_of(skey),
                "reason": "too_small",
            })
            continue

        vectors = [[float(it.get(k) or 0.0) for k in feature_keys] for it in group]
        scores = isolation_forest_scores(
            vectors, n_trees=int(cfg["n_trees"]),
            sample_size=int(cfg["sample_size"]), seed=42)
        for it, sc in zip(group, scores):
            it["score"] = round(sc, 4)
        _attribute(group)

        hits = 0
        for it in group:
            flagged = (it["score"] >= cfg["threshold"]
                       and it["extremity"] >= cfg["min_extremity"])
            it["is_anomaly"] = flagged
            if flagged:
                hits += 1
                it["signals"] = _signals(it, base, len(group))
                found.append(it)
        scored_groups.append({
            "service": skey, "size": len(group), "anomalies": hits,
            "category": services.category_of(skey),
            "well_known": group[0]["well_known"],
        })
    return found, scored_groups, skipped_groups


async def analyze(db: AsyncSession, *, hours: int = 24, min_flows: int = 5,
                  baseline_days: int = 30, limit: int = 200,
                  service: str | None = None,
                  overrides: dict | None = None) -> dict:
    """Score every recent outbound connection against its own service peer group.

    Args:
        hours: recent window to score.
        min_flows: ignore connections below this many flows (noise floor).
        baseline_days: history used for the novelty signals.
        limit: max anomalies returned (ranked by score).
        service: restrict the analysis to a single service key (e.g. ``https``).
        overrides: tuning overrides, see :data:`DEFAULTS`.

    Returns the ranked anomalies plus a per-service breakdown, including the
    groups that were **too small to score** so nothing disappears silently."""
    cfg = dict(DEFAULTS)
    if overrides:
        cfg.update({k: v for k, v in overrides.items() if v is not None})
    min_group = int(cfg["min_group"])

    now = datetime.now(timezone.utc)
    recent_start = now - timedelta(hours=hours)
    baseline_start = now - timedelta(days=baseline_days)

    base = await _load_baseline(db, baseline_start, recent_start)
    items = await _recent(db, recent_start, min_flows)
    if service:
        items = [it for it in items if it["service"] == service]

    # How many internal hosts talk to each destination — the rarity input.
    spread: dict[str, set[str]] = {}
    for it in items:
        spread.setdefault(it["dst"], set()).add(it["src"])
    dst_spread = {k: len(v) for k, v in spread.items()}
    _featurize(items, dst_spread)

    # The forests are pure-Python and CPU-bound (one per service group), so the
    # whole scoring pass goes off the event loop — same reason the IP-level
    # endpoint wraps its scoring in asyncio.to_thread.
    found, scored_groups, skipped_groups = await asyncio.to_thread(
        _score_groups, items, base, cfg, min_group)

    found.sort(key=lambda a: (a["score"], a["extremity"]), reverse=True)
    scored_groups.sort(key=lambda g: g["size"], reverse=True)
    skipped_groups.sort(key=lambda g: g["size"], reverse=True)

    def _public(it: dict) -> dict:
        """Drop the f_* helpers; keep everything an analyst or the agent needs."""
        return {k: v for k, v in it.items() if not k.startswith("f_")} | {
            "first_seen": it["first_seen"].isoformat() if it["first_seen"] else None,
            "last_seen": it["last_seen"].isoformat() if it["last_seen"] else None,
        }

    return {
        "as_of": now.isoformat(),
        "window_hours": hours,
        "baseline_days": baseline_days,
        "source": "netflow",
        "mode": "per_service_peer_group",
        "features": FEATURES,
        "analyzed": len(items),
        "scored": sum(g["size"] for g in scored_groups),
        "anomaly_count": len(found),
        "params": {"min_flows": min_flows, "min_group": min_group,
                   "threshold": cfg["threshold"], "min_extremity": cfg["min_extremity"]},
        "services": scored_groups,
        "skipped_services": skipped_groups,
        "skipped_connections": sum(g["size"] for g in skipped_groups),
        "anomalies": [_public(it) for it in found[:limit]],
    }
