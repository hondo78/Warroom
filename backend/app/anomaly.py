"""Isolation Forest anomaly detection for firewall-log source IPs.

A dependency-free implementation (no numpy/sklearn — the codebase is deliberately
lean) of the Isolation Forest algorithm (Liu, Ting & Zhou, 2008). Each source IP
is reduced to a behavioural feature vector over a time window; the forest scores
how easily each point is isolated — outliers (scanners, brute-forcers, beaconing
hosts) need fewer random splits and score closer to 1.0.

The scoring is CPU-bound pure Python, so callers should run :func:`analyze` via
``asyncio.to_thread`` to keep the event loop responsive.
"""

from __future__ import annotations

import bisect
import math
import random
from typing import Any

# Euler-Mascheroni constant, for the average-path-length normalisation c(n).
_EULER = 0.5772156649


def _c(n: int) -> float:
    """Expected path length of an unsuccessful BST search over n points —
    the normalisation factor that makes scores comparable across sample sizes."""
    if n <= 1:
        return 0.0
    return 2.0 * (math.log(n - 1) + _EULER) - (2.0 * (n - 1) / n)


class _Node:
    __slots__ = ("feature", "split", "left", "right", "size")

    def __init__(self, feature=None, split=0.0, left=None, right=None, size=0):
        self.feature = feature      # None => external (leaf) node
        self.split = split
        self.left = left
        self.right = right
        self.size = size


def _build_tree(data: list[list[float]], depth: int, max_depth: int,
                rng: random.Random, n_features: int) -> _Node:
    n = len(data)
    if depth >= max_depth or n <= 1:
        return _Node(size=n)
    f = rng.randrange(n_features)
    col = [row[f] for row in data]
    lo, hi = min(col), max(col)
    if lo == hi:
        return _Node(size=n)
    split = rng.uniform(lo, hi)
    left = [r for r in data if r[f] < split]
    right = [r for r in data if r[f] >= split]
    return _Node(
        feature=f, split=split, size=n,
        left=_build_tree(left, depth + 1, max_depth, rng, n_features),
        right=_build_tree(right, depth + 1, max_depth, rng, n_features),
    )


def _path_length(row: list[float], node: _Node) -> float:
    depth = 0
    while node.feature is not None:
        node = node.left if row[node.feature] < node.split else node.right
        depth += 1
    return depth + _c(node.size)


def isolation_forest_scores(data: list[list[float]], *, n_trees: int = 100,
                            sample_size: int = 256, seed: int = 42) -> list[float]:
    """Anomaly score in (0, 1) for each row — higher = more anomalous. A fixed
    seed makes the result deterministic across refreshes."""
    n = len(data)
    if n == 0:
        return []
    n_features = len(data[0])
    rng = random.Random(seed)
    psi = min(sample_size, n)
    max_depth = max(1, math.ceil(math.log2(psi))) if psi > 1 else 1

    trees = []
    for _ in range(n_trees):
        sample = rng.sample(data, psi) if n > psi else list(data)
        trees.append(_build_tree(sample, 0, max_depth, rng, n_features))

    cpsi = _c(psi)
    scores = []
    for row in data:
        avg = sum(_path_length(row, t) for t in trees) / len(trees)
        scores.append(2.0 ** (-avg / cpsi) if cpsi > 0 else 0.0)
    return scores


# --- generic scoring -----------------------------------------------------------

def score_items(items: list[dict[str, Any]], feature_keys: list[str], *,
                threshold: float = 0.62, n_trees: int = 120,
                sample_size: int = 256) -> dict[str, Any]:
    """Score pre-built items by Isolation Forest. Each item must carry its numeric
    feature values under ``feature_keys``; the item dict is returned enriched with
    ``score`` / ``is_anomaly``, ranked most-anomalous first. Feature engineering
    (which dimensions, how to encode categoricals like country) lives in the
    caller, so the same forest serves firewall-log, NetFlow, or any other source."""
    if not items:
        return {"analyzed": 0, "anomaly_count": 0, "threshold": threshold,
                "feature_keys": feature_keys, "items": []}

    vectors = [[float(it.get(k) or 0.0) for k in feature_keys] for it in items]
    scores = isolation_forest_scores(vectors, n_trees=n_trees, sample_size=sample_size)

    out = []
    for it, score in zip(items, scores):
        rec = dict(it)
        rec["score"] = round(score, 4)
        rec["is_anomaly"] = score >= threshold
        out.append(rec)
    out.sort(key=lambda x: x["score"], reverse=True)
    return {
        "analyzed": len(out),
        "anomaly_count": sum(1 for x in out if x["is_anomaly"]),
        "threshold": threshold,
        "feature_keys": feature_keys,
        "items": out,
    }


def attribute_drivers(result: dict[str, Any], feature_keys: list[str],
                      dim_labels: dict[str, str], *, top_cut: float = 0.85) -> dict[str, Any]:
    """Explain WHICH dimension drives each item by its percentile rank within the
    population — the fraction of items it sits strictly above on that feature.
    Adds ``drivers`` (list of {dim, pct}, highest first) to every item. All four
    features are "higher = more anomalous", so a high percentile = a real driver;
    each item keeps at least its single most-extreme dimension.

    Operates in place and returns the same result dict."""
    items = result.get("items") or []
    n = len(items)
    if n == 0:
        return result
    sorted_vals = {k: sorted(float(it.get(k) or 0.0) for it in items) for k in feature_keys}
    for it in items:
        ranks = []
        for k in feature_keys:
            v = float(it.get(k) or 0.0)
            pct = bisect.bisect_left(sorted_vals[k], v) / n   # fraction strictly below
            ranks.append((k, pct))
        ranks.sort(key=lambda x: x[1], reverse=True)
        drivers = [{"dim": dim_labels.get(k, k), "pct": round(p, 2)} for k, p in ranks if p >= top_cut]
        if not drivers:
            k, p = ranks[0]
            drivers = [{"dim": dim_labels.get(k, k), "pct": round(p, 2)}]
        it["drivers"] = drivers
    return result
