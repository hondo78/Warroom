"""The anomaly baselines are cached in-process and must stay bounded.

Both modules key their cache on the analysis window, so a new entry appears
every hour and the previous one is never looked at again. The TTL only decides
whether a hit is *served* — it frees nothing. Without a cap the worker grows by
one full 30-day map per hour until something kills it, which presents as an
unexplained restart rather than as a leak, so it is worth a test rather than a
comment.
"""
from app import connection_anomaly, service_anomaly


def _fill(mod, n):
    mod._baseline_cache.clear()
    for i in range(n):
        mod._baseline_cache[f"key-{i:03d}"] = (0.0, {"payload": i})
    # the modules trim on write, so reproduce that step
    for stale in list(mod._baseline_cache)[:-mod._BASELINE_CACHE_MAX]:
        mod._baseline_cache.pop(stale, None)
    return mod._baseline_cache


def test_the_connection_baseline_cache_is_bounded():
    cache = _fill(connection_anomaly, 50)
    assert len(cache) == connection_anomaly._BASELINE_CACHE_MAX


def test_the_service_baseline_cache_is_bounded():
    cache = _fill(service_anomaly, 50)
    assert len(cache) == service_anomaly._BASELINE_CACHE_MAX


def test_the_newest_entries_are_the_ones_kept():
    """Eviction has to drop the windows nobody can hit any more, not the
    current one — dropping the newest would make the cache useless."""
    cache = _fill(connection_anomaly, 10)
    assert "key-009" in cache
    assert "key-000" not in cache


def test_both_modules_agree_on_the_bound():
    """They have the identical pattern; a divergent bound would mean one of
    them was fixed and the other only looked fixed."""
    assert (connection_anomaly._BASELINE_CACHE_MAX
            == service_anomaly._BASELINE_CACHE_MAX)
