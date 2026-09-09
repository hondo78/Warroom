"""Peer-group scoring: groups too small to judge are reported rather than
dropped, attribution is two-sided, and an outlier is found relative to its own
service — not to the network as a whole."""

from app import service_anomaly as sa


def _conn(src, dst, service, *, out=1000, inn=1000, flows=10, buckets=10,
          night=0.0, dst_hosts=3):
    """One connection row as ``_recent`` would produce it (pre-featurize)."""
    return {"src": src, "dst": dst, "service": service, "service_label": service,
            "category": "web", "well_known": True, "port": 443, "ports": [443],
            "port_count": 1, "protocol": "TCP",
            "out_bytes": out, "in_bytes": inn, "flows": flows, "packets": flows * 2,
            "buckets": buckets, "night_ratio": night, "country": "AT",
            "first_seen": None, "last_seen": None,
            "_dst_hosts": dst_hosts}


def _prepare(items):
    spread = {it["dst"]: it["_dst_hosts"] for it in items}
    sa._featurize(items, spread)
    return items


def _empty_base():
    return {"host_service": {}, "service_hosts": {}}


def test_small_groups_are_reported_not_silently_dropped():
    items = _prepare([_conn(f"10.0.0.{i}", f"9.9.9.{i}", "ssh") for i in range(4)])
    found, scored, skipped = sa._score_groups(items, _empty_base(), dict(sa.DEFAULTS), 15)

    assert found == [] and scored == []
    assert len(skipped) == 1
    assert skipped[0]["service"] == "ssh"
    assert skipped[0]["size"] == 4
    assert skipped[0]["reason"] == "too_small"


def test_outlier_is_found_within_its_service_group():
    # 40 look-alike HTTPS connections plus one pushing 10000x the volume.
    items = [_conn(f"10.0.0.{i}", f"9.9.9.{i}", "https", out=1000 + i)
             for i in range(40)]
    items.append(_conn("10.0.0.99", "9.9.9.99", "https", out=10_000_000))
    _prepare(items)

    found, scored, _ = sa._score_groups(items, _empty_base(), dict(sa.DEFAULTS), 15)

    assert scored and scored[0]["service"] == "https"
    assert [a["src"] for a in found] == ["10.0.0.99"]
    top = found[0]
    assert top["drivers"][0]["dim"] == "out_bytes"
    assert top["drivers"][0]["dir"] == "high"
    assert top["drivers"][0]["factor"] > 100


def test_same_volume_is_normal_in_one_service_and_odd_in_another():
    """The whole point of peer grouping: identical numbers, different verdict.

    A 5 MB upload sits mid-field among HTTPS peers that all move megabytes, but
    is the extreme outlier among SMTP peers that all move kilobytes."""
    items = []
    for i in range(30):                       # HTTPS peers: megabytes each
        items.append(_conn(f"10.0.1.{i}", f"9.9.1.{i}", "https", out=4_000_000 + i * 1000))
    for i in range(30):                       # SMTP peers: kilobytes each
        items.append(_conn(f"10.0.2.{i}", f"9.9.2.{i}", "smtp", out=5_000 + i * 10))
    items.append(_conn("10.0.1.99", "9.9.1.99", "https", out=5_000_000))
    items.append(_conn("10.0.2.99", "9.9.2.99", "smtp", out=5_000_000))
    _prepare(items)

    found, _, _ = sa._score_groups(items, _empty_base(), dict(sa.DEFAULTS), 15)
    flagged = {a["src"] for a in found}

    assert "10.0.2.99" in flagged      # 5 MB over SMTP -> outlier
    assert "10.0.1.99" not in flagged  # same 5 MB over HTTPS -> unremarkable


def test_attribution_is_two_sided():
    # A connection whose upload ratio is far BELOW its peers must be explained
    # as "low", not missed because only high values count.
    items = [_conn(f"10.0.0.{i}", f"9.9.9.{i}", "https", out=10_000, inn=100)
             for i in range(30)]
    items.append(_conn("10.0.0.99", "9.9.9.99", "https", out=100, inn=10_000))
    _prepare(items)
    sa._attribute(items)

    odd = items[-1]
    dims = {d["dim"]: d for d in odd["drivers"]}
    assert "upload_ratio" in dims
    assert dims["upload_ratio"]["dir"] == "low"
    assert dims["upload_ratio"]["value"] < dims["upload_ratio"]["median"]


def test_novelty_signals_come_from_the_baseline():
    items = _prepare([_conn("10.0.0.1", "9.9.9.1", "ssh", dst_hosts=1)])
    it = items[0]

    base = {"host_service": {}, "service_hosts": {"ssh": 1}}
    codes = {s["code"] for s in sa._signals(it, base, 20)}
    assert "new_service_for_host" in codes      # host never used ssh before
    assert "rare_service_on_network" in codes   # nobody else speaks it either
    assert "rare_dst" in codes

    base = {"host_service": {("10.0.0.1", "ssh"): 20}, "service_hosts": {"ssh": 9}}
    codes = {s["code"] for s in sa._signals(it, base, 20)}
    assert "new_service_for_host" not in codes
    assert "rare_service_on_network" not in codes


def test_featurize_keeps_raw_and_model_values_aligned():
    items = _prepare([_conn("10.0.0.1", "9.9.9.1", "https", out=900, inn=100,
                            flows=9, dst_hosts=4)])
    it = items[0]
    assert it["upload_ratio"] == 0.9
    assert it["bytes_per_flow"] == 100.0
    assert it["dst_spread"] == 4
    # Every feature must exist as raw + f_ pair, or attribution reads zeros.
    for f in sa.FEATURES:
        assert f in it, f
        assert f"f_{f}" in it, f
