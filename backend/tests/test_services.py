"""Service resolution behind a NetFlow connection: the grouping key must stay
stable, and counting services must not degenerate into counting ports."""

from app import services


def test_well_known_port_resolves_to_service():
    r = services.resolve(443, 6)
    assert r["key"] == "https"
    assert r["category"] == "web"
    assert r["well_known"] is True
    assert "443" in r["label"] and "TCP" in r["label"]


def test_unknown_registered_port_keeps_its_own_identity():
    # Own group on purpose: an unnamed service on 8082 is its own population
    # for peer-group scoring.
    assert services.resolve(8082, 6)["key"] == "port-8082"
    assert services.resolve(8082, 6)["well_known"] is False


def test_dynamic_ports_collapse_into_one_group():
    # Every per-session client port must land in the same bucket, otherwise the
    # peer groups are all of size 1 and nothing can be an outlier.
    assert services.resolve(54709, 6)["key"] == services.EPHEMERAL
    assert services.resolve(60123, 17)["key"] == services.EPHEMERAL
    assert services.resolve(services.EPHEMERAL_MIN, 6)["key"] == services.EPHEMERAL


def test_port_zero_is_not_a_service():
    # NetFlow writes 0 for ICMP and friends — that is "no port", not port 0.
    assert services.resolve(0, 1)["key"] == services.UNKNOWN
    assert services.resolve(None, None)["key"] == services.UNKNOWN


def test_service_class_collapses_unnamed_ports():
    # The counting granularity: named services keep their name, everything
    # unnamed folds into two buckets.
    assert services.service_class(443, 6) == "https"
    assert services.service_class(8082, 6) == services.REGISTERED
    assert services.service_class(9999, 6) == services.REGISTERED
    assert services.service_class(54709, 6) == services.EPHEMERAL

    # The regression this guards: a host touching many unnamed ports must not
    # look like it speaks many services. (Range picked clear of the catalogue —
    # 9001/9030 are Tor and would legitimately resolve to names.)
    ports = range(30000, 30200)
    assert len({services.service_class(p, 6) for p in ports}) == 1
    assert len({services.resolve(p, 6)["key"] for p in ports}) == 200


def test_service_name_is_protocol_aware_and_optional():
    assert services.service_name(22, 6) == "ssh"
    # Not well-known -> None, so display code keeps showing a blank column.
    assert services.service_name(8082, 6) is None
    assert services.service_name(None) is None


def test_category_of_matches_resolve():
    for port in (443, 22, 3306, 123, 6881):
        r = services.resolve(port, 6)
        assert services.category_of(r["key"]) == r["category"]
    assert services.category_of("port-8082") == "other"


def test_proto_name():
    assert services.proto_name(6) == "TCP"
    assert services.proto_name(17) == "UDP"
    assert services.proto_name(99) == "proto-99"
    assert services.proto_name(None) is None
