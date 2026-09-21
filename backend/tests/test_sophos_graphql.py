"""The Fusion XDR GraphQL transport, and the one way it could lie.

Sophos announced these APIs on 2026-09-18 as the replacement for the XDR Query
and Live Discover REST routes Warroom was built on. Most of the port is
mechanical. One part is not, and it is the reason this file exists.

**A GraphQL server reports failure with HTTP 200.** The status line says fine;
the body carries an `errors` array. Every other client in this codebase decides
success with `raise_for_status()`, and a transport that kept that habit would
read a permissions failure, a malformed query and a backend outage all as "no
detections found" — the single most dangerous sentence a security tool can say,
because it is indistinguishable from good news and nobody investigates it.
"""
import asyncio

import httpx
import pytest

from app import sophos_graphql as sgql


def _respond(payload, status=200):
    return lambda request: httpx.Response(status, json=payload)


def run_gql(handler, *args, **kwargs):
    """Drive one execute() against a mocked transport.

    asyncio.run rather than pytest-asyncio: that is how every other async test
    in this repo is written, and one file needing a plugin the others do not is
    a dependency nobody remembers to install."""
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await sgql.execute(c, *args, **kwargs)
    return asyncio.run(go())


def test_http_200_with_errors_is_a_failure_not_an_empty_result():
    """The whole point of the module. GraphQL signals failure in the body."""
    handler = _respond({
        "data": None,
        "errors": [{"message": "Access denied for tenant",
                    "extensions": {"code": "FORBIDDEN"}}],
    })
    with pytest.raises(sgql.SophosGraphQLError) as exc:
        run_gql(handler, {}, "query { detectionSearch { status } }")
    # The code is kept, not flattened into a string: a permissions problem, a
    # bad query and an outage need three different reactions.
    assert "FORBIDDEN" in exc.value.codes
    assert "Access denied" in str(exc.value)


def test_partial_data_alongside_errors_is_also_a_failure():
    """GraphQL can resolve some fields and fail others, returning both. Using
    the half that arrived would under-report without anything looking wrong —
    a detection list missing exactly the field that errored."""
    payload = {"data": {"detectionSearch": {"alerts": {"list": []}}},
               "errors": [{"message": "timeout resolving severity"}]}
    with pytest.raises(sgql.SophosGraphQLError):
        run_gql(_respond(payload), {}, "query { x }")

    # Opt-in, and deliberately awkward to reach.
    data = run_gql(_respond(payload), {}, "query { x }", allow_partial=True)
    assert data["detectionSearch"]["alerts"]["list"] == []


def test_neither_data_nor_errors_is_not_an_empty_success():
    """Returning {} here would be indistinguishable from a real empty result."""
    with pytest.raises(sgql.SophosGraphQLError):
        run_gql(_respond({}), {}, "query { x }")


def test_transport_errors_still_fail_loudly():
    """401/429/5xx never carry a GraphQL envelope."""
    with pytest.raises(sgql.SophosGraphQLError, match="401"):
        run_gql(_respond({"message": "no"}, status=401), {}, "query { x }")


def test_a_clean_response_returns_data():
    assert run_gql(_respond({"data": {"ok": True}}), {}, "query { ok }") == {"ok": True}


def test_graphql_never_goes_to_the_regional_host():
    """REST calls go to the tenant's data region; GraphQL does not. Sending it
    to api-eu01 fails in a way that reads as an auth problem, which is a long
    afternoon."""
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["tenant"] = request.headers.get("X-Tenant-ID")
        return httpx.Response(200, json={"data": {}})

    run_gql(handler, {"X-Tenant-ID": "t-1"}, "query { x }")
    assert seen["url"] == "https://api.taegis.sophos.com/graphql"
    assert seen["tenant"] == "t-1"


# --- the scale change ---------------------------------------------------------

def test_severity_is_converted_to_the_scale_the_rest_of_warroom_uses():
    """REST used 0-10, GraphQL uses a 0-1 float. Every threshold, notification
    rule and badge in this codebase is written against the old scale, so a raw
    0.9 would be read as "almost nothing" by a rule expecting 9."""
    assert sgql.severity_to_ten(0.9) == 9.0
    assert sgql.severity_to_ten(0.4) == 4.0
    assert sgql.severity_to_ten(0) == 0.0
    assert sgql.severity_to_ten(None) is None
    assert sgql.severity_to_ten("nonsense") is None


def test_a_value_already_on_the_ten_scale_is_not_multiplied_again():
    """Defensive. If Sophos ever sends 8 here, turning it into 80 would put it
    above every threshold at once."""
    assert sgql.severity_to_ten(8) == 8.0


def test_timestamps_are_read_from_seconds_and_nanos():
    """GraphQL sends {seconds, nanos}, not an ISO string. Passing that struct
    into anything expecting a string gives a row with no time at all."""
    iso = sgql.ts_to_iso({"seconds": 1789000000, "nanos": 123456000})
    assert iso is not None and iso.startswith("2026-")
    assert sgql.ts_to_iso("2026-09-20T10:00:00Z") is None
    assert sgql.ts_to_iso({}) is None


def test_a_detection_is_flattened_once_and_carries_both_scales():
    """Both scales on the row: the converted one for existing rules, the raw one
    so a value can still be traced back to what Sophos actually said."""
    flat = sgql.flatten_detection({
        "id": "d-1",
        "status": "OPEN",
        "metadata": {"title": "Suspicious PowerShell", "severity": 0.75,
                     "created_at": {"seconds": 1789000000, "nanos": 0}},
        "sensor_types": ["endpoint"],
        "attack_technique_ids": ["T1059.001"],
        "source_entities": [{"display_name": "host-a", "subtype": "host"}],
        "target_entities": [],
        "event_ids": [{"id": "rn:event:1"}],
    })
    assert flat["severity"] == 7.5
    assert flat["severity_raw"] == 0.75
    assert flat["mitre_techniques"] == ["T1059.001"]
    assert flat["source_entities"] == ["host-a"]
    assert flat["event_ids"] == ["rn:event:1"]
    assert flat["created_at"].startswith("2026-")


def test_flattening_survives_a_detection_with_nothing_in_it():
    """Sophos omits empty collections rather than sending []. Indexing into a
    missing key would drop the whole batch, not the one field."""
    flat = sgql.flatten_detection({"id": "d-2"})
    assert flat["id"] == "d-2"
    assert flat["severity"] is None
    assert flat["source_entities"] == [] and flat["event_ids"] == []


def test_the_detection_predicate_is_ql_not_sql():
    """The deprecated XDR Query API took SQL. QL is a different language and a
    copied query fails at the server, not here."""
    ql = sgql.detection_query(min_severity=0.4, status="OPEN", earliest="-24h")
    assert ql.startswith("from alert where")
    assert "severity >= 0.4" in ql and "earliest=-24h" in ql
    assert "SELECT" not in ql.upper()
