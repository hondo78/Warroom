"""SFOS v23 REST parsing and transport selection.

The published REST schemas are rendered client-side and differ by firmware, so
the parser matches on *shape* rather than on field names it cannot verify —
exactly what the XML transport already had to learn. These tests pin the shape
rules, and pin the one thing a wrong answer would quietly break: that a DHCP
server's own config row never turns into a fake client host.
"""
import asyncio

import pytest

from app import sfos_rest
from app.sfos_common import host_record


# --- DHCP records ------------------------------------------------------------

def test_a_flat_list_of_reservations_is_parsed():
    payload = [
        {"hostname": "printer", "ipAddress": "192.168.10.20",
         "macAddress": "AA:BB:CC:DD:EE:01"},
        {"hostname": "nas", "ipAddress": "192.168.10.21"},
    ]
    recs = sfos_rest.parse_dhcp_records(payload)
    assert recs["192.168.10.20"] == {"hostname": "printer", "mac": "aa:bb:cc:dd:ee:01"}
    assert recs["192.168.10.21"] == {"hostname": "nas", "mac": None}


def test_records_are_found_however_deeply_they_are_nested():
    """The response envelope differs per endpoint and per firmware. Walking the
    whole document means a new wrapper key does not lose every record."""
    payload = {"data": {"servers": [
        {"name": "lan-dhcp", "staticEntries": [
            {"hostName": "ws-01", "ipAddress": "10.0.0.5",
             "macAddress": "aa-bb-cc-dd-ee-02"},
        ]},
    ]}}
    recs = sfos_rest.parse_dhcp_records(payload)
    assert recs["10.0.0.5"]["hostname"] == "ws-01"
    # MAC is normalised to colon-lowercase regardless of the separator used.
    assert recs["10.0.0.5"]["mac"] == "aa:bb:cc:dd:ee:02"


def test_the_dhcp_servers_own_config_row_is_not_read_as_a_client():
    """A server record carries a name plus a subnet, gateway and netmask. If the
    netmask or network address were accepted as a host IP, every firewall would
    grow phantom hosts named after its DHCP scope."""
    payload = [{
        "name": "lan-dhcp",
        "subnetMask": "255.255.255.0",
        "network": "192.168.10.0",
        "gateway": "192.168.10.1",
        "startIp": "192.168.10.100",
    }]
    recs = sfos_rest.parse_dhcp_records(payload)
    assert "255.255.255.0" not in recs
    assert "192.168.10.0" not in recs


def test_a_record_without_a_name_is_skipped():
    assert sfos_rest.parse_dhcp_records([{"ipAddress": "10.0.0.9"}]) == {}


def test_placeholder_names_are_not_hostnames():
    payload = [{"hostname": "-", "ipAddress": "10.0.0.7"}]
    assert sfos_rest.parse_dhcp_records(payload) == {}


def test_the_first_record_for_an_ip_wins():
    """Endpoints are scanned in order and merged; a later duplicate must not
    overwrite an earlier, more specific answer."""
    payload = [
        {"hostname": "first", "ipAddress": "10.0.0.8"},
        {"hostname": "second", "ipAddress": "10.0.0.8"},
    ]
    assert sfos_rest.parse_dhcp_records(payload)["10.0.0.8"]["hostname"] == "first"


def test_an_empty_document_is_not_an_error():
    for empty in ({}, [], None, {"data": []}):
        assert sfos_rest.parse_dhcp_records(empty) == {}


def test_booleans_are_not_mistaken_for_field_values():
    """``True`` is an int in Python. Without excluding bools, a flag field could
    be stringified into the name slot."""
    payload = [{"enabled": True, "hostname": "real", "ipAddress": "10.0.0.10"}]
    recs = sfos_rest.parse_dhcp_records(payload)
    assert recs["10.0.0.10"]["hostname"] == "real"


# --- interfaces --------------------------------------------------------------

def test_interfaces_carry_name_zone_and_address():
    payload = [{"name": "Port1", "hardware": "Port1", "zone": "LAN",
                "ipAddress": "172.16.16.1", "netmask": "255.255.255.0",
                "status": "up"}]
    ifaces = sfos_rest.parse_interfaces(payload)
    assert ifaces == [{"name": "Port1", "hardware": "Port1", "zone": "LAN",
                       "ip": "172.16.16.1", "netmask": "255.255.255.0",
                       "status": "up", "kind": "physical"}]


def test_vlans_arrive_in_the_same_list_and_are_labelled():
    """The XML API had a separate VLAN entity; REST returns one interface list,
    so the kind has to come from the record itself."""
    payload = [{"name": "Port1.100", "vlanId": 100, "zone": "DMZ",
                "ipAddress": "10.1.0.1"}]
    assert sfos_rest.parse_interfaces(payload)[0]["kind"] == "vlan"


def test_an_object_with_a_name_but_nothing_interface_like_is_ignored():
    """Walking the whole document means unrelated named objects get visited.
    Requiring hardware/zone/IP keeps them out of the interface list."""
    assert sfos_rest.parse_interfaces([{"name": "some-policy"}]) == []


def test_a_non_ip_address_field_does_not_become_an_ip():
    ifaces = sfos_rest.parse_interfaces(
        [{"name": "Port2", "zone": "WAN", "ipAddress": "dhcp"}])
    assert ifaces[0]["ip"] is None


def test_interfaces_are_deduplicated_by_name():
    payload = [{"name": "Port1", "zone": "LAN", "ipAddress": "10.0.0.1"},
               {"name": "Port1", "zone": "LAN", "ipAddress": "10.0.0.1"}]
    assert len(sfos_rest.parse_interfaces(payload)) == 1


# --- hostname ----------------------------------------------------------------

def test_hostname_is_read_from_system_settings():
    assert sfos_rest.parse_hostname({"hostname": "fw-01"}) == "fw-01"
    assert sfos_rest.parse_hostname({"device": {"hostName": "fw-02"}}) == "fw-02"


def test_hostname_missing_is_none_not_an_exception():
    assert sfos_rest.parse_hostname({"unrelated": 1}) is None


# --- shared record shape -----------------------------------------------------

def test_both_transports_build_the_same_record_shape():
    """The facade lets callers switch transports without noticing. That only
    holds while a record means the same thing on both sides."""
    assert host_record("10.0.0.2", "host", "AA-BB-CC-DD-EE-03") == {
        "hostname": "host", "mac": "aa:bb:cc:dd:ee:03"}
    assert host_record("10.0.0.255", "host") is None   # broadcast
    assert host_record("not-an-ip", "host") is None
    assert host_record("10.0.0.2", "") is None


# --- transport selection -----------------------------------------------------

def test_a_pinned_mode_is_used_verbatim(monkeypatch):
    from app import sfos_client
    from app.config import settings
    sfos_client.reset_transport_cache()
    monkeypatch.setattr(settings, "firewall_api_mode", "xml", raising=False)
    assert asyncio.run(sfos_client.active_transport()) == "xml"
    monkeypatch.setattr(settings, "firewall_api_mode", "rest", raising=False)
    assert asyncio.run(sfos_client.active_transport()) == "rest"


def test_auto_falls_back_to_xml_when_no_api_key_is_configured(monkeypatch):
    """A firewall below v23, or a v23 box nobody has made a key on yet, must
    keep resolving hostnames over XML instead of going quiet."""
    from app import sfos_client
    from app.config import settings
    sfos_client.reset_transport_cache()
    monkeypatch.setattr(settings, "firewall_api_mode", "auto", raising=False)
    monkeypatch.setattr(settings, "firewall_api_key", "", raising=False)
    assert asyncio.run(sfos_client.active_transport()) == "xml"


def test_auto_uses_rest_when_the_probe_authenticates(monkeypatch):
    from app import sfos_client, sfos_rest as rest
    from app.config import settings
    sfos_client.reset_transport_cache()
    monkeypatch.setattr(settings, "firewall_api_mode", "auto", raising=False)
    monkeypatch.setattr(settings, "firewall_api_host", "fw.example", raising=False)
    monkeypatch.setattr(settings, "firewall_api_key", "k", raising=False)

    async def ok():
        return {"available": True, "authenticated": True, "error": None}
    monkeypatch.setattr(rest, "probe", ok)
    assert asyncio.run(sfos_client.active_transport()) == "rest"


def test_auto_falls_back_when_the_key_is_rejected(monkeypatch):
    """A stale or wrong key must not take hostname resolution down with it."""
    from app import sfos_client, sfos_rest as rest
    from app.config import settings
    sfos_client.reset_transport_cache()
    monkeypatch.setattr(settings, "firewall_api_mode", "auto", raising=False)
    monkeypatch.setattr(settings, "firewall_api_host", "fw.example", raising=False)
    monkeypatch.setattr(settings, "firewall_api_key", "bad", raising=False)

    async def denied():
        return {"available": True, "authenticated": False, "error": "401"}
    monkeypatch.setattr(rest, "probe", denied)
    assert asyncio.run(sfos_client.active_transport()) == "xml"


def test_changing_settings_forgets_the_detected_transport(monkeypatch):
    """The probe result is cached, so adding a key later has to invalidate it —
    otherwise the operator sets one and nothing happens until a restart."""
    from app import sfos_client
    from app.config import settings
    monkeypatch.setattr(settings, "firewall_api_mode", "auto", raising=False)
    monkeypatch.setattr(settings, "firewall_api_key", "", raising=False)
    assert asyncio.run(sfos_client.active_transport()) == "xml"
    sfos_client.reset_transport_cache()
    assert sfos_client._auto_transport is None


# --- the fallback has to survive more than the two tidy errors ---------------

def test_a_generic_rest_failure_still_falls_back_to_xml(monkeypatch):
    """Catching only the two *expected* REST errors meant an HTTP 500, bad JSON,
    or a bare httpx timeout escaped the fallback into the caller's own broad
    except — serving stale data for the whole outage while XML worked fine."""
    from app import sfos_client, sfos_rest as rest, sfos_xml
    from app.config import settings
    sfos_client.reset_transport_cache()
    monkeypatch.setattr(settings, "firewall_api_mode", "auto", raising=False)

    async def boom():
        raise TimeoutError("connect timed out")
    async def xml_ok():
        return {"10.0.0.1": {"hostname": "from-xml", "mac": None}}
    monkeypatch.setattr(rest, "fetch_dhcp_records", boom)
    monkeypatch.setattr(sfos_xml, "fetch_dhcp_records", xml_ok)

    out = asyncio.run(sfos_client._try_rest("fetch_dhcp_records"))
    assert out["10.0.0.1"]["hostname"] == "from-xml"


def test_a_pinned_rest_mode_still_surfaces_the_error(monkeypatch):
    """Falling back silently would hide the problem from the operator who
    deliberately pinned REST while setting it up."""
    from app import sfos_client, sfos_rest as rest
    from app.config import settings
    sfos_client.reset_transport_cache()
    monkeypatch.setattr(settings, "firewall_api_mode", "rest", raising=False)

    async def boom():
        raise TimeoutError("connect timed out")
    monkeypatch.setattr(rest, "fetch_dhcp_records", boom)

    with pytest.raises(TimeoutError):
        asyncio.run(sfos_client._try_rest("fetch_dhcp_records"))
