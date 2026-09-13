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


# --- the XML login rejection has to be actionable -----------------------------

def test_an_xml_auth_failure_names_what_to_check():
    """SFOS answers "Authentication Failure" for a wrong password, a source IP
    that is not allow-listed, and a profile without API rights alike. The bare
    status sends operators to re-check the password, which is the least likely
    of the three — the per-IP allow-list is what silently goes stale."""
    from app import sfos_xml

    recs, err = sfos_xml.parse_dhcp_records(
        '<Response><Login><status>Authentication Failure</status></Login></Response>')
    assert recs == {}
    assert "API access" in err
    assert "HOST" in err          # the firewall sees the Docker host, not the container
    assert "Authentication Failure" in err   # the original status is not thrown away


def test_a_successful_login_is_not_decorated_with_a_hint():
    from app import sfos_xml

    recs, err = sfos_xml.parse_dhcp_records(
        '<Response><Login><status>Authentication Successful</status></Login>'
        '<DHCPStaticEntry><HostName>ws-1</HostName><IPAddress>10.0.0.5</IPAddress>'
        '</DHCPStaticEntry></Response>')
    assert err is None
    assert recs["10.0.0.5"]["hostname"] == "ws-1"


# --- host records from more than DHCP ----------------------------------------

def test_a_neighbour_entry_without_a_name_is_kept_for_its_mac():
    """ARP/neighbour rows name nothing but know the MAC — which is what
    host-identity monitoring watches. parse_dhcp_records drops them; the host
    record parser must not."""
    payload = [{"ipAddress": "10.0.0.30", "macAddress": "aa:bb:cc:dd:ee:30"}]
    assert sfos_rest.parse_dhcp_records(payload) == {}
    recs = sfos_rest.parse_host_records(payload)
    assert recs["10.0.0.30"] == {"hostname": None, "mac": "aa:bb:cc:dd:ee:30"}


def test_a_row_with_neither_name_nor_mac_is_still_rejected():
    """Relaxing the name requirement must not start accepting gateways, DHCP
    range bounds or netmasks as if they were hosts. The MAC is the discriminator
    — infrastructure addresses never carry one."""
    payload = [{"name": "lan-dhcp", "gateway": "192.168.10.1",
                "startIp": "192.168.10.100", "subnetMask": "255.255.255.0"}]
    assert sfos_rest.parse_host_records(payload) == {}


def test_a_name_from_one_endpoint_merges_with_a_mac_from_another():
    """The whole reason for consulting four endpoints: a DHCP reservation names
    a host, the neighbour table has its MAC. Merging whole records would throw
    one of the two away."""
    out = {}
    sfos_rest._merge_records(out, sfos_rest.parse_host_records(
        [{"hostname": "ws-01", "ipAddress": "10.0.0.40"}]))
    sfos_rest._merge_records(out, sfos_rest.parse_host_records(
        [{"ipAddress": "10.0.0.40", "macAddress": "aa:bb:cc:dd:ee:40"}]))
    assert out["10.0.0.40"] == {"hostname": "ws-01", "mac": "aa:bb:cc:dd:ee:40"}


def test_the_earlier_endpoint_wins_per_field():
    """Endpoints are scanned in priority order, so a later, less deliberate
    source must not overwrite a name an operator maintains by hand."""
    out = {}
    sfos_rest._merge_records(out, {"10.0.0.41": {"hostname": "reserved", "mac": None}})
    sfos_rest._merge_records(out, {"10.0.0.41": {"hostname": "guessed", "mac": "aa:bb:cc:dd:ee:41"}})
    assert out["10.0.0.41"]["hostname"] == "reserved"
    assert out["10.0.0.41"]["mac"] == "aa:bb:cc:dd:ee:41"


def test_dhcp_parsing_is_unchanged_by_the_relaxed_rule():
    """parse_dhcp_records still requires a name, so nothing that depended on it
    starts seeing nameless rows."""
    payload = [{"hostname": "printer", "ipAddress": "192.168.10.20",
                "macAddress": "AA:BB:CC:DD:EE:01"},
               {"ipAddress": "192.168.10.21", "macAddress": "AA:BB:CC:DD:EE:02"}]
    recs = sfos_rest.parse_dhcp_records(payload)
    assert set(recs) == {"192.168.10.20"}


def test_the_xml_transport_answers_the_host_record_question_too():
    """The facade asks both transports the same thing; XML must not 404 on the
    richer question just because its answer is narrower."""
    from app import sfos_xml
    assert callable(sfos_xml.fetch_host_records)


def test_a_dhcp_scope_does_not_become_a_host_at_its_own_gateway():
    """Both transports used to scan a record for the first value shaped like a
    host IP. On a DHCP scope row that is the *gateway* — so the firewall itself
    appeared in the inventory renamed after the scope. is_host_ip() cannot catch
    it: a gateway is a perfectly valid host address."""
    from app.sfos_common import extract_host

    scope = {"name": "lan-dhcp", "gateway": "192.168.10.1",
             "startip": "192.168.10.100", "subnetmask": "255.255.255.0"}
    assert extract_host(scope) == ("", "", "")

    # A reservation *inside* a scope document still has a MAC, and must survive.
    reservation = {"hostname": "ws-01", "ipaddress": "192.168.10.50",
                   "macaddress": "aa:bb:cc:dd:ee:50", "gateway": "192.168.10.1"}
    ip, name, mac = extract_host(reservation)
    assert (ip, name) == ("192.168.10.50", "ws-01")


def test_the_named_address_field_wins_over_any_other_ip_in_the_row():
    """A host row can mention more than one address. The one in an address field
    is the host's; whatever else is there is context."""
    from app.sfos_common import extract_host

    ip, name, _ = extract_host({"hostname": "ws-02", "dnsserver": "10.0.0.1",
                                "ipaddress": "10.0.0.77"})
    assert ip == "10.0.0.77"


# --- the real v23 interface schema, captured from a live firewall -------------

_V23_IFACE = {"items": [
    {"name": "Port3", "hardwareName": "Port3", "type": "physical", "enabled": True,
     "zone": {"name": "MGMT"},
     "ipv4": {"ipv4Address": "172.16.3.1", "cidr": 24,
              "gatewayIpAddress": "", "assignmentType": "static"}},
    # A DHCP WAN port: no address of its own, but a populated gateway.
    {"name": "Port4", "hardwareName": "Port4", "type": "physical", "enabled": False,
     "zone": {"name": "WAN"},
     "ipv4": {"ipv4Address": "", "cidr": 0,
              "gatewayIpAddress": "128.0.0.1", "assignmentType": "dhcp"}},
    {"name": "VLAN-LAN", "hardwareName": "Port1", "type": "vlan", "enabled": True,
     "zone": {"name": "LAN"},
     "ipv4": {"ipv4Address": "172.16.16.1", "cidr": 23, "gatewayIpAddress": ""}},
]}


def test_the_nested_v23_interface_shape_is_parsed():
    ifaces = {i["name"]: i for i in sfos_rest.parse_interfaces(_V23_IFACE)}
    assert ifaces["Port3"]["ip"] == "172.16.3.1"
    assert ifaces["Port3"]["netmask"] == "255.255.255.0"   # cidr 24 -> dotted
    assert ifaces["Port3"]["zone"] == "MGMT"
    assert ifaces["Port3"]["status"] == "enabled"


def test_an_interface_does_not_adopt_its_gateway_as_its_own_address():
    """A DHCP WAN port has an empty address beside a populated gateway. Anything
    scanning the record for "an IP" reports the gateway as the interface's own —
    and that address then looks like one of the firewall's own IPs."""
    ifaces = {i["name"]: i for i in sfos_rest.parse_interfaces(_V23_IFACE)}
    assert ifaces["Port4"]["ip"] is None
    assert "128.0.0.1" not in {i["ip"] for i in sfos_rest.parse_interfaces(_V23_IFACE)}


def test_the_kind_is_read_from_the_record_not_guessed_from_the_name():
    """`type` already says physical/vlan/xfrm. Guessing from the name got
    'VLAN-LAN' right by luck and 'BACKUP' wrong."""
    ifaces = {i["name"]: i for i in sfos_rest.parse_interfaces(_V23_IFACE)}
    assert ifaces["VLAN-LAN"]["kind"] == "vlan"
    assert ifaces["Port3"]["kind"] == "physical"
    assert ifaces["VLAN-LAN"]["netmask"] == "255.255.254.0"   # /23


def test_a_flat_interface_record_still_works():
    """Older/other firmware reports the fields flat; the fallback must remain."""
    ifaces = sfos_rest.parse_interfaces(
        [{"name": "Port1", "hardware": "Port1", "zone": "LAN",
          "ipAddress": "10.0.0.1", "netmask": "255.255.255.0", "status": "up"}])
    assert ifaces[0]["ip"] == "10.0.0.1" and ifaces[0]["zone"] == "LAN"
