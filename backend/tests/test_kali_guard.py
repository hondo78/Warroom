"""Command guard for the Tor-only Kali box.

Two very different failure modes are covered here. The allow-list rules stop a
command from reaching a target it must not touch. The nmap rules stop something
worse: a command that runs perfectly and reports fiction, because port states
cannot be observed through a transparent Tor proxy — the local Tor port accepts
every connection before the target is contacted, so nmap calls every port open.
"""

from app import kali_client as kc


def _guard(cmd, allowlist="34.22.184.52,example.com"):
    kc.settings.kali_target_allowlist = allowlist
    return kc.guard(cmd)


# --- nmap: refuse what would be fiction ---------------------------------------

def test_raw_scans_are_refused_with_the_actual_reason():
    for cmd in ("nmap -sS -Pn -p 80 34.22.184.52",
                "nmap -sU -Pn -p 53 34.22.184.52",
                "nmap -O -Pn -p 80 34.22.184.52",
                "nmap -PE -Pn -p 80 34.22.184.52"):
        argv, _, reason = _guard(cmd)
        assert argv is None, cmd
        assert "raw-packet" in reason, cmd


def test_a_portless_scan_is_refused_because_every_port_would_read_open():
    argv, _, reason = _guard("nmap -sT -Pn 34.22.184.52")
    assert argv is None
    assert "every port as open" in reason


def test_ranges_and_top_ports_are_refused():
    for cmd in ("nmap -sT -Pn -p- 34.22.184.52",
                "nmap -sT -Pn -p 1-1000 34.22.184.52",
                "nmap -sT -Pn --top-ports 100 34.22.184.52"):
        assert _guard(cmd)[0] is None, cmd


def test_too_many_explicit_ports_is_discovery_too():
    assert _guard("nmap -sT -Pn -p 21,22,23,25,80,443 34.22.184.52")[0] is None
    # ... and exactly the maximum still passes.
    assert _guard("nmap -sT -Pn -p 21,22,23,25,80 34.22.184.52")[0] is not None


def test_missing_Pn_is_named_rather_than_left_to_nmap():
    # Without -Pn nmap dies on a raw socket it may not open; the operator should
    # learn that from us, not from a cryptic dnet error.
    argv, _, reason = _guard("nmap -sT -p 80 34.22.184.52")
    assert argv is None
    assert "-Pn" in reason


def test_a_targeted_check_on_known_ports_is_allowed():
    # What still works over Tor: talking to a service on a port you already know.
    for cmd in ("nmap -sT -Pn -p 443 34.22.184.52",
                "nmap -sT -Pn -p80,443 34.22.184.52",
                "nmap -sT -Pn --ports=443 -sV 34.22.184.52"):
        argv, targets, reason = _guard(cmd)
        assert argv is not None, f"{cmd}: {reason}"
        assert targets == ["34.22.184.52"], cmd


def test_nmap_rules_do_not_leak_into_other_tools():
    # whois/dig have no ports and must not be asked for -p or -Pn.
    for cmd in ("whois 34.22.184.52", "dig example.com", "sslscan example.com"):
        assert _guard(cmd)[0] is not None, cmd


# --- the pre-existing guarantees, now covered ---------------------------------

def test_targets_outside_the_allowlist_are_refused():
    argv, _, reason = _guard("whois 1.2.3.4")
    assert argv is None and "allowlist" in reason


def test_an_empty_allowlist_allows_nothing():
    assert _guard("whois 34.22.184.52", allowlist="")[0] is None


def test_shell_metacharacters_and_unknown_binaries_are_refused():
    assert _guard("nmap -sT -Pn -p 80 34.22.184.52 | grep open")[0] is None
    assert _guard("cat /etc/passwd")[0] is None


def test_subdomains_of_an_allowed_domain_are_allowed():
    assert _guard("dig www.example.com")[0] is not None
    assert _guard("dig example.com.evil.net")[0] is None


# --- hosts hidden inside a single token --------------------------------------

def test_the_dns_server_in_digs_at_syntax_is_a_target():
    """`dig @1.2.3.4 example.com` asks 1.2.3.4, not the allow-listed name. The
    `@host` token used to parse as nothing and was skipped, so the server the
    query actually went to never reached the allow-list."""
    argv, targets, reason = _guard("dig @203.0.113.9 example.com",
                                   allowlist="example.com")
    assert argv is None
    assert "203.0.113.9" in reason


def test_an_allow_listed_dns_server_is_still_usable():
    argv, targets, reason = _guard("dig @example.com example.com",
                                   allowlist="example.com")
    assert argv is not None, reason


def test_curl_resolve_cannot_redirect_an_allow_listed_name_elsewhere():
    """--resolve pins the real TCP destination. Validating only the URL host
    would approve a request that connects somewhere else entirely."""
    argv, targets, reason = _guard(
        "curl --resolve example.com:443:203.0.113.9 https://example.com/",
        allowlist="example.com")
    assert argv is None
    assert "203.0.113.9" in reason


def test_curl_connect_to_is_checked_the_same_way():
    argv, targets, reason = _guard(
        "curl --connect-to example.com:443:203.0.113.9:443 https://example.com/",
        allowlist="example.com")
    assert argv is None
    assert "203.0.113.9" in reason


def test_an_ipv6_literal_is_not_torn_apart_by_the_colon_split():
    """The colon handling must not turn one IPv6 address into a pile of
    fragments that each fail to parse — that would fail closed by accident and
    for the wrong reason."""
    argv, targets, reason = _guard("curl http://[2001:db8::1]/",
                                   allowlist="2001:db8::/32")
    assert argv is not None, reason


def test_ordinary_arguments_are_still_not_targets():
    """The wider net must not start treating flags and filenames as hosts."""
    argv, targets, reason = _guard("nmap -Pn -p 443 example.com",
                                   allowlist="example.com")
    assert argv is not None, reason
    assert targets == ["example.com"]


# --- commands whose destination never appears as an argument -------------------

def test_a_command_without_a_recognisable_target_is_refused():
    """The allow-list loop can only judge hosts it can see. A command that names
    none passed it vacuously and ran unchecked — fail-closed means refusing the
    one case the guard cannot parse, not waving it through."""
    argv, _, reason = _guard("whois --help")
    assert argv is None
    assert "no target recognised" in reason


def test_targets_read_from_a_file_or_invented_are_refused():
    # -iL/-iR/-K keep the real destinations out of argv entirely: a downloaded
    # target list or nmap's random-host generator would never reach the
    # allow-list at all.
    for cmd in ("nmap -Pn -p 80 -iL /tmp/targets.txt",
                "nmap -Pn -p 80 -iR 1000",
                "curl -K /tmp/curlrc",
                "wget --input-file /tmp/urls.txt"):
        assert _guard(cmd)[0] is None, cmd


def test_the_equals_spelling_of_a_flood_rate_is_blocked_too():
    # nmap takes --min-rate=90000 as readily as --min-rate 90000; a pattern that
    # only knew the spaced form blocked one and passed the other.
    assert _guard("nmap -Pn -p 80 --min-rate=90000 example.com")[0] is None
    assert _guard("nmap -Pn -p 80 --min-rate 90000 example.com")[0] is None


# --- approving a command is a one-time claim ---------------------------------

def test_the_approval_carries_its_precondition_in_the_update():
    """Read-then-write let two concurrent approvals both see 'pending' and both
    execute — the intrusive command ran twice and the second result overwrote
    the first. The precondition has to travel with the UPDATE so the database
    settles it, not the application."""
    import inspect
    from app import kali_client

    src = inspect.getsource(kali_client._claim)
    assert "update(KaliCommand)" in src
    assert 'KaliCommand.status == "pending"' in src
    # and the decision must not be re-derived from a prior read
    assert "db.get(KaliCommand, cmd_id)" in src   # only for the error message


def test_approve_and_reject_both_go_through_the_claim():
    import inspect
    from app import kali_client

    for fn in (kali_client.approve_command, kali_client.reject_command):
        assert "_claim(" in inspect.getsource(fn), fn.__name__
