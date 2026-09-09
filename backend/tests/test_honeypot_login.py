"""Decoy login page.

Two things must hold. The page must never give itself away — same answer, same
shape, whatever it is fed. And the automatic response must not be turnable
against the people it protects: an attacker typing a real colleague's name into
the decoy must not get that colleague blocked everywhere else.
"""

from app import honeypot_login as hl


class _Req:
    def __init__(self, headers=None, client_host=None):
        self.headers = headers or {}
        self.client = type("C", (), {"host": client_host})()
        self.url = type("U", (), {"path": "/api/honeypot/decoy-login"})()


def test_forwarded_client_ip_wins_over_the_socket():
    # The decoy is only useful when reachable from outside, which means a proxy
    # in front; the socket address would be that proxy, not the attacker.
    r = _Req({"x-forwarded-for": "185.195.232.168, 10.0.0.9",
              "x-real-ip": "10.0.0.9"}, client_host="172.18.0.5")
    assert hl.client_ip(r) == "185.195.232.168"


def test_a_forged_leading_forwarded_entry_does_not_win():
    # Every proxy appends what it saw, so the leftmost entry is whatever the
    # client sent. Trusting it would let an attacker POST
    # "X-Forwarded-For: 8.8.8.8" at the decoy and have Warroom block the
    # resolver instead of them.
    r = _Req({"x-forwarded-for": "8.8.8.8, 185.195.232.168, 10.0.0.9",
              "x-real-ip": "10.0.0.9"}, client_host="172.18.0.5")
    assert hl.client_ip(r) == "185.195.232.168"


def test_real_ip_is_used_when_nothing_was_forwarded():
    assert hl.client_ip(_Req({"x-real-ip": "185.195.232.168"})) == "185.195.232.168"


def test_socket_address_is_the_last_resort():
    assert hl.client_ip(_Req({}, client_host="185.195.232.168")) == "185.195.232.168"


def test_missing_everything_is_not_an_error():
    # A capture with no usable address must still record; failing here would
    # turn a malformed request into a 500 and expose the page as special.
    assert hl.client_ip(_Req({})) is None


def test_oversized_fields_are_truncated_not_rejected():
    # Rejecting tells the visitor the form is not real. Truncating keeps the
    # illusion and bounds what a scripted flood can write.
    long = "A" * 50_000
    assert len(hl._trim(long, hl.MAX_FIELD)) == hl.MAX_FIELD
    assert hl._trim("  spaced  ") == "spaced"
    assert hl._trim("") is None
    assert hl._trim(None) is None


# --- credential extraction ----------------------------------------------------
# The decoy must record what was tried, not insist the attacker use our field
# names. Every portal and every scanner has its own vocabulary, and a pair we
# fail to parse is evidence thrown away at the moment of capture.

def test_the_obvious_shape():
    assert hl.extract_credentials({"username": "a", "password": "b"}) == ("a", "b")


def test_common_alternative_field_names():
    for body, want in (
        ({"user": "a", "pass": "b"}, ("a", "b")),
        ({"login": "a", "passwd": "b"}, ("a", "b")),
        ({"email": "a@b.c", "pwd": "b"}, ("a@b.c", "b")),
        ({"j_username": "a", "j_password": "b"}, ("a", "b")),
    ):
        assert hl.extract_credentials(body) == want, body


def test_field_names_are_case_insensitive():
    assert hl.extract_credentials({"Username": "a", "PASSWORD": "b"}) == ("a", "b")


def test_nested_bodies_are_searched():
    assert hl.extract_credentials(
        {"data": {"credentials": {"username": "a", "password": "b"}}}) == ("a", "b")
    assert hl.extract_credentials(
        {"items": [{"user": "a"}, {"pass": "b"}]}) == ("a", "b")


def test_http_basic_is_understood():
    import base64
    h = {"authorization": "Basic " + base64.b64encode(b"a:b").decode()}
    assert hl.extract_credentials(None, h) == ("a", "b")
    # A body wins over the header, but the header fills a gap.
    assert hl.extract_credentials({"username": "x"}, h) == ("x", "b")


def test_nothing_credential_shaped_is_not_invented():
    assert hl.extract_credentials({"foo": "bar"}) == (None, None)
    assert hl.extract_credentials(None) == (None, None)
    assert hl.extract_credentials("not a mapping") == (None, None)


def test_a_hostile_payload_cannot_turn_the_search_into_the_attack():
    # Depth is bounded, so a deeply nested body terminates instead of blowing
    # the stack — the decoy must not be a way to take the backend down.
    deep = cur = {}
    for _ in range(5000):
        cur["x"] = {}
        cur = cur["x"]
    cur["password"] = "never reached, and that is fine"
    assert hl.extract_credentials(deep) == (None, None)


# --- MCP exposure -------------------------------------------------------------
# The password was deliberately taken out of the Telegram alert; MCP is the same
# class of channel, with a language model at the far end that may not be local.

def test_masking_describes_the_password_without_disclosing_it(monkeypatch):
    from app import mcp_server
    from app.config import settings

    monkeypatch.setattr(settings, "mcp_honeypot_reveal_passwords", False)
    out = mcp_server._mask("Sommer2026!")
    assert "Sommer" not in out and "2026" not in out
    assert "11 chars" in out          # length survives ...
    assert "A" in out and "a" in out and "9" in out and "#" in out   # ... and shape

    assert mcp_server._mask(None) is None


def test_the_operator_can_still_choose_to_reveal(monkeypatch):
    from app import mcp_server
    from app.config import settings

    monkeypatch.setattr(settings, "mcp_honeypot_reveal_passwords", True)
    assert mcp_server._mask("Sommer2026!") == "Sommer2026!"
