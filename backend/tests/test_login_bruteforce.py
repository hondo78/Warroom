"""Invalid-username brute-force detection.

The rule blocks without human or LLM review, so the tests focus as much on what
must NOT be blocked as on what must.
"""

from app import login_bruteforce as lb

KNOWN = {"burkhard", "admin", "christian", "ztna1"}


def _a(ip, user, ts="2026-08-10T10:00:00+00:00", **kw):
    return {"uid": 1, "ip": ip, "user": user, "ts": ts,
            "component": kw.get("component"), "country": kw.get("country")}


def test_sprayer_with_invented_usernames_is_reported():
    attempts = [_a("185.195.232.168", u) for u in
                ("art@familie-luehrs.de", "burkhard_support", "atelier.info", "apoyo")]
    out = lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3)

    assert len(out) == 1
    o = out[0]
    assert o["ip"] == "185.195.232.168"
    assert o["unknown_user_count"] == 4
    assert o["attempts"] == 4
    assert "apoyo" in o["unknown_users"]


def test_real_user_retrying_one_password_is_never_reported():
    # 20 failures, but a single existing username — a forgotten password, not an
    # attack. This is the false positive that would lock out our own people.
    attempts = [_a("146.70.119.90", "burkhard") for _ in range(20)]
    assert lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3) == []


def test_one_typo_does_not_trigger():
    # A user mistyping their own name twice must stay below the threshold.
    attempts = [_a("147.78.241.189", "burkhrad"), _a("147.78.241.189", "burkhard"),
                _a("147.78.241.189", "burkhard")]
    assert lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3) == []


def test_internal_sources_are_never_reported():
    # Blocking our own network is worse than missing an internal attacker.
    for ip in ("10.0.1.5", "192.168.1.10", "172.16.4.4", "127.0.0.1"):
        attempts = [_a(ip, f"ghost{i}") for i in range(6)]
        assert lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3) == [], ip


def test_empty_directory_blocks_nothing():
    # The critical interlock: with no known users every name looks invalid, so
    # the rule must produce nothing rather than block the world.
    attempts = [_a("185.195.232.168", f"user{i}") for i in range(10)]
    assert lb.evaluate(attempts, set(), min_unknown_users=3, min_attempts=3) == []


def test_username_matching_is_case_and_space_insensitive():
    attempts = [_a("185.195.232.168", " BURKHARD "), _a("185.195.232.168", "Admin"),
                _a("185.195.232.168", "Christian")]
    assert lb.evaluate(attempts, KNOWN, min_unknown_users=1, min_attempts=1) == []


def test_thresholds_are_respected_independently():
    three = [_a("185.195.232.168", f"ghost{i}") for i in range(3)]
    # Enough distinct names, but attempt floor raised above it.
    assert lb.evaluate(three, KNOWN, min_unknown_users=3, min_attempts=10) == []
    # Enough attempts, but not enough distinct names.
    assert lb.evaluate(three, KNOWN, min_unknown_users=5, min_attempts=3) == []
    assert len(lb.evaluate(three, KNOWN, min_unknown_users=3, min_attempts=3)) == 1


def test_placeholder_usernames_are_ignored():
    attempts = [_a("185.195.232.168", u) for u in ("", "-", "unknown", "n/a", "none")]
    assert lb.evaluate(attempts, KNOWN, min_unknown_users=1, min_attempts=1) == []


def test_offenders_are_ranked_worst_first():
    attempts = ([_a("135.136.21.85", f"a{i}") for i in range(3)]
                + [_a("194.36.27.169", f"b{i}") for i in range(9)])
    out = lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3)
    assert [o["ip"] for o in out] == ["194.36.27.169", "135.136.21.85"]


def test_report_carries_evidence_for_the_alert():
    attempts = [_a("185.195.232.168", f"ghost{i}", ts=f"2026-08-10T10:0{i}:00+00:00",
                   component="SSL VPN", country="RU") for i in range(4)]
    o = lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3)[0]

    assert o["country"] == "RU"
    assert o["components"] == ["SSL VPN"]
    assert o["first_ts"] == "2026-08-10T10:00:00+00:00"
    assert o["last_ts"] == "2026-08-10T10:03:00+00:00"
    assert "ghost0" in lb.block_comment(o)
    assert "4" in lb.block_comment(o)


def test_unknown_user_list_is_capped():
    attempts = [_a("185.195.232.168", f"ghost{i:03d}") for i in range(50)]
    o = lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3)[0]
    assert o["unknown_user_count"] == 50      # full count is kept ...
    assert len(o["unknown_users"]) == 10      # ... but the sample is bounded


def test_is_public_ipv4():
    assert lb.is_public_ipv4("185.195.232.168")
    assert not lb.is_public_ipv4("10.0.0.1")
    assert not lb.is_public_ipv4("169.254.1.1")
    assert not lb.is_public_ipv4("::1")       # IPv4-only rule
    assert not lb.is_public_ipv4("not-an-ip")
    assert not lb.is_public_ipv4(None)


def test_normalise():
    assert lb.normalise("  Admin ") == "admin"
    assert lb.normalise(None) == ""


# --- directory composition (learned + operator overrides) ---------------------
# The effective directory decides what counts as a real account, so the
# allow/deny arithmetic is the second place a mistake would cause bad blocks.

import asyncio


class _FakeDB:
    """Stands in for the AsyncSession: only load_overrides touches it."""

    def __init__(self, rows):
        self._rows = rows

    async def execute(self, *_a, **_kw):
        rows = self._rows

        class R:
            def all(self):
                return rows
        return R()


def _known(monkeypatch, learned, override_rows):
    async def fake_learned():
        return learned
    monkeypatch.setattr(lb, "learned_users", fake_learned)
    return asyncio.run(lb.known_users(_FakeDB(override_rows)))


def test_manual_allow_extends_the_directory(monkeypatch):
    # The new-hire gap: an account that exists but never logged in yet.
    users = _known(monkeypatch, {"burkhard", "admin", "christian"},
                   [("neuer.kollege", "allow")])
    assert "neuer.kollege" in users


def test_deny_removes_a_learned_name(monkeypatch):
    # A generic login that did succeed must not shield someone guessing it.
    users = _known(monkeypatch, {"burkhard", "admin", "christian", "service"},
                   [("service", "deny")])
    assert "service" not in users
    assert "burkhard" in users


def test_deny_wins_over_allow(monkeypatch):
    users = _known(monkeypatch, {"a", "b", "c"},
                   [("x", "allow"), ("x", "deny")])
    assert "x" not in users


def test_denying_everything_disarms_instead_of_arming(monkeypatch):
    # The size check runs on the EFFECTIVE set: stripping it below the minimum
    # must disable the rule, not leave it armed against every username.
    users = _known(monkeypatch, {"burkhard", "admin", "christian"},
                   [("burkhard", "deny"), ("admin", "deny")])
    assert users is None


def test_redis_outage_yields_none_even_with_overrides(monkeypatch):
    async def fake_learned():
        return None
    monkeypatch.setattr(lb, "learned_users", fake_learned)
    assert asyncio.run(lb.known_users(_FakeDB([("a", "allow")]))) is None


def test_directory_view_reports_origin_and_state(monkeypatch):
    async def fake_learned():
        return {"burkhard", "admin", "christian", "service"}
    monkeypatch.setattr(lb, "learned_users", fake_learned)
    rows = [("neuer.kollege", "allow"), ("admin", "allow"), ("service", "deny")]

    view = asyncio.run(lb.directory_view(_FakeDB(rows)))
    by_user = {e["user"]: e for e in view["entries"]}

    assert by_user["burkhard"]["origin"] == "learned"
    assert by_user["neuer.kollege"]["origin"] == "manual"
    assert by_user["admin"]["origin"] == "both"
    assert by_user["service"]["excluded"] is True
    assert by_user["service"]["counts_as_real"] is False
    assert by_user["neuer.kollege"]["counts_as_real"] is True
    assert view["armed"] is True
    assert view["learned_count"] == 4 and view["manual_count"] == 2


# --- generic names ------------------------------------------------------------
# A generic name that counts as real costs the rule a point against whoever
# guesses it. Flagged, never auto-excluded: the operator decides.

def test_is_generic():
    assert lb.is_generic("admin") and lb.is_generic("  ROOT ")
    assert not lb.is_generic("burkhard")
    assert not lb.is_generic(None)


def test_directory_view_flags_only_generic_names_that_still_shield(monkeypatch):
    async def fake_learned():
        return {"burkhard", "admin", "christian", "service"}
    monkeypatch.setattr(lb, "learned_users", fake_learned)

    view = asyncio.run(lb.directory_view(_FakeDB([("service", "deny")])))
    by_user = {e["user"]: e for e in view["entries"]}

    assert by_user["admin"]["generic"] is True
    assert by_user["burkhard"]["generic"] is False
    # "service" is generic too, but excluded — it shields nobody any more and
    # must not show up as something left to fix.
    assert by_user["service"]["generic"] is True
    assert view["generic_shielding"] == ["admin"]


# --- backtest -----------------------------------------------------------------

def test_summarise_reports_what_evaluate_found_plus_context():
    attempts = ([_a("185.195.232.168", f"ghost{i}", ts=f"2026-08-10T10:0{i}:00+00:00")
                 for i in range(4)]
                + [_a("10.0.0.5", "ghost9", ts="2026-08-10T09:00:00+00:00")]
                + [_a("135.136.21.85", "burkhard", ts="2026-08-10T11:00:00+00:00")])

    out = lb.summarise(attempts, KNOWN, min_unknown_users=3, min_attempts=3)

    assert [o["ip"] for o in out["offenders"]] == ["185.195.232.168"]
    assert out["attempts_total"] == 6
    assert out["attempts_public"] == 5        # the internal source is excluded ...
    assert out["distinct_ips"] == 2           # ... from the public tally too
    assert out["first_ts"] == "2026-08-10T09:00:00+00:00"
    assert out["last_ts"] == "2026-08-10T11:00:00+00:00"
    assert out["directory_size"] == len(KNOWN)


# --- burned usernames (instant block on the first attempt) --------------------
# The dangerous half of the rule: one attempt is enough. Everything here is about
# what must NOT end up on the list, and what must not fire once it does.

BURNED = {"admin_support", "art@familie-luehrs.de", "burkhard_admin"}


def test_single_attempt_with_a_burned_name_is_enough():
    hit = lb.match_burned([_a("185.195.232.168", "admin_support")], BURNED)
    assert len(hit) == 1
    assert hit[0]["ip"] == "185.195.232.168"
    assert hit[0]["attempts"] == 1
    assert hit[0]["trigger"] == "burned_username"


def test_burned_match_ignores_names_not_on_the_list():
    # A real user failing their own password must not be touched by this rule.
    assert lb.match_burned([_a("185.195.232.168", "burkhard") for _ in range(9)],
                           BURNED) == []


def test_burned_match_never_touches_internal_sources():
    for ip in ("10.0.1.5", "192.168.1.10", "127.0.0.1"):
        assert lb.match_burned([_a(ip, "admin_support")], BURNED) == [], ip


def test_burned_match_is_case_and_space_insensitive():
    assert len(lb.match_burned([_a("185.195.232.168", "  ADMIN_Support ")], BURNED)) == 1


def test_empty_burn_list_blocks_nothing():
    # Same interlock as the directory: an empty list must mean "no opinion",
    # never "everything matches".
    assert lb.match_burned([_a("185.195.232.168", f"x{i}") for i in range(5)], set()) == []


def test_a_typo_of_a_real_user_never_reaches_the_burn_list():
    """The whole safety argument for a threshold of one.

    A user mistyping their own name produces a source that tried exactly one
    non-existent name — which never becomes an offender, so the typo is never
    burned, so the user is never blocked for repeating it."""
    attempts = [_a("146.70.119.90", "burkhrad"), _a("146.70.119.90", "burkhard")]
    offenders = lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3)
    assert offenders == []

    # Nothing to burn -> the name cannot be on the list -> a later typo from the
    # same source matches nothing.
    burnable = {n for o in offenders for n in o["unknown_users_all"]}
    assert "burkhrad" not in burnable
    assert lb.match_burned([_a("146.70.119.90", "burkhrad")], burnable) == []


def test_offenders_expose_every_name_for_burning():
    # The display list is capped at 10; burning must use the full set or most of
    # an attacker's word list would silently stay unburned.
    attempts = [_a("185.195.232.168", f"ghost{i:03d}") for i in range(50)]
    o = lb.evaluate(attempts, KNOWN, min_unknown_users=3, min_attempts=3)[0]
    assert len(o["unknown_users"]) == 10
    assert len(o["unknown_users_all"]) == 50


def test_declaring_a_burned_name_real_disarms_it(monkeypatch):
    """Attacker word lists are full of plausible real names. When one of them
    turns out to be an actual colleague, fixing the directory has to disarm the
    burn list too — otherwise the operator does the right thing and the person
    keeps getting blocked."""
    class _Rows:
        def all(self):
            return [("burkhard",), ("admin_support",)]

    class _DB:
        async def execute(self, *_a, **_kw):
            return _Rows()

    # Without the directory, the harvested real name still fires ...
    bare = asyncio.run(lb.active_burned(_DB()))
    assert "burkhard" in bare

    # ... and with it, only the invented one is left armed.
    armed = asyncio.run(lb.active_burned(_DB(), {"burkhard"}))
    assert armed == {"admin_support"}
    assert lb.match_burned([_a("185.195.232.168", "burkhard")], armed) == []


def test_burned_comment_names_the_evidence():
    hit = lb.match_burned([_a("185.195.232.168", "admin_support")], BURNED)[0]
    text = lb.burned_block_comment(hit)
    assert "admin_support" in text


def test_alert_survives_hostile_usernames(monkeypatch):
    """The alert is the only live signal this rule produces, and everything about
    it fails quietly: the sender sits in a broad ``except`` that turns any
    mistake into a log line. This asserts the message is actually handed to a
    channel (a missing import once made it never leave the function) and that
    attacker-chosen usernames cannot break it — an unescaped "<" gets the whole
    message rejected by Telegram's HTML parser."""
    from app import agent, notifications

    sent = {}

    async def fake_notify(text_html, title=None, event=None):
        sent["text"] = text_html
        sent["event"] = event
        return {"channels": ["telegram"], "errors": {}, "skipped": []}

    # Patched on the source module: the sender imports it at call time.
    monkeypatch.setattr(notifications, "notify", fake_notify)
    asyncio.run(agent._notify_invalid_user_blocks([{
        "ip": "146.70.119.90", "country": "GB",
        "unknown_user_count": 3, "attempts": 7,
        "unknown_users": ["<script>x</script>", "a&b", "x>y"],
    }], 15))

    # Declared to the routing matrix — without an event the alert would fall back
    # to "deliver everywhere" and could not be routed by an operator.
    assert sent["event"] == "invalid_user_block"

    text = sent["text"]
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert "a&amp;b" in text
    # <br> is not in Telegram's HTML subset and gets the message rejected.
    assert "<br>" not in text and "\n" in text
    # The evidence itself must still be readable.
    assert "146.70.119.90" in text and "<b>" in text


def test_summarise_without_a_directory_finds_nothing():
    # Mirrors the live interlock: no usable directory means no judgement, so a
    # backtest must not present an empty result as a clean one either.
    attempts = [_a("185.195.232.168", f"ghost{i}") for i in range(10)]
    out = lb.summarise(attempts, None, min_unknown_users=3, min_attempts=3)
    assert out["offenders"] == []
    assert out["attempts_total"] == 10
    assert out["directory_size"] == 0
