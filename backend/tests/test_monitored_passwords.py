"""Recognising a real password in an attack.

Two things must hold, and they pull in opposite directions. The match has to be
reliable enough to be worth waking someone for, and the plaintext must never be
written down — not in the table, not in the captured row, not in the
notification. The tests below pin both, plus the severity split that decides how
loud the alarm gets.
"""
import asyncio

import pytest

from app import monitored_passwords as mp


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalars(self):
        return self

    def all(self):
        return self._value if isinstance(self._value, list) else []


class _FakeDB:
    """Only what the module actually touches: one select, and an update it
    does not read back."""

    def __init__(self, row=None):
        self.row = row
        self.executed = []

    async def execute(self, stmt, *a, **kw):
        self.executed.append(stmt)
        # The first execute in evaluate() is the fingerprint lookup; the second
        # is the hit-counter update, whose result is never inspected.
        if len(self.executed) == 1:
            return _FakeResult(self.row)
        return _FakeResult(None)

    async def commit(self):
        pass


class _Entry:
    def __init__(self, fingerprint, label="Domain admin", entry_id=7):
        self.id = entry_id
        self.label = label
        self.fingerprint = fingerprint
        self.hit_count = 0
        self.active = True


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    """A deterministic master key, so fingerprints are stable in tests without
    depending on whatever key the machine happens to have."""
    monkeypatch.setattr(mp, "derive_subkey", lambda info: b"test-key-material")


# --- the fingerprint ---------------------------------------------------------

def test_the_same_password_always_fingerprints_the_same_way():
    assert mp.fingerprint("hunter2!") == mp.fingerprint("hunter2!")


def test_different_passwords_fingerprint_differently():
    assert mp.fingerprint("hunter2!") != mp.fingerprint("hunter3!")


def test_the_fingerprint_does_not_contain_the_password():
    """Stating the obvious, because the whole feature rests on it."""
    fp = mp.fingerprint("SuperSecret123")
    assert "SuperSecret123" not in fp
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)


def test_the_fingerprint_is_keyed_not_a_bare_hash(monkeypatch):
    """A plain SHA-256 of a real password would be crackable from the table
    alone. Changing the key must change every fingerprint."""
    import hashlib
    a = mp.fingerprint("pw12345")
    monkeypatch.setattr(mp, "derive_subkey", lambda info: b"a-different-key")
    assert mp.fingerprint("pw12345") != a
    assert a != hashlib.sha256(b"pw12345").hexdigest()


def test_without_a_key_there_is_no_fingerprint(monkeypatch):
    """No key must mean "cannot run", never a silent downgrade to an unkeyed
    hash — that would put crackable real passwords in the database."""
    monkeypatch.setattr(mp, "derive_subkey", lambda info: b"")
    assert mp.fingerprint("pw12345") is None
    assert mp.available() is False


# --- registration ------------------------------------------------------------

def test_registration_refuses_a_password_too_short_to_be_real():
    """Registering "abc" would collide with things attackers type by chance and
    turn the alarm into noise."""
    with pytest.raises(mp.MonitoredPasswordError):
        asyncio.run(mp.add(_FakeDB(), "label", "abc"))


def test_registration_requires_a_label():
    with pytest.raises(mp.MonitoredPasswordError):
        asyncio.run(mp.add(_FakeDB(), "  ", "a-long-enough-password"))


def test_registration_refuses_when_no_key_is_available(monkeypatch):
    monkeypatch.setattr(mp, "derive_subkey", lambda info: b"")
    with pytest.raises(mp.MonitoredPasswordError):
        asyncio.run(mp.add(_FakeDB(), "label", "a-long-enough-password"))


def test_the_serialized_entry_never_carries_the_fingerprint():
    """The fingerprint is the one field that would let someone test guesses
    offline, so it must not leave the backend."""
    row = _Entry(mp.fingerprint("pw123456"))
    row.created_by, row.created_at, row.last_hit_at = "admin", None, None
    out = mp.serialize(row)
    assert "fingerprint" not in out
    assert out["label"] == "Domain admin"


# --- matching and severity ---------------------------------------------------

def _evaluate(password, username, known, stored="RealPassword!23"):
    entry = _Entry(mp.fingerprint(stored))
    db = _FakeDB(entry if mp.fingerprint(password) == entry.fingerprint else None)

    async def fake_known(_db):
        return known
    import app.login_bruteforce as lb
    orig_known, orig_norm = lb.known_users, lb.normalise
    lb.known_users = fake_known
    try:
        return asyncio.run(mp.evaluate(db, username, password))
    finally:
        lb.known_users, lb.normalise = orig_known, orig_norm


def test_an_ordinary_guess_is_not_an_alarm():
    assert _evaluate("admin123", "admin", {"alice"}) is None


def test_a_real_password_with_an_unknown_username_is_high():
    v = _evaluate("RealPassword!23", "nosuchuser", {"alice", "bob"})
    assert v["severity"] == "high"
    assert v["label"] == "Domain admin"


def test_a_real_password_with_a_real_username_is_critical():
    """Not a leaked password any more — a working login in someone's hands."""
    v = _evaluate("RealPassword!23", "alice", {"alice", "bob"})
    assert v["severity"] == "critical"
    assert v["username_real"] is True


def test_an_unjudgeable_directory_does_not_silently_downgrade_to_high():
    """known_users() returns None when it cannot judge. That must not be read as
    "the username is fake" — but guessing downward is the safe direction, so the
    alarm still fires, and the message says the username is unconfirmed."""
    v = _evaluate("RealPassword!23", "alice", None)
    assert v["severity"] == "high"
    assert v["username_real"] is None
    assert "could not be confirmed" in mp.alarm_text(v, "alice", "1.2.3.4")


def test_no_password_submitted_is_not_a_match():
    assert asyncio.run(mp.match(_FakeDB(), None)) is None
    assert asyncio.run(mp.match(_FakeDB(), "")) is None


# --- the alarm text ----------------------------------------------------------

def test_the_alarm_never_carries_the_password():
    """Telegram and Teams are third parties with their own retention. The label
    identifies which credential leaked; the credential itself stays here."""
    v = {"severity": "critical", "entry_id": 1, "label": "Domain admin",
         "username_real": True}
    text = mp.alarm_text(v, "alice", "203.0.113.9")
    assert "RealPassword!23" not in text
    assert "not</b> stored" in text or "not stored" in text
    assert "Domain admin" in text and "alice" in text


def test_the_critical_alarm_says_what_to_do():
    v = {"severity": "critical", "entry_id": 1, "label": "VPN", "username_real": True}
    assert "rotate" in mp.alarm_text(v, "alice", "1.2.3.4").lower()


def test_hostile_input_cannot_inject_markup_into_the_alarm():
    """Username and label reach the notification from an attacker-controlled
    submission and an operator field respectively."""
    v = {"severity": "high", "entry_id": 1, "label": "<b>x</b>", "username_real": False}
    text = mp.alarm_text(v, "<script>alert(1)</script>", "1.2.3.4")
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
