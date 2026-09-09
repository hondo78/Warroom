"""Routing alerts to channels.

The matrix decides which alarm reaches which channel. Two properties matter more
than the routing itself, and both are about failing in the safe direction: a
broken or missing configuration must never mute an alert, and switching the
feature on must not change what anyone receives until they say so.
"""
import asyncio
import json

import pytest

from app import notification_matrix as nm


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "notification_matrix", "", raising=False)


def _set(monkeypatch, value):
    from app.config import settings
    monkeypatch.setattr(settings, "notification_matrix", value, raising=False)


# --- defaults ----------------------------------------------------------------

def test_every_declared_event_has_a_row():
    m = nm.default_matrix()
    assert set(m) == set(nm.EVENTS)
    for ev, row in m.items():
        assert set(row) == set(nm.CHANNELS), ev


def test_defaults_send_most_events_everywhere():
    m = nm.default_matrix()
    assert m["monitored_password"] == {"telegram": True, "teams": True}
    assert m["honeypot_access"] == {"telegram": True, "teams": True}


def test_defaults_preserve_the_two_channels_that_were_hardwired_before():
    """Switching the matrix on must not change what anyone receives. These two
    were pinned to one channel in code before the matrix existed."""
    m = nm.default_matrix()
    # posted straight to telegram_client, bypassing the fan-out
    assert m["user_endangered"] == {"telegram": True, "teams": False}
    # Teams got the card; Telegram gets the interactive approval prompt instead
    assert m["m365_login"] == {"telegram": False, "teams": True}


# --- overrides ---------------------------------------------------------------

def test_an_override_switches_one_channel_off(monkeypatch):
    _set(monkeypatch, json.dumps({"honeypot_access": {"telegram": False}}))
    assert nm.channel_enabled("honeypot_access", "telegram") is False
    # and leaves the other channel of the same event alone
    assert nm.channel_enabled("honeypot_access", "teams") is True


def test_an_override_only_changes_what_it_names(monkeypatch):
    _set(monkeypatch, json.dumps({"honeypot_access": {"telegram": False}}))
    assert nm.channel_enabled("monitored_password", "telegram") is True


def test_junk_entries_are_ignored_not_trusted(monkeypatch):
    _set(monkeypatch, json.dumps({
        "honeypot_access": {"telegram": False},
        "no_such_event": {"telegram": False},
        "conn_anomaly": {"carrier_pigeon": False},
    }))
    eff = nm.effective_matrix()
    assert "no_such_event" not in eff
    assert set(eff["conn_anomaly"]) == set(nm.CHANNELS)
    assert nm.channel_enabled("honeypot_access", "telegram") is False


def test_malformed_json_falls_back_to_defaults_instead_of_muting_everything(monkeypatch):
    """A typo in a settings field must not be able to silence every alert in the
    system. Defaults win over a broken override."""
    _set(monkeypatch, "{not json at all")
    assert nm.effective_matrix() == nm.default_matrix()
    assert nm.channel_enabled("monitored_password", "telegram") is True


def test_a_non_object_value_is_ignored(monkeypatch):
    _set(monkeypatch, json.dumps(["telegram"]))
    assert nm.effective_matrix() == nm.default_matrix()


# --- the safe direction ------------------------------------------------------

def test_an_undeclared_event_is_delivered_everywhere():
    """A new alarm that forgets to declare itself must be too loud, never
    silently dropped: a missed alert costs far more than a duplicate one."""
    assert nm.channel_enabled("brand_new_alarm", "telegram") is True
    assert nm.channel_enabled("brand_new_alarm", "teams") is True


def test_no_event_at_all_is_delivered_everywhere():
    assert nm.channel_enabled(None, "telegram") is True
    assert nm.channel_enabled("", "teams") is True


def test_an_unknown_channel_is_never_blocked_by_the_matrix():
    """A channel added later must work before someone edits the matrix."""
    assert nm.channel_enabled("honeypot_access", "signal") is True


def test_switching_an_event_off_everywhere_is_possible(monkeypatch):
    """The operator is allowed to mute something completely — the fail-open
    rules protect against accidents, not against intent."""
    _set(monkeypatch, json.dumps({"honeypot_access": {"telegram": False, "teams": False}}))
    assert nm.channel_enabled("honeypot_access", "telegram") is False
    assert nm.channel_enabled("honeypot_access", "teams") is False


# --- the fan-out honours it --------------------------------------------------

def test_notify_skips_the_muted_channel(monkeypatch):
    from app import notifications
    from app.config import settings

    _set(monkeypatch, json.dumps({"honeypot_access": {"telegram": False, "teams": False}}))
    monkeypatch.setattr(settings, "telegram_enabled", True, raising=False)
    monkeypatch.setattr(settings, "telegram_bot_token", "t", raising=False)
    monkeypatch.setattr(settings, "telegram_chat_id", "c", raising=False)
    monkeypatch.setattr(settings, "teams_incoming_webhook", "https://example/x", raising=False)

    sent = []
    async def boom(*a, **kw):
        sent.append(a)
        raise AssertionError("a muted channel must not be contacted")
    monkeypatch.setattr(notifications, "send_teams", boom)

    out = asyncio.run(notifications.notify("<b>x</b>", title="t", event="honeypot_access"))
    assert out["channels"] == []
    assert sorted(out["skipped"]) == ["teams", "telegram"]
    assert sent == []


def test_notify_without_an_event_still_reaches_teams(monkeypatch):
    """Legacy call sites that pass no event must keep working."""
    from app import notifications
    from app.config import settings

    monkeypatch.setattr(settings, "telegram_enabled", False, raising=False)
    monkeypatch.setattr(settings, "teams_incoming_webhook", "https://example/x", raising=False)

    calls = []
    async def ok(text, title=None):
        calls.append(title)
    monkeypatch.setattr(notifications, "send_teams", ok)

    out = asyncio.run(notifications.notify("<b>x</b>", title="t"))
    assert out["channels"] == ["teams"]
    assert out["skipped"] == []
    assert calls == ["t"]


# --- the UI payload ----------------------------------------------------------

def test_describe_exposes_every_event_with_a_label():
    d = nm.describe()
    assert d["channels"] == list(nm.CHANNELS)
    assert {e["key"] for e in d["events"]} == set(nm.EVENTS)
    assert all(e["label"] for e in d["events"])
    assert set(d["defaults"]) == set(nm.EVENTS)
    assert set(d["effective"]) == set(nm.EVENTS)
