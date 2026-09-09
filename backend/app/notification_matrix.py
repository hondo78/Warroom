"""Which alert goes out over which channel.

Warroom raises a dozen different kinds of alarm, and they are not equally
interesting to the same people. A honeypot access every hour is worth a Teams
card and nothing more; a real credential being replayed should reach a phone.
This module is the single place that decides, so the answer does not end up
scattered across a dozen call sites as hard-wired channel choices — which is
exactly what it looked like before.

Shaped after :mod:`app.osint`'s provider matrix, deliberately: an operator who
has understood one has understood the other.

Two rules make it safe to leave switched on:

* **The defaults reproduce the behaviour that existed before this module.**
  Turning the matrix on changes nothing until someone edits it.
* **An unknown event is delivered everywhere.** A new alarm that forgets to
  declare itself must be too loud, never silently muted — the failure mode of
  a missed alert is far worse than a duplicate one.
"""
from __future__ import annotations

import json
import logging

from app.config import settings

logger = logging.getLogger(__name__)

# The delivery channels. Interactive Telegram approval prompts are NOT governed
# here: they carry buttons and are part of the approval workflow, not a
# notification. Muting those would break approvals, not just quieten them.
CHANNELS: tuple[str, ...] = ("telegram", "teams")

# Every alarm Warroom can raise, with the operator-facing label the admin UI
# shows. The key is what call sites pass as ``event`` and is part of the stored
# settings value, so keys are stable once shipped.
EVENTS: dict[str, str] = {
    "agent_burst":         "Agent · Block-Burst",
    "invalid_user_block":  "Agent · Brute-Force geblockt (ungültige Benutzernamen)",
    "user_endangered":     "Agent · Konto unter Beschuss",
    "conn_anomaly":        "Agent · C2/Exfil-Anomalie",
    "conn_triage":         "Agent · Verbindungs-Bewertung",
    "honeypot_access":     "Honeypot · Zugriff",
    "honeypot_login":      "Honeypot · Köder-Login",
    "monitored_password":  "Honeypot · Echtes Passwort verwendet",
    "host_identity":       "Netzwerk · Host-Identität geändert",
    "host_scan":           "Netzwerk · Port-Änderung",
    "ip_monitor":          "Netzwerk · IP-Überwachung",
    "m365_login":          "M365 · Login von neuem Gerät/Ort",
}

# Per-event overrides of the "everywhere" default. Only entries that differ from
# all-channels-on are listed, and each one records what it is preserving.
_DEFAULT_OVERRIDES: dict[str, dict[str, bool]] = {
    # Telegram-only before this module existed: the sweep posted straight to
    # telegram_client, bypassing the fan-out entirely.
    "user_endangered": {"telegram": True, "teams": False},
    # Teams-only by design: Telegram receives the *interactive approval prompt*
    # for this event, which is a separate mechanism. Enabling telegram here
    # would send the same finding twice.
    "m365_login": {"telegram": False, "teams": True},
}


def default_matrix() -> dict[str, dict[str, bool]]:
    """The built-in defaults, as the UI shows them."""
    return {ev: {**{c: True for c in CHANNELS}, **_DEFAULT_OVERRIDES.get(ev, {})}
            for ev in EVENTS}


def _configured_matrix() -> dict[str, dict[str, bool]]:
    """Operator overrides from the ``notification_matrix`` setting.

    Malformed JSON yields an empty override rather than an exception: a typo in
    a settings field must not be able to stop every alert in the system."""
    raw = (getattr(settings, "notification_matrix", "") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception as e:
        logger.warning(f"notification_matrix is not valid JSON, ignoring it: {e}")
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, dict[str, bool]] = {}
    for ev, row in parsed.items():
        if ev in EVENTS and isinstance(row, dict):
            out[ev] = {c: bool(v) for c, v in row.items() if c in CHANNELS}
    return out


def effective_matrix() -> dict[str, dict[str, bool]]:
    """Defaults with the operator's overrides applied — what actually sends."""
    merged = default_matrix()
    for ev, row in _configured_matrix().items():
        merged.setdefault(ev, {}).update(row)
    return merged


def channel_enabled(event: str | None, channel: str) -> bool:
    """May ``event`` be delivered over ``channel``?

    An unknown or missing event is delivered everywhere. A new alarm that
    forgets to declare itself should be too loud rather than silently dropped —
    a missed alert costs far more than a duplicate one."""
    if channel not in CHANNELS:
        return True
    if not event or event not in EVENTS:
        return True
    return bool(effective_matrix().get(event, {}).get(channel, True))


def describe() -> dict:
    """What the admin UI renders: the events, the channels, what is in effect
    and what the defaults were, so an operator can see what they changed."""
    return {
        "channels": list(CHANNELS),
        "events": [{"key": k, "label": v} for k, v in EVENTS.items()],
        "effective": effective_matrix(),
        "defaults": default_matrix(),
    }
