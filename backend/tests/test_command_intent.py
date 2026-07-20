"""The keyword intent parser routes chat messages to a command or to the LLM.
Includes the regression for the bug where an internal-IP question was hijacked
into an OSINT lookup (and rejected as 'not public')."""
import pytest

from app.command_service import _keyword_intent


def test_block_ip():
    r = _keyword_intent("blockiere 1.2.3.4")
    assert r["tool"] == "block_ip" and r["args"]["ip"] == "1.2.3.4"


def test_block_domain():
    r = _keyword_intent("sperre boese.example")
    assert r["tool"] == "block_domain"


def test_isolate():
    assert _keyword_intent("isoliere PC-12345")["tool"] == "isolate_endpoint"


def test_quarantine():
    assert _keyword_intent("zeig die Quarantäne")["tool"] == "quarantine_list"


def test_stats_report():
    assert _keyword_intent("Statistik-Report der letzten 7 Tage")["tool"] == "stats_report"


def test_help():
    assert _keyword_intent("hilfe")["tool"] == "help"


def test_explicit_osint():
    r = _keyword_intent("osint zu 8.8.8.8")
    assert r["tool"] == "osint" and r["args"]["value"] == "8.8.8.8"


def test_bare_ip_is_osint():
    assert _keyword_intent("8.8.8.8")["tool"] == "osint"


@pytest.mark.parametrize("msg", [
    "zeige mir die letzten verbindungen zu 10.0.1.5 in den letzten 24 stunden",
    "welche verbindungen gingen gestern zu interner IP 172.16.16.20",
])
def test_ip_question_is_not_osint(msg):
    # Regression: a question that merely mentions an IP must NOT become osint
    # (which would reject the private IP) — it falls through to the LLM chat.
    assert _keyword_intent(msg)["tool"] == "unknown"
