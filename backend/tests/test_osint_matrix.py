"""OSINT provider matrix: which source may be asked from where.

One global on/off per provider was never enough. The decoy login sees dozens of
fresh addresses an hour and would drain a daily quota by lunchtime; an analyst
opening a dossier wants everything available. Same provider, opposite answer,
decided only by who is asking.

The failure that matters here is silent: a matrix that resolves wrongly does not
crash, it just spends quota nobody authorised — or returns nothing and looks
like a provider outage.
"""

import json

from app import osint
from app.config import settings


def _set_matrix(monkeypatch, value):
    monkeypatch.setattr(settings, "osint_provider_matrix",
                        value if isinstance(value, str) else json.dumps(value))


def test_defaults_keep_the_metered_providers_away_from_the_decoy(monkeypatch):
    # The honeypot is the highest-volume context by an order of magnitude, so
    # nothing metered may run there unattended.
    _set_matrix(monkeypatch, "")
    for p in osint.PAID_PROVIDERS:
        assert not osint.provider_enabled(p, "honeypot"), p


def test_defaults_give_a_human_everything_but_the_scarce_credit(monkeypatch):
    _set_matrix(monkeypatch, "")
    for p in ("abuseipdb", "virustotal", "greynoise", "ipinfo", "intelix"):
        assert osint.provider_enabled(p, "manual"), p
    # Shodan costs a credit per call and stays an explicit decision.
    assert not osint.provider_enabled("shodan", "manual")


def test_free_providers_run_everywhere_by_default(monkeypatch):
    _set_matrix(monkeypatch, "")
    for ctx in osint.CONTEXTS:
        for p in osint.FREE_PROVIDERS:
            assert osint.provider_enabled(p, ctx), (ctx, p)


def test_an_override_only_changes_what_it_names(monkeypatch):
    _set_matrix(monkeypatch, {"honeypot": {"abuseipdb": True}})
    assert osint.provider_enabled("abuseipdb", "honeypot")
    # Everything else in that row keeps its default.
    assert not osint.provider_enabled("virustotal", "honeypot")
    # And other contexts are untouched.
    assert osint.provider_enabled("virustotal", "manual")


def test_an_override_can_switch_a_provider_off(monkeypatch):
    _set_matrix(monkeypatch, {"manual": {"virustotal": False}})
    assert not osint.provider_enabled("virustotal", "manual")


def test_malformed_json_falls_back_to_defaults_instead_of_breaking_osint(monkeypatch):
    # A typo in a settings field must not be able to stop every lookup in the
    # system — the cost of ignoring it is a wrong-but-safe default, the cost of
    # raising is no OSINT at all.
    _set_matrix(monkeypatch, "{not json at all")
    assert osint.provider_enabled("abuseipdb", "manual")
    assert not osint.provider_enabled("abuseipdb", "honeypot")


def test_junk_entries_are_ignored_not_trusted(monkeypatch):
    _set_matrix(monkeypatch, {
        "nonexistent_context": {"abuseipdb": True},
        "manual": {"nonexistent_provider": True, "virustotal": False},
    })
    assert not osint.provider_enabled("virustotal", "manual")   # the valid part applies
    assert osint.provider_enabled("nonexistent_provider", "manual")  # unknown → not ours to gate


def test_an_undeclared_context_behaves_like_a_human_asked(monkeypatch):
    # A new call site that forgets to declare itself should look like the
    # permissive case, not silently return nothing and read as an outage.
    _set_matrix(monkeypatch, "")
    assert osint.provider_enabled("abuseipdb", "a_context_nobody_defined")
    assert osint.provider_enabled("abuseipdb", None)


def test_effective_matrix_covers_every_context_and_provider(monkeypatch):
    _set_matrix(monkeypatch, "")
    m = osint.effective_matrix()
    assert set(m) == set(osint.CONTEXTS)
    for ctx, row in m.items():
        for p in osint.PROVIDERS:
            assert p in row, (ctx, p)


def test_a_cached_entry_from_before_a_change_is_not_served(monkeypatch):
    # Switching a provider on must take effect now, not in an hour: the cached
    # payload still carries the "disabled" sentinel from the run that happened
    # while it was off.
    # Shodan is off everywhere by default; switch it on for one context only.
    _set_matrix(monkeypatch, {"manual": {"shodan": True}})
    stale = {"shodan": {"skipped": True, "reason": "disabled_by_matrix"}}
    assert osint._cache_is_stale_for(stale, ("shodan",), "manual")
    # A context where it is still switched off has nothing to gain from a
    # re-run, so the very same entry stays perfectly serviceable there.
    assert not osint._cache_is_stale_for(stale, ("shodan",), "agent")
    # And a real payload is never stale.
    fresh = {"shodan": {"ports": [22, 80]}}
    assert not osint._cache_is_stale_for(fresh, ("shodan",), "manual")
