"""The two copies of the Kali guard must not drift.

The guard exists twice: `backend/app/kali_client.py` decides before sending, and
`kali/box/kali_api.py` decides again on the box, which is the authoritative one.
The box ships standalone and cannot import the backend, so the copies are kept
in step by hand — and they have already drifted once. Both the argv-vs-raw-string
hole and the `@server` / `--resolve` bypasses had to be fixed twice, and a fix
applied to only one side leaves the authoritative side open while the code that
gets read looks correct.

These tests do not remove the duplication. They make drift fail loudly the next
time somebody edits one copy, which is the part that actually goes wrong.
"""
import pathlib
import re

BACKEND = pathlib.Path(__file__).resolve().parents[2] / "backend/app/kali_client.py"
BOX = pathlib.Path(__file__).resolve().parents[2] / "kali/box/kali_api.py"


def _literal_set(src: str, name: str) -> set[str]:
    m = re.search(rf"^{name}\s*[:=].*?[=]\s*[\{{\(\[](.*?)[\}}\)\]]\s*$",
                  src, re.S | re.M)
    assert m, f"{name} not found"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_both_files_exist():
    assert BACKEND.exists() and BOX.exists()


def test_the_allowed_binaries_match():
    a, b = BACKEND.read_text(), BOX.read_text()
    assert _literal_set(a, "ALLOWED_BINARIES") == _literal_set(b, "ALLOWED_BINARIES")


def test_the_dangerous_patterns_match():
    """The list that decides what is a reverse shell. A pattern added on one
    side only is a hole on the other."""
    a, b = BACKEND.read_text(), BOX.read_text()
    assert _literal_set(a, "_DANGEROUS") == _literal_set(b, "_DANGEROUS")


def test_both_copies_understand_hosts_hidden_inside_a_token():
    """`dig @1.2.3.4` and `curl --resolve host:port:ip` hide the real
    destination in a token that parses as nothing. Both sides must extract it,
    or the backend refuses what the box would have allowed — or worse."""
    for src in (BACKEND.read_text(), BOX.read_text()):
        assert "_host_candidates" in src
        assert 'lstrip("@")' in src


def test_both_copies_fail_closed_on_an_unrecognised_target():
    """A command whose destination cannot be parsed must be refused, not waved
    through because the loop found nothing to check."""
    for src in (BACKEND.read_text(), BOX.read_text()):
        assert "no target recognised" in src or "not in the allowlist" in src


def test_the_nmap_reasoning_matches():
    """nmap_reason() is what makes a scan honest over Tor. Its thresholds must
    be the same on both sides, or the backend approves a scan the box rejects."""
    a, b = BACKEND.read_text(), BOX.read_text()
    for const in ("MAX_NMAP_PORTS",):
        va = re.search(rf"{const}\s*=\s*(\d+)", a)
        vb = re.search(rf"{const}\s*=\s*(\d+)", b)
        assert va and vb and va.group(1) == vb.group(1), const
