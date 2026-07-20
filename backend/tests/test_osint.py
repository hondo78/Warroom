"""OSINT pure helpers: public-IP detection, distinct-public capping (used to
bound enrichment), and the risk summary shape."""
from app.osint import is_public, _distinct_public, _risk_summary


def test_is_public():
    assert is_public("8.8.8.8")
    assert not is_public("10.0.0.5")
    assert not is_public("192.168.1.1")
    assert not is_public("172.16.16.20")
    assert not is_public("127.0.0.1")
    assert not is_public("not-an-ip")


def test_distinct_public_dedups_and_filters():
    ips = ["8.8.8.8", "8.8.8.8", "10.0.0.5", "1.1.1.1", "192.168.1.1", "not-an-ip"]
    out = _distinct_public(ips, cap=10)
    assert out == ["8.8.8.8", "1.1.1.1"]


def test_distinct_public_cap():
    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    assert _distinct_public(ips, cap=2) == ["8.8.8.8", "1.1.1.1"]


def test_risk_summary_shape():
    payload = {
        "abuseipdb": {"abuse_score": 80},
        "virustotal": {"malicious": 3},
        "greynoise": {"classification": "malicious"},
        "intelix": {"security_category": "botnet"},
        "ipinfo": {"country": "US", "org": "AS1 Example"},
    }
    s = _risk_summary(payload)
    assert s["abuse_score"] == 80
    assert s["vt_malicious"] == 3
    assert s["greynoise"] == "malicious"
    assert s["intelix_category"] == "botnet"
    assert s["country"] == "US"


def test_risk_summary_handles_missing():
    s = _risk_summary({})
    assert s["abuse_score"] is None and s["vt_malicious"] is None
