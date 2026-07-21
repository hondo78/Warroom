"""Password hashing, signed sessions and role checks (app.auth)."""
from app.auth import (hash_password, verify_password, make_session, read_session,
                      has_role, ROLE_ORDER)


def test_password_roundtrip():
    h = hash_password("s3cret!")
    assert h != "s3cret!"
    assert verify_password("s3cret!", h)
    assert not verify_password("wrong", h)


def test_password_unique_salt():
    assert hash_password("x") != hash_password("x")   # random salt


def test_session_roundtrip():
    p = read_session(make_session(7, "alice", "analyst"))
    assert p and p["uid"] == 7 and p["u"] == "alice" and p["r"] == "analyst"


def test_session_tamper_rejected():
    body, sig = make_session(1, "bob", "admin").split(".")
    tampered = body[:-2] + ("aa" if not body.endswith("aa") else "bb") + "." + sig
    assert read_session(tampered) is None


def test_session_expired_rejected(monkeypatch):
    import app.auth as a
    tok = make_session(1, "bob", "viewer")
    real = a.time.time()
    monkeypatch.setattr(a.time, "time", lambda: real + 13 * 3600)   # TTL is 12h
    assert read_session(tok) is None


def test_roles():
    assert ROLE_ORDER["viewer"] < ROLE_ORDER["analyst"] < ROLE_ORDER["admin"]
    assert has_role({"r": "admin"}, "analyst")
    assert has_role({"r": "analyst"}, "analyst")
    assert not has_role({"r": "viewer"}, "analyst")
    assert not has_role(None, "viewer")
