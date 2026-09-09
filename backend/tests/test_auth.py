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


# --- "admin role required" must not be the answer to "who are you?" -----------
# /api/auth/* is exempt from the global login check so the login stays
# reachable, which makes these endpoints the only place that can tell a
# logged-out visitor from an under-privileged one. Getting it wrong sends
# someone hunting for a permission they already hold.

class _Req:
    def __init__(self, cookies=None):
        self.cookies = cookies or {}
        self.state = type("S", (), {})()


def test_no_session_is_401_not_403():
    import pytest
    from fastapi import HTTPException
    from app.main import _require_admin

    with pytest.raises(HTTPException) as e:
        _require_admin(_Req())
    assert e.value.status_code == 401


def test_a_session_without_the_role_is_403():
    import pytest
    from fastapi import HTTPException
    from app.auth import COOKIE_NAME, make_session
    from app.main import _require_admin

    token = make_session(2, "analyst-user", "analyst")
    with pytest.raises(HTTPException) as e:
        _require_admin(_Req({COOKIE_NAME: token}))
    assert e.value.status_code == 403


def test_an_admin_session_passes():
    from app.auth import COOKIE_NAME, make_session
    from app.main import _require_admin

    user = _require_admin(_Req({COOKIE_NAME: make_session(1, "admin", "admin")}))
    assert user["u"] == "admin" and user["r"] == "admin"


# --- actor_name --------------------------------------------------------------

def test_actor_name_extracts_the_username_from_the_session_dict():
    """request.state.user is the session dict, not a name. Passing the dict
    straight into a VARCHAR audit column looks fine until auth is switched on,
    at which point every insert fails with a DataError."""
    from app.main import actor_name

    class _S:
        user = {"uid": 1, "u": "admin", "r": "admin"}

    class _R:
        state = _S()

    assert actor_name(_R()) == "admin"


def test_actor_name_falls_back_to_human_without_a_session():
    from app.main import actor_name

    class _S:
        user = None

    class _R:
        state = _S()

    assert actor_name(_R()) == "human"
    assert actor_name(object()) == "human"


def test_actor_name_always_returns_a_string_that_fits_the_column():
    """Audit columns are VARCHAR(100); a hostile or odd session value must not
    be able to break the insert it is being written into."""
    from app.main import actor_name

    class _S:
        user = {"uid": 1, "u": "x" * 500, "r": "admin"}

    class _R:
        state = _S()

    out = actor_name(_R())
    assert isinstance(out, str) and len(out) <= 100
