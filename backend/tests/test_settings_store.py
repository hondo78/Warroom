"""Setting value coercion (DB text <-> typed values)."""
from app.settings_store import _coerce, _to_str, MANAGED_KEYS, SECRET_KEYS


def test_to_str():
    assert _to_str(True) == "true"
    assert _to_str(False) == "false"
    assert _to_str(None) == ""
    assert _to_str(42) == "42"
    assert _to_str("x") == "x"


def test_coerce_bool():
    # pick any bool-typed managed key
    key = next(k for k, t in MANAGED_KEYS.items() if t is bool)
    assert _coerce(key, "true") is True
    assert _coerce(key, "1") is True
    assert _coerce(key, "false") is False
    assert _coerce(key, "off") is False


def test_coerce_int():
    key = next(k for k, t in MANAGED_KEYS.items() if t is int)
    assert _coerce(key, "123") == 123
    assert _coerce(key, "notanint") is None


def test_secret_keys_are_managed():
    # every secret key must also be a managed key, or it can't be saved/loaded
    assert SECRET_KEYS.issubset(set(MANAGED_KEYS))
