"""Secret encryption-at-rest round-trips and stays backward-compatible with
legacy plaintext values."""
import os

from cryptography.fernet import Fernet


def _fresh_crypto():
    # Configure a key via env and reset the module's cached Fernet.
    os.environ["WARROOM_SECRET_KEY"] = Fernet.generate_key().decode()
    import app.crypto as c
    c._fernet = None
    return c


def test_roundtrip():
    c = _fresh_crypto()
    token = c.encrypt("s3cr3t-value")
    assert c.is_encrypted(token)
    assert token != "s3cr3t-value"
    assert c.decrypt(token) == "s3cr3t-value"


def test_plaintext_passthrough():
    c = _fresh_crypto()
    # legacy plaintext (no enc:v1: marker) is returned unchanged
    assert c.decrypt("legacy-plain") == "legacy-plain"


def test_empty_passthrough():
    c = _fresh_crypto()
    assert c.encrypt("") == ""
    assert c.decrypt("") == ""


def test_double_encrypt_is_idempotent():
    c = _fresh_crypto()
    once = c.encrypt("abc")
    assert c.encrypt(once) == once  # already encrypted → unchanged


def test_wrong_key_returns_empty():
    c = _fresh_crypto()
    token = c.encrypt("value")
    # rotate the key: the old token can no longer be decrypted
    os.environ["WARROOM_SECRET_KEY"] = Fernet.generate_key().decode()
    c._fernet = None
    assert c.decrypt(token) == ""
