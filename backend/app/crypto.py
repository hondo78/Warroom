"""Encryption-at-rest for secret settings (API keys, tokens, passwords).

Secret values in ``app_settings`` were stored in plaintext, so a DB dump/backup
leaked every credential. They are now Fernet-encrypted at rest with an
``enc:v1:`` marker. Decryption is transparent and backward-compatible: a value
without the marker is returned as-is (legacy plaintext), so the app keeps working
before/through the one-time migration (``encrypt_existing_secrets``).

The key lives OUTSIDE the database (that is the whole point):
  1. env ``WARROOM_SECRET_KEY`` (a base64 Fernet key) if set, else
  2. a key file (``WARROOM_SECRET_KEY_FILE``, default ``/app/data/secret.key``)
     — auto-generated on first boot and persisted via a Docker volume.
Back up that key/file: losing it makes the stored secrets unrecoverable (you'd
just re-enter them in the admin UI).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_PREFIX = "enc:v1:"
_KEY_FILE = os.environ.get("WARROOM_SECRET_KEY_FILE", "/app/data/secret.key")
_fernet: Fernet | None | bool = None  # None = uninitialised, False = disabled


def _load_or_create_key() -> bytes:
    env = (os.environ.get("WARROOM_SECRET_KEY") or "").strip()
    if env:
        return env.encode()
    p = Path(_KEY_FILE)
    try:
        if p.exists():
            return p.read_text().strip().encode()
        p.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        p.write_bytes(key)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        logger.warning(
            f"Generated a new secret-encryption key at {p}. BACK THIS UP — "
            "losing it makes stored secrets unrecoverable."
        )
        return key
    except Exception as e:
        logger.error(f"secret-key load/create failed ({e}); secrets stay UNENCRYPTED at rest")
        return b""


def _get_fernet() -> Fernet | None:
    global _fernet
    if _fernet is None:
        key = _load_or_create_key()
        try:
            _fernet = Fernet(key) if key else False
        except Exception as e:
            logger.error(f"invalid secret key ({e}); secrets stay UNENCRYPTED at rest")
            _fernet = False
    return _fernet or None


def encryption_available() -> bool:
    return _get_fernet() is not None


def is_encrypted(value) -> bool:
    return isinstance(value, str) and value.startswith(_PREFIX)


def encrypt(plaintext: str) -> str:
    """Return the ``enc:v1:`` ciphertext for a plaintext secret. Empty values and
    already-encrypted values pass through unchanged; if no key is available the
    plaintext is returned (so nothing breaks)."""
    if plaintext is None or plaintext == "" or is_encrypted(plaintext):
        return plaintext or ""
    f = _get_fernet()
    if f is None:
        return plaintext
    return _PREFIX + f.encrypt(plaintext.encode()).decode()


def decrypt(value: str) -> str:
    """Return the plaintext for a stored value. Values without the marker are
    returned unchanged (legacy plaintext). On a decryption failure (wrong/rotated
    key) returns '' and logs — the admin can re-enter the secret."""
    if not is_encrypted(value):
        return value or ""
    f = _get_fernet()
    if f is None:
        logger.error("encrypted secret present but no key available")
        return ""
    try:
        return f.decrypt(value[len(_PREFIX):].encode()).decode()
    except InvalidToken:
        logger.error("secret decryption failed (wrong or rotated key?)")
        return ""
