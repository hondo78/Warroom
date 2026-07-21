"""User auth: password hashing, signed session cookies, and roles.

Opt-in (``settings.auth_enabled``). No external deps — pbkdf2 for passwords
(stdlib) and an HMAC-signed stateless cookie for sessions, keyed off the same
persisted secret as app/crypto.py.

Roles (increasing privilege): viewer < analyst < admin.
- viewer  : read-only (no POST/PUT/PATCH/DELETE)
- analyst : read + actions (block, isolate, settings, …)
- admin   : everything + user management + audit log
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time

from starlette.requests import Request

logger = logging.getLogger(__name__)

COOKIE_NAME = "warroom_session"
SESSION_TTL = 12 * 3600           # seconds
_PBKDF2_ROUNDS = 200_000

ROLE_ORDER = {"viewer": 0, "analyst": 1, "admin": 2}
ROLES = tuple(ROLE_ORDER)


# --- password hashing --------------------------------------------------------

def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, rounds, salt_b64, dk_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        test = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, int(rounds))
        return hmac.compare_digest(test, expected)
    except Exception:
        return False


# --- signed session cookie ---------------------------------------------------

def _signing_key() -> bytes:
    from app.crypto import _load_or_create_key
    base = _load_or_create_key() or b"warroom-insecure-fallback"
    return hashlib.sha256(b"warroom-auth|" + base).digest()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_session(uid: int, username: str, role: str) -> str:
    payload = {"uid": uid, "u": username, "r": role, "exp": int(time.time()) + SESSION_TTL}
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(_signing_key(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64u(sig)}"


def read_session(token: str) -> dict | None:
    try:
        body, sig = token.split(".")
        expected = hmac.new(_signing_key(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64u_dec(sig)):
            return None
        payload = json.loads(_b64u_dec(body))
        if int(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except Exception:
        return None


def get_current_user(request: Request) -> dict | None:
    """The authenticated user from the session cookie, or None."""
    token = request.cookies.get(COOKIE_NAME)
    return read_session(token) if token else None


def has_role(user: dict | None, minimum: str) -> bool:
    if not user:
        return False
    return ROLE_ORDER.get(user.get("r"), -1) >= ROLE_ORDER.get(minimum, 99)


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True,
        samesite="lax", path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")
