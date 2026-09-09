"""Recognise a *real* password turning up in an attack.

An attacker guessing at a decoy never lands on a password genuinely in use here.
If one appears, it did not come from guessing — it leaked, and the only open
questions are from where and how long ago. That makes it the single most
valuable thing the decoy can produce, and it deserves a louder alarm than the
thousands of ``admin/123456`` attempts around it.

How it works: an operator registers a password that is really in use. Warroom
stores an HMAC-SHA256 fingerprint of it, keyed with a subkey derived from the
master secret, and throws the plaintext away. Later submissions are fingerprinted
the same way and compared. The table alone reveals nothing — the key lives
outside the database (``./data/secret.key`` or ``WARROOM_SECRET_KEY``).

Two severities, because two very different things can have happened:

* ``high`` — a real password was used. The credential is out.
* ``critical`` — a real password *and* a real username. That is not a leaked
  password any more, it is a working login someone is holding.

The username check leans on the same directory the brute-force rule uses
(:func:`app.login_bruteforce.known_users`), which answers ``None`` when it cannot
judge. ``None`` is deliberately *not* treated as "invalid username": guessing
downward from critical is the safe direction, and the alarm still fires as high.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto import derive_subkey
from app.models import MonitoredPassword

logger = logging.getLogger(__name__)

# Names the purpose of the subkey. Changing this string invalidates every stored
# fingerprint, so it is fixed forever.
_KEY_INFO = b"warroom.monitored-password.v1"

# Below this, a "password" is too short to be a credential and too likely to
# collide with something an attacker types by chance. Registering "abc" would
# turn the alarm into noise, which is worse than not having it.
MIN_LENGTH = 6


class MonitoredPasswordError(RuntimeError):
    """Registration was refused. The message is safe to show an operator."""


def available() -> bool:
    """False when there is no master key, so fingerprints cannot be keyed.

    Callers must not silently degrade to an unkeyed hash: that would put a
    plain SHA-256 of real passwords in the database, which is exactly the thing
    this module exists to avoid."""
    return bool(derive_subkey(_KEY_INFO))


def fingerprint(password: str) -> str | None:
    """Keyed fingerprint of ``password``, or None when it cannot be computed."""
    key = derive_subkey(_KEY_INFO)
    if not key or not password:
        return None
    return hmac.new(key, password.encode("utf-8"), hashlib.sha256).hexdigest()


async def add(db: AsyncSession, label: str, password: str,
              created_by: str | None = None) -> MonitoredPassword:
    """Register a password. The plaintext is fingerprinted and dropped here —
    it is never returned, logged, or written anywhere."""
    label = (label or "").strip()
    if not label:
        raise MonitoredPasswordError("a label is required")
    if not password or len(password) < MIN_LENGTH:
        raise MonitoredPasswordError(
            f"password must be at least {MIN_LENGTH} characters")
    if not available():
        raise MonitoredPasswordError(
            "no encryption key available — cannot fingerprint safely")

    fp = fingerprint(password)
    existing = (await db.execute(
        select(MonitoredPassword).where(MonitoredPassword.fingerprint == fp)
    )).scalar_one_or_none()
    if existing is not None:
        # Re-registering the same password reactivates and relabels it rather
        # than failing — the operator's intent is clear and the duplicate would
        # otherwise leak (via the error) that this password is already known.
        existing.active = True
        existing.label = label[:200]
        await db.commit()
        return existing

    row = MonitoredPassword(label=label[:200], fingerprint=fp, active=True,
                            created_by=created_by, hit_count=0)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def remove(db: AsyncSession, entry_id: int) -> bool:
    row = await db.get(MonitoredPassword, entry_id)
    if row is None:
        return False
    await db.delete(row)
    await db.commit()
    return True


async def set_active(db: AsyncSession, entry_id: int, active: bool) -> bool:
    row = await db.get(MonitoredPassword, entry_id)
    if row is None:
        return False
    row.active = bool(active)
    await db.commit()
    return True


def serialize(row: MonitoredPassword) -> dict:
    """The operator-facing view. The fingerprint is deliberately omitted: it is
    the one field that would let someone test guesses offline."""
    return {
        "id": row.id,
        "label": row.label,
        "active": bool(row.active),
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_hit_at": row.last_hit_at.isoformat() if row.last_hit_at else None,
        "hit_count": row.hit_count or 0,
    }


async def list_entries(db: AsyncSession) -> list[dict]:
    rows = (await db.execute(
        select(MonitoredPassword).order_by(MonitoredPassword.created_at.desc())
    )).scalars().all()
    return [serialize(r) for r in rows]


async def match(db: AsyncSession, password: str | None) -> MonitoredPassword | None:
    """The registered password this submission is, or None.

    Compared with :func:`hmac.compare_digest` even though the lookup is by
    index — the cost is nil and it keeps the comparison honest if this ever
    moves to scanning a list."""
    if not password:
        return None
    fp = fingerprint(password)
    if not fp:
        return None
    row = (await db.execute(
        select(MonitoredPassword).where(
            MonitoredPassword.fingerprint == fp,
            MonitoredPassword.active.is_(True),
        )
    )).scalar_one_or_none()
    if row is None:
        return None
    if not hmac.compare_digest(row.fingerprint, fp):
        return None
    return row


async def _username_is_real(db: AsyncSession, username: str | None) -> bool | None:
    """True/False, or None when the directory cannot judge.

    Reuses the brute-force rule's directory so "a real username" means the same
    thing in both places."""
    if not username:
        return False
    try:
        from app import login_bruteforce
        known = await login_bruteforce.known_users(db)
        if known is None:
            return None
        return login_bruteforce.normalise(username) in known
    except Exception as e:
        logger.warning(f"monitored password: username check failed: {e}")
        return None


async def evaluate(db: AsyncSession, username: str | None,
                   password: str | None) -> dict | None:
    """Judge one submitted credential pair.

    Returns None for the ordinary case (no registered password involved), or a
    verdict dict when one matched::

        {"severity": "high"|"critical", "entry_id": int, "label": str,
         "username_real": True|False|None}

    The hit counters are advanced here so a repeatedly replayed credential shows
    its history rather than looking new every time."""
    entry = await match(db, password)
    if entry is None:
        return None

    username_real = await _username_is_real(db, username)
    severity = "critical" if username_real else "high"

    # Incremented in SQL, not from the value this session happened to read: two
    # decoys replaying the same leaked credential at once would both compute
    # N+1 and the second write would swallow the first, so the counter would
    # under-report exactly the credential being hammered hardest.
    await db.execute(
        update(MonitoredPassword)
        .where(MonitoredPassword.id == entry.id)
        .values(hit_count=func.coalesce(MonitoredPassword.hit_count, 0) + 1,
                last_hit_at=datetime.now(timezone.utc))
    )
    return {
        "severity": severity,
        "entry_id": entry.id,
        "label": entry.label,
        "username_real": username_real,
    }


def alarm_text(verdict: dict, username: str | None, ip: str | None) -> str:
    """The notification body. Never contains the password — the whole point is
    that a real credential does not travel to Telegram or Teams."""
    import html

    crit = verdict["severity"] == "critical"
    head = ("🚨 <b>Warroom · CRITICAL — real credential in use</b>" if crit
            else "🔴 <b>Warroom · real password used</b>")
    lines = [
        head,
        f"<b>Source:</b> <code>{html.escape(str(ip or '?'))}</code>",
        f"<b>Registered password:</b> {html.escape(verdict['label'])}",
        f"<b>Username:</b> <code>{html.escape(str(username or '-'))}</code>",
    ]
    if crit:
        lines.append("<b>The username is a real account here.</b> Treat this as "
                     "a working login in someone else's hands: rotate the "
                     "password and review that account's recent activity now.")
    elif verdict.get("username_real") is None:
        lines.append("The user directory could not be consulted, so the username "
                     "could not be confirmed — treat as potentially critical.")
    else:
        lines.append("A password genuinely in use here was submitted to a decoy. "
                     "It did not come from guessing: rotate it wherever it is used.")
    lines.append("The submitted password was <b>not</b> stored.")
    return "\n".join(lines)
