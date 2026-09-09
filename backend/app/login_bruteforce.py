"""Immediate blocking of brute-force sources that guess NON-EXISTENT usernames.

The existing failed-login stages hand their evidence to the LLM and act on its
verdict, which is right for judgement calls ("is this one user's 6 failures a
forgotten password or an attack?"). Guessing usernames needs no judgement: an
attacker spraying ``admin``, ``art@familie-luehrs.de``, ``burkhard_support`` at
the VPN portal is trying names that **do not exist on this network**. A real
user fat-fingers their password, never their own name — and never five different
names. This module is therefore deliberately **rule-based and immediate**: no
model call sits between detection and block.

How "does this user exist?" is answered
---------------------------------------
From the firewall's own history: every username that has ever *successfully*
authenticated is a real account. That directory is self-maintaining, needs no
AD/Entra integration, and is exactly the set an attacker cannot guess. On this
network it holds ~37 names, while failed logins reference ~2400 distinct ones —
the separation is stark.

Why the directory lives in Redis
--------------------------------
``firewall_logs`` carries only a primary-key index, so *any* time-window query is
a full scan of a 40 GB table — building the directory from scratch measures ~79 s.
It is therefore maintained incrementally behind a cursor (same pattern as
:mod:`login_cache`): one expensive backfill, then only new rows. The attempts
themselves come from :mod:`login_cache`, so this module adds no table scans at
all to the loop.

Safety interlocks (all must hold before anything is blocked)
------------------------------------------------------------
* The directory must be **initialised and hold at least** ``min_directory``
  names. An empty directory would make every username look invalid and block
  every source — the single most dangerous failure mode here, so a cold or
  broken cache disables the rule instead of arming it.
* Only **public IPv4** sources; internal ranges are never blocked.
* Whitelisted and already-blocked IPs are skipped by the caller.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.geoip_service import get_redis

logger = logging.getLogger(__name__)

_USERS_KEY = "agent:knownusers:set"
_USERS_CURSOR = "agent:knownusers:cursor"

# One-off backfill depth when the directory is cold. The table has no index on
# created_at, so a narrower window would not actually be cheaper — the scan is
# the cost, not the range.
BACKFILL_DAYS = 30
# Refuse to act on a directory this small: it means the backfill has not run or
# the log format changed, not that the network has two users.
MIN_DIRECTORY = 3

# Usernames that are never "real" even if they show up in a success row, e.g.
# a device that authenticates with a generic name. Kept small on purpose.
_IGNORED_USERS = frozenset({"", "-", "n/a", "unknown", "null", "none"})

# Names every spray list contains. Learning one of these from a successful login
# is normal (a NAS, a router, a service account really does log in as "admin"),
# but it has a side effect worth surfacing: the name then counts as *real*, so an
# attacker guessing exactly it is not counted as guessing an invalid name and
# loses a point towards the block threshold. That is a judgement call for the
# operator — a shared "admin" account may genuinely need to stay valid — so this
# list only *flags* names in the UI. Nothing here is excluded automatically.
GENERIC_USERS = frozenset({
    "admin", "administrator", "root", "guest", "user", "test", "tester",
    "demo", "info", "support", "service", "office", "backup", "operator",
    "manager", "sysadmin", "helpdesk", "default", "temp", "scanner",
    "mail", "webmaster", "postmaster", "ftp", "www", "web", "sql", "mysql",
    "postgres", "oracle", "git", "jenkins", "pi", "ubuntu", "kali", "cisco",
})


def is_generic(user: str | None) -> bool:
    """True for names that appear in every brute-force word list — see
    :data:`GENERIC_USERS` for why they are only flagged, never auto-excluded."""
    return normalise(user) in GENERIC_USERS

_SUCCESS_SQL = (
    "COALESCE(raw_data->>'status', raw_data->>'auth_status') ILIKE 'success%'"
)


def normalise(user: str | None) -> str:
    """Canonical form for comparing usernames (case/whitespace-insensitive)."""
    return (user or "").strip().lower()


def is_public_ipv4(ip: str | None) -> bool:
    """True only for routable public IPv4 — brute-force blocks never target
    internal space, where a false positive would lock out our own hosts."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return (addr.version == 4 and not addr.is_private and not addr.is_loopback
            and not addr.is_link_local and not addr.is_reserved
            and not addr.is_multicast)


# --- known-user directory -----------------------------------------------------

async def refresh_directory(db: AsyncSession, now: datetime | None = None) -> dict:
    """Pull newly-succeeded usernames into the Redis directory.

    Incremental behind a cursor; the first run backfills ``BACKFILL_DAYS`` and is
    the only expensive one. Returns a status dict (never raises) so a Redis or DB
    hiccup degrades to "rule disabled" instead of taking the loop down."""
    now = now or datetime.now(timezone.utc)
    try:
        r = await get_redis()
    except Exception as e:
        logger.warning(f"login_bruteforce: redis unavailable, directory not refreshed: {e}")
        return {"ok": False, "reason": "redis_unavailable", "size": 0}

    try:
        cursor_iso = await r.get(_USERS_CURSOR)
    except Exception:
        cursor_iso = None

    backfill = not cursor_iso
    since = now - timedelta(days=BACKFILL_DAYS)
    if cursor_iso:
        try:
            since = datetime.fromisoformat(cursor_iso)
        except ValueError:
            backfill = True
    if backfill:
        logger.info("login_bruteforce: cold directory — backfilling %d days "
                    "(full scan of firewall_logs, expect ~1 min)", BACKFILL_DAYS)

    try:
        rows = (await db.execute(text(f"""
            SELECT user_name, created_at
            FROM firewall_logs
            WHERE created_at >= :since
              AND user_name IS NOT NULL AND user_name <> ''
              AND {_SUCCESS_SQL}
        """), {"since": since})).all()
    except Exception as e:
        logger.warning(f"login_bruteforce: directory query failed: {e}")
        return {"ok": False, "reason": "query_failed", "size": 0}

    users = {normalise(u) for u, _ in rows}
    users -= _IGNORED_USERS
    newest = max((ts for _, ts in rows if ts), default=None)

    try:
        if users:
            await r.sadd(_USERS_KEY, *users)
        # Advance the cursor even when nothing new arrived, so the expensive
        # backfill runs exactly once.
        await r.set(_USERS_CURSOR, (newest or now).isoformat())
        size = await r.scard(_USERS_KEY)
    except Exception as e:
        logger.warning(f"login_bruteforce: directory write failed: {e}")
        return {"ok": False, "reason": "redis_write_failed", "size": 0}

    logger.info(f"login_bruteforce: directory +{len(users)} name(s), now {size} total"
                f"{' (backfill)' if backfill else ''}")
    return {"ok": True, "added": len(users), "size": int(size), "backfill": backfill}


async def learned_users() -> set[str] | None:
    """Only the self-learned part of the directory (from successful logins).
    ``None`` when Redis is unavailable."""
    try:
        r = await get_redis()
        members = await r.smembers(_USERS_KEY)
    except Exception as e:
        logger.warning(f"login_bruteforce: directory read failed: {e}")
        return None
    return {normalise(m) for m in members} - _IGNORED_USERS


async def load_overrides(db: AsyncSession) -> tuple[set[str], set[str]]:
    """Operator corrections as ``(allow, deny)`` sets of normalised names."""
    try:
        rows = (await db.execute(
            text("SELECT user_name, status FROM known_user_overrides")
        )).all()
    except Exception as e:
        logger.warning(f"login_bruteforce: overrides unreadable: {e}")
        return set(), set()
    allow = {normalise(u) for u, s in rows if (s or "allow") == "allow"}
    deny = {normalise(u) for u, s in rows if s == "deny"}
    return allow - _IGNORED_USERS, deny - _IGNORED_USERS


async def known_users(db: AsyncSession | None = None) -> set[str] | None:
    """The effective directory: learned ∪ allow − deny.

    Returns ``None`` when it is unavailable or too small to trust — the safe
    answer, which callers must read as "cannot judge, block nothing" rather than
    "every username is invalid". ``deny`` is applied last so an operator can
    always strip a name, and the size check runs on the *effective* set, so
    denying everything disarms the rule instead of arming it against the world."""
    learned = await learned_users()
    if learned is None:
        return None

    allow: set[str] = set()
    deny: set[str] = set()
    if db is not None:
        allow, deny = await load_overrides(db)

    users = (learned | allow) - deny
    if len(users) < MIN_DIRECTORY:
        logger.warning(f"login_bruteforce: effective directory too small "
                       f"({len(users)} < {MIN_DIRECTORY}) — rule stays disarmed")
        return None
    return users


async def directory_view(db: AsyncSession) -> dict:
    """Everything the UI needs to show and audit the directory: each name with
    where it came from, plus the interlock state."""
    learned = await learned_users()
    allow, deny = await load_overrides(db)
    effective = await known_users(db)

    entries: list[dict] = []
    for name in sorted((learned or set()) | allow | deny):
        in_learned = name in (learned or set())
        entries.append({
            "user": name,
            # "learned" = seen in a successful login; "manual" = operator-added;
            # "both" = learned and explicitly kept.
            "origin": ("both" if in_learned and name in allow
                       else "manual" if name in allow
                       else "learned"),
            "excluded": name in deny,
            "counts_as_real": name in (effective or set()),
            "generic": is_generic(name),
        })
    # Only names that are BOTH generic and currently valid actually shield an
    # attacker; an excluded one is already handled and must not nag.
    shielding = [e["user"] for e in entries if e["generic"] and e["counts_as_real"]]
    return {
        "entries": entries,
        "learned_count": len(learned) if learned is not None else 0,
        "manual_count": len(allow),
        "excluded_count": len(deny),
        "effective_count": len(effective) if effective is not None else 0,
        "armed": effective is not None,
        "min_directory": MIN_DIRECTORY,
        "redis_available": learned is not None,
        "generic_shielding": sorted(shielding),
    }


# --- detection ----------------------------------------------------------------

def evaluate(attempts: list[dict], known: set[str], *,
             min_unknown_users: int = 3, min_attempts: int = 3,
             public_only: bool = True) -> list[dict]:
    """Find sources that guessed non-existent usernames.

    Pure function over cached attempts — no I/O, so the whole decision is unit
    testable. ``attempts`` are ``login_cache`` records (``ip``/``user``/``ts``).

    A source is reported when it tried at least ``min_unknown_users`` *distinct*
    usernames absent from ``known`` and made at least ``min_attempts`` failures.
    Distinct-name count is the discriminator, not raw volume: a real user
    retrying one password 20 times stays at one name and is never reported,
    while a sprayer hits the threshold within seconds."""
    if not known:
        return []

    by_ip: dict[str, dict] = {}
    for a in attempts:
        ip = (a.get("ip") or "").strip()
        if not ip or (public_only and not is_public_ipv4(ip)):
            continue
        user = normalise(a.get("user"))
        if user in _IGNORED_USERS:
            continue
        rec = by_ip.setdefault(ip, {
            "ip": ip, "attempts": 0, "users": set(), "unknown_users": set(),
            "country": a.get("country"), "components": set(),
            "first_ts": a.get("ts"), "last_ts": a.get("ts"),
        })
        rec["attempts"] += 1
        rec["users"].add(user)
        if user not in known:
            rec["unknown_users"].add(user)
        if a.get("component"):
            rec["components"].add(a["component"])
        rec["country"] = rec["country"] or a.get("country")
        ts = a.get("ts")
        if ts:
            if not rec["first_ts"] or ts < rec["first_ts"]:
                rec["first_ts"] = ts
            if not rec["last_ts"] or ts > rec["last_ts"]:
                rec["last_ts"] = ts

    offenders = []
    for rec in by_ip.values():
        if len(rec["unknown_users"]) < min_unknown_users:
            continue
        if rec["attempts"] < min_attempts:
            continue
        offenders.append({
            "ip": rec["ip"],
            "attempts": rec["attempts"],
            "users_tried": len(rec["users"]),
            "unknown_user_count": len(rec["unknown_users"]),
            # Sorted + capped: this goes into the block comment and the alert.
            "unknown_users": sorted(rec["unknown_users"])[:10],
            # Uncapped, for machine use only (burning the name list). Kept
            # separate so nothing renders 60 usernames into a Telegram message.
            "unknown_users_all": sorted(rec["unknown_users"]),
            "components": sorted(rec["components"])[:3],
            "country": rec["country"],
            "first_ts": rec["first_ts"],
            "last_ts": rec["last_ts"],
            "trigger": "threshold",
        })
    offenders.sort(key=lambda o: (o["unknown_user_count"], o["attempts"]), reverse=True)
    return offenders


# --- burned usernames ---------------------------------------------------------
# Names proven to come from a spray. The threshold rule discovers them; this list
# then blocks every later source on its first attempt, because a word list that
# has already been used against us buys nobody a second chance.

async def burn_from_offenders(db: AsyncSession, offenders: list[dict],
                              now: datetime | None = None) -> int:
    """Add every non-existent name an offender tried to the burn list.

    Only offenders — sources that already met the threshold rule — feed this.
    A single failed login never does, which is precisely what keeps a real
    user's mistyped own name off the list.

    The upsert only refreshes ``last_seen``; it never re-counts, so the same
    spray sitting in the analysis window for fifteen consecutive loops cannot
    inflate the numbers."""
    now = now or datetime.now(timezone.utc)
    rows = []
    for o in offenders:
        for name in o.get("unknown_users_all") or o.get("unknown_users") or []:
            n = normalise(name)
            if n and n not in _IGNORED_USERS:
                rows.append({"user_name": n[:255], "ip": o.get("ip")})
    if not rows:
        return 0

    # Deduplicate inside the batch: ON CONFLICT cannot fire twice for the same
    # key in one statement.
    seen: dict[str, str | None] = {}
    for r in rows:
        seen.setdefault(r["user_name"], r["ip"])

    try:
        await db.execute(text("""
            INSERT INTO invalid_usernames
                (user_name, first_seen, last_seen, burned_by_ip, origin, status)
            VALUES (:user_name, :now, :now, :ip, 'learned', 'active')
            ON CONFLICT (user_name) DO UPDATE SET last_seen = EXCLUDED.last_seen
        """), [{"user_name": u, "ip": ip, "now": now} for u, ip in seen.items()])
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.warning(f"login_bruteforce: burning usernames failed: {e}")
        return 0
    return len(seen)


async def active_burned(db: AsyncSession, known: set[str] | None = None) -> set[str]:
    """Names that currently block on sight. Empty on error — failing open here
    only costs detection, while failing closed on a broken query would be
    invisible.

    ``known`` is subtracted last, and that subtraction is load-bearing. Attacker
    word lists are full of plausible real names harvested from public sources;
    one of them turning out to be an actual colleague is a question of when, not
    if. Declaring that name a real account in the directory therefore has to
    disarm it here too — otherwise the operator fixes the directory, sees the
    name still on this list, and the person keeps getting blocked."""
    try:
        rows = (await db.execute(text(
            "SELECT user_name FROM invalid_usernames WHERE status = 'active'"
        ))).all()
    except Exception as e:
        logger.warning(f"login_bruteforce: burn list unreadable: {e}")
        return set()
    return {normalise(r[0]) for r in rows} - _IGNORED_USERS - (known or set())


def match_burned(attempts: list[dict], burned: set[str], *,
                 public_only: bool = True) -> list[dict]:
    """Sources that tried a name from the burn list — one attempt is enough.

    Pure, so the whole trigger is unit testable. Returns the same shape as
    :func:`evaluate` so both paths can share the blocking and audit code."""
    if not burned:
        return []

    by_ip: dict[str, dict] = {}
    for a in attempts:
        ip = (a.get("ip") or "").strip()
        if not ip or (public_only and not is_public_ipv4(ip)):
            continue
        user = normalise(a.get("user"))
        if user not in burned:
            continue
        rec = by_ip.setdefault(ip, {
            "ip": ip, "attempts": 0, "users": set(), "unknown_users": set(),
            "country": a.get("country"), "components": set(),
            "first_ts": a.get("ts"), "last_ts": a.get("ts"),
        })
        rec["attempts"] += 1
        rec["users"].add(user)
        rec["unknown_users"].add(user)
        if a.get("component"):
            rec["components"].add(a["component"])
        rec["country"] = rec["country"] or a.get("country")
        ts = a.get("ts")
        if ts:
            if not rec["first_ts"] or ts < rec["first_ts"]:
                rec["first_ts"] = ts
            if not rec["last_ts"] or ts > rec["last_ts"]:
                rec["last_ts"] = ts

    hits = []
    for rec in by_ip.values():
        names = sorted(rec["unknown_users"])
        hits.append({
            "ip": rec["ip"],
            "attempts": rec["attempts"],
            "users_tried": len(rec["users"]),
            "unknown_user_count": len(names),
            "unknown_users": names[:10],
            "unknown_users_all": names,
            "components": sorted(rec["components"])[:3],
            "country": rec["country"],
            "first_ts": rec["first_ts"],
            "last_ts": rec["last_ts"],
            # What separates these from threshold hits, all the way into the
            # block comment and the alert.
            "trigger": "burned_username",
        })
    hits.sort(key=lambda h: (h["unknown_user_count"], h["attempts"]), reverse=True)
    return hits


async def record_burn_hits(db: AsyncSession, hits: list[dict]) -> None:
    """Count which burned names actually caused a block, so the operator can
    tell a productive entry from one that has never fired."""
    names = {n for h in hits for n in (h.get("unknown_users_all") or [])}
    if not names:
        return
    try:
        await db.execute(text("""
            UPDATE invalid_usernames SET block_hits = block_hits + 1
            WHERE user_name = ANY(:names)
        """), {"names": sorted(names)})
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.warning(f"login_bruteforce: burn-hit counters not updated: {e}")


def burned_block_comment(hit: dict) -> str:
    """Provenance for a block caused by the name list alone."""
    names = ", ".join(hit["unknown_users"][:5])
    more = "…" if hit["unknown_user_count"] > 5 else ""
    return (f"agent[invalid-user] Loginversuch mit bekanntem Angreifer-Benutzernamen "
            f"({hit['attempts']} Versuch(e)): {names}{more}")


def summarise(attempts: list[dict], known: set[str] | None, *,
              min_unknown_users: int = 3, min_attempts: int = 3) -> dict:
    """What the rule would find in ``attempts`` — evidence, not action.

    Exists because the rule is silent by design: it blocks only while an attack
    is running, so an operator looking at a quiet system cannot tell a working
    rule from a broken one, nor whether the thresholds fit their traffic. This
    replays the same :func:`evaluate` over a span of cached attempts and reports
    what it hit, blocking nothing.

    One honest caveat, mirrored in the UI: the live rule evaluates a sliding
    window (default 15 min), while this aggregates the *whole* span at once. A
    source pacing itself below the live threshold can therefore show up here —
    the result is an upper bound on what a live run would have caught."""
    known = known or set()
    public = [a for a in attempts if is_public_ipv4(a.get("ip"))]
    timestamps = [a.get("ts") for a in attempts if a.get("ts")]
    return {
        "offenders": evaluate(attempts, known,
                              min_unknown_users=min_unknown_users,
                              min_attempts=min_attempts),
        "attempts_total": len(attempts),
        "attempts_public": len(public),
        "distinct_ips": len({a.get("ip") for a in public if a.get("ip")}),
        "first_ts": min(timestamps, default=None),
        "last_ts": max(timestamps, default=None),
        "min_unknown_users": min_unknown_users,
        "min_attempts": min_attempts,
        "directory_size": len(known),
    }


def block_comment(offender: dict) -> str:
    """Human-readable provenance stored on the block row."""
    names = ", ".join(offender["unknown_users"][:5])
    more = "…" if offender["unknown_user_count"] > 5 else ""
    return (f"agent[invalid-user] {offender['unknown_user_count']} nicht existierende "
            f"Benutzer in {offender['attempts']} Fehlversuchen: {names}{more}")
