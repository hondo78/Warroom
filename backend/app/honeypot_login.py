"""Decoy login page: capture what people type into it, then act on it.

The page is linked from nowhere and grants access to nothing. That makes every
submission unambiguous in a way a failed login on a real portal never is: on the
real portal the first suspect is a forgotten password, here there is no innocent
explanation to weigh. So a single submission is enough to block the source and
burn the username — no threshold, no model, no approval.

Passwords are stored in the clear. The whole value of the page is knowing *what*
was tried: whether credentials leaked elsewhere are being replayed against us,
whether a guess lands uncomfortably close to a real password, which word lists
are in circulation this week. A hash answers none of those questions.

The one exception is a password that is genuinely ours. Registered real
passwords (:mod:`app.monitored_passwords`) are recognised by keyed fingerprint,
and a submission that matches one is redacted rather than stored — at that point
it is a live credential, not an attacker's guess, and the row would otherwise
hold a real password in the clear. It also raises a much louder alarm, because
nobody guesses a real password by accident: it leaked.
"""
import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app import monitored_passwords
from app.config import settings
from app.database import async_session
from app.geoip_service import lookup_ip
from app.models import BlockedIp, HoneypotLogin, WhitelistedIp

logger = logging.getLogger(__name__)

# Generous, but not unbounded: a scripted flood should not be able to write
# arbitrarily large rows. Anything longer is truncated, never rejected — a
# rejection would tell the attacker the page is not real.
MAX_FIELD = 4000


def _trim(value: str | None, limit: int = 255) -> str | None:
    if value is None:
        return None
    v = str(value).strip()
    return v[:limit] or None


# Credential field names as they actually appear in the wild. A decoy that only
# understands "username"/"password" records the visit and throws away the very
# thing it exists to collect the moment a client uses its own vocabulary — and
# every portal has its own.
_USER_KEYS = (
    "username", "user", "uname", "userid", "user_id", "user_name", "login",
    "loginname", "logon", "account", "email", "mail", "j_username", "benutzer",
    "principal", "identity", "uid",
)
_PASS_KEYS = (
    "password", "pass", "passwd", "pwd", "secret", "credential", "credentials",
    "j_password", "kennwort", "passphrase", "token", "otp", "pin",
)
# How deep to look for them in a nested body. Bounded so a hostile payload
# cannot turn the search into the attack.
_MAX_DEPTH = 4


def extract_credentials(payload, headers=None) -> tuple[str | None, str | None]:
    """Pull a username/password pair out of whatever shape arrived.

    Walks nested objects and lists to a bounded depth and matches field names
    case-insensitively, because the point is to record what was tried, not to
    insist the attacker use our vocabulary. Falls back to HTTP Basic auth, which
    is how a fair number of appliance APIs take credentials.

    Pure and total: never raises, returns (None, None) when nothing looks like
    a credential."""
    user = pwd = None

    def walk(node, depth=0):
        nonlocal user, pwd
        if depth > _MAX_DEPTH or (user and pwd):
            return
        if isinstance(node, dict):
            for k, v in node.items():
                key = str(k).strip().lower()
                if isinstance(v, (str, int, float)):
                    val = str(v)
                    if user is None and key in _USER_KEYS:
                        user = val
                    elif pwd is None and key in _PASS_KEYS:
                        pwd = val
                else:
                    walk(v, depth + 1)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v, depth + 1)

    try:
        walk(payload)
    except Exception:
        pass

    if (user is None or pwd is None) and headers:
        b_user, b_pwd = _basic_auth(headers.get("authorization"))
        user = user or b_user
        pwd = pwd or b_pwd
    return user, pwd


def _basic_auth(header: str | None) -> tuple[str | None, str | None]:
    """Decode HTTP Basic credentials, or (None, None)."""
    if not header or not header.lower().startswith("basic "):
        return None, None
    import base64

    try:
        raw = base64.b64decode(header.split(" ", 1)[1], validate=True).decode("utf-8", "replace")
    except Exception:
        return None, None
    if ":" not in raw:
        return None, None
    u, p = raw.split(":", 1)
    return u or None, p or None


def client_ip(request) -> str | None:
    """The attacker's address, as far as it can be trusted.

    Read from the RIGHT of X-Forwarded-For, not the left. Every proxy in the
    chain appends what it saw, so the leftmost entry is whatever the client
    sent — which on this endpoint is an attacker who would very much like us to
    write someone else's address into the block list. ``_block()`` acts on this
    value, so a spoofable one turns the decoy into a way to have Warroom block
    arbitrary third parties (a DNS resolver, an update server, the operator's
    own uplink).

    Walking right-to-left and taking the first public address gives the real
    client whether the decoy is exposed directly (our nginx appended it) or via
    another proxy (which appended it before ours appended the proxy). Private
    entries are our own hops. Nothing public in the chain means nobody
    forwarded a real client, and the socket address is what remains truthful.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        for hop in reversed(xff.split(",")):
            hop = hop.strip()
            if hop and _is_public(hop):
                return hop[:45]
    real = (request.headers.get("x-real-ip") or "").strip()
    if real:
        return real[:45]
    return getattr(getattr(request, "client", None), "host", None)


async def capture(request, username: str | None, password: str | None,
                  visited_path: str | None = None,
                  raw_body: str | None = None) -> dict:
    """Record a submission and respond to it. Never raises: a decoy that 500s
    tells the visitor it is a decoy."""
    ip = client_ip(request)
    row_action = "none"
    row_id: int | None = None
    verdict: dict | None = None

    try:
        async with async_session() as db:
            geo = None
            if ip:
                try:
                    geo = await lookup_ip(ip, db)
                except Exception:
                    geo = None

            # Is this one of our own passwords? Decided before the row is built,
            # because the answer changes whether the password may be stored.
            if settings.monitored_password_enabled:
                try:
                    verdict = await monitored_passwords.evaluate(db, username, password)
                except Exception as e:
                    logger.warning(f"monitored password check failed: {e}")

            # A matched password is a live credential of ours, not an attacker's
            # guess. Storing it would put a real password in the clear in the
            # database — the exact outcome this feature exists to prevent.
            stored_password = (
                None if verdict
                else (str(password)[:MAX_FIELD] if password is not None else None))

            row = HoneypotLogin(
                username=_trim(username),
                password=stored_password,
                monitored_password_id=(verdict or {}).get("entry_id"),
                credential_alarm=(verdict or {}).get("severity"),
                source_ip=ip,
                user_agent=_trim(request.headers.get("user-agent"), MAX_FIELD),
                # Which endpoint they went looking for, best source first: the
                # page reports its own location, a bot posting straight at the
                # API has its original path preserved by nginx, and the
                # rewritten backend route is the last resort.
                path=(_trim(visited_path)
                      or _trim(request.headers.get("x-original-path"))
                      or _trim(request.url.path if request.url else None)),
                method=_trim(getattr(request, "method", None), 10),
                # Redacted on a match for the same reason as `password`: the raw
                # body carries the credential verbatim, so keeping it would put
                # back exactly what the redaction above just removed.
                raw_body=(None if verdict
                          else (str(raw_body)[:MAX_FIELD] if raw_body else None)),
                referer=_trim(request.headers.get("referer"), MAX_FIELD),
                attacker_country=(geo or {}).get("country"),
                attacker_city=(geo or {}).get("city"),
                attacker_asn=str((geo or {}).get("asn")) if (geo or {}).get("asn") else None,
                attacker_org=(geo or {}).get("org"),
            )
            db.add(row)
            await db.flush()

            actions = []
            if settings.honeypot_web_block_source and ip:
                if await _block(db, ip, username):
                    actions.append("blocked")
            if settings.honeypot_web_burn_username and username:
                if await _burn(db, username, ip):
                    actions.append("burned")
            row_action = "+".join(actions) or "none"
            row.action = row_action
            await db.commit()
            row_id = row.id
    except Exception as e:
        logger.warning(f"honeypot login capture failed: {e}")

    # Detached on purpose: the visitor is answered first, the lookup catches up
    # afterwards. Only public sources are worth asking a provider about.
    if (settings.honeypot_web_osint_enabled and ip and row_id
            and _is_public(ip)):
        asyncio.create_task(enrich_async(row_id, ip))

    # A real credential outranks the routine bait notification, and fires even
    # when the ordinary honeypot alert is switched off: someone switching the
    # noise down must not also switch this off without meaning to.
    if verdict:
        try:
            await _credential_alarm(verdict, username, ip)
        except Exception as e:
            logger.warning(f"monitored password alarm failed: {e}")

    if settings.honeypot_web_alert:
        try:
            await _alert(username, ip, row_action)
        except Exception as e:
            logger.warning(f"honeypot login alert failed: {e}")

    return {"ip": ip, "action": row_action}


async def capture_probe(request) -> dict:
    """Record that someone merely *looked* — no credentials submitted.

    Reconnaissance, not yet an attempt. Worth knowing, because the path they
    asked for says what they were hunting for and the first probe usually
    precedes the attempt by minutes. Not acted on by default: a page request has
    innocent explanations a typed password does not.

    Debounced per source and path, or a scanner walking twenty URLs would bury
    the credential captures under its own noise."""
    ip = client_ip(request)
    path = (request.headers.get("x-original-path")
            or (request.url.path if request.url else "")) or "/"

    if not await _probe_is_new(ip, path):
        return {"ip": ip, "recorded": False}

    try:
        async with async_session() as db:
            geo = None
            if ip:
                try:
                    geo = await lookup_ip(ip, db)
                except Exception:
                    geo = None
            db.add(HoneypotLogin(
                kind="probe",
                username=None, password=None,
                source_ip=ip,
                user_agent=_trim(request.headers.get("user-agent"), MAX_FIELD),
                path=_trim(path),
                referer=_trim(request.headers.get("referer"), MAX_FIELD),
                attacker_country=(geo or {}).get("country"),
                attacker_city=(geo or {}).get("city"),
                attacker_asn=str((geo or {}).get("asn")) if (geo or {}).get("asn") else None,
                attacker_org=(geo or {}).get("org"),
                action="none",
            ))
            await db.commit()
    except Exception as e:
        logger.warning(f"honeypot probe capture failed: {e}")
        return {"ip": ip, "recorded": False}
    return {"ip": ip, "recorded": True}


async def _probe_is_new(ip: str | None, path: str) -> bool:
    """True at most once per source+path per debounce window.

    Redis-backed and fail-open: if the cache is down the probe is recorded
    rather than dropped — duplicates are noise, a missing record is a blind
    spot."""
    from app.geoip_service import get_redis

    minutes = max(1, min(1440, int(settings.honeypot_web_probe_dedup_minutes or 10)))
    try:
        r = await get_redis()
        key = f"hp:probe:{ip or '?'}:{path[:120]}"
        return bool(await r.set(key, "1", ex=minutes * 60, nx=True))
    except Exception:
        return True


async def enrich_async(row_id: int, ip: str) -> None:
    """Look the source up with the OSINT providers and attach the result.

    Runs detached, *after* the visitor has been answered, for two reasons. A
    provider call takes seconds, and the decoy's reply must stay as fast and as
    uniform as a real login backend's — a request that hangs noticeably longer
    than the others is a fingerprint. And a provider being slow or down must
    never be able to make the decoy look broken.

    Never raises: enrichment is a bonus on top of a capture that is already
    safely recorded."""
    from app import osint

    try:
        result = await osint.enrich_live([ip], cap=1, context="honeypot")
        summary = result.get(ip)
        if not summary:
            return
        async with async_session() as db:
            row = await db.get(HoneypotLogin, row_id)
            if row:
                row.osint = summary
                await db.commit()
    except Exception as e:
        logger.warning(f"honeypot login: OSINT enrichment for {ip} failed: {e}")


def _is_public(ip: str) -> bool:
    from app.login_bruteforce import is_public_ipv4

    return is_public_ipv4(ip)


async def _block(db, ip: str, username: str | None) -> bool:
    """Block the source unless it is whitelisted or already blocked."""
    from app.login_bruteforce import is_public_ipv4

    if not is_public_ipv4(ip):
        # An internal source typing into the decoy is worth knowing about — it
        # usually means a compromised host inside — but blocking our own network
        # on the strength of one form post is the wrong trade. A public IPv6
        # source lands here too: the block path (and the firewall feed behind
        # it) is IPv4-only, so the line says "not blockable", not "internal" —
        # calling a routable v6 address internal made the audit trail lie.
        logger.warning(f"honeypot login: source {ip} is not a blockable public "
                       f"IPv4 (internal or IPv6) — credentials from it "
                       f"(user={username!r}) recorded, not blocked")
        return False
    if (await db.execute(select(WhitelistedIp.ip).where(WhitelistedIp.ip == ip))).scalar_one_or_none():
        return False
    if (await db.execute(select(BlockedIp.ip).where(BlockedIp.ip == ip))).scalar_one_or_none():
        return False
    db.add(BlockedIp(
        ip=ip,
        comment=f"honeypot[login] Zugangsdaten auf der Köderseite eingegeben"
                + (f" (Benutzer: {username[:60]})" if username else ""),
        blocked_at=datetime.now(timezone.utc),
        blocked_by="agent", source="honeypot_login",
    ))
    return True


async def _burn(db, username: str, ip: str | None) -> bool:
    """Add the username to the invalid-username list.

    Skipped when the name is a real account here: an attacker typing a genuine
    colleague's name into the decoy must not get that colleague blocked
    everywhere else. The name is still recorded on the row above."""
    from app import login_bruteforce

    name = login_bruteforce.normalise(username)
    if not name:
        return False
    known = await login_bruteforce.known_users(db)
    if known is None:
        # None is not "no known users": known_users() returns it when the
        # directory is unavailable or too small to trust, and its contract is
        # "cannot judge, block nothing". Read as merely falsy, an outage turned
        # a colleague's real name into a burned one — and a burned name blocks
        # any source that uses it on its first attempt, including the colleague.
        logger.warning("honeypot login: user directory unavailable — recorded, not burned")
        return False
    if name in known:
        logger.info(f"honeypot login: {name!r} is a real account here — recorded, not burned")
        return False
    burned = await login_bruteforce.burn_from_offenders(
        db, [{"ip": ip, "unknown_users_all": [name]}])
    return bool(burned)


async def _alert(username, ip, action) -> None:
    """Notify that someone took the bait — without the password.

    The captured password never leaves this system. Telegram and Teams are
    third-party services with their own retention and their own readers, and a
    notification channel is the last place a plaintext credential belongs. The
    password is readable in the frontend, which is where the decision to look at
    it can be made deliberately."""
    import html

    from app.notifications import notify

    lines = [
        "🍯 <b>Warroom · Köder-Login</b>",
        f"<b>Quelle:</b> <code>{html.escape(str(ip or '?'))}</code>",
        f"<b>Benutzer:</b> <code>{html.escape(str(username or '—')[:80])}</code>",
        f"<b>Reaktion:</b> {html.escape(action)}",
        "Das eingegebene Kennwort steht nur im Warroom-Frontend.",
    ]
    await notify("\n".join(lines), title="Warroom · Köder-Login",
                 event="honeypot_login")


async def _credential_alarm(verdict: dict, username: str | None,
                            ip: str | None) -> None:
    """Raise the alarm for a *real* password appearing in an attack.

    Separate from :func:`_alert` on purpose. The bait notification is routine
    and gets switched off by operators who do not want the noise; this one is
    the opposite kind of event — rare, and the one worth waking someone for. It
    carries the registered password's label, never the password itself."""
    from app.notifications import notify

    critical = verdict["severity"] == "critical"
    title = ("Warroom · CRITICAL credential compromise" if critical
             else "Warroom · real password used")
    await notify(monitored_passwords.alarm_text(verdict, username, ip),
                 title=title, event="monitored_password")
    logger.warning(
        f"MONITORED PASSWORD {verdict['severity'].upper()}: "
        f"registered credential {verdict['label']!r} submitted from {ip} "
        f"as user {username!r}")


async def respond_delay() -> None:
    """Pause before rejecting. An instant refusal is the tell that gives a decoy
    away — a real backend takes a moment to check a directory."""
    ms = max(0, min(10000, int(settings.honeypot_web_delay_ms or 0)))
    if ms:
        await asyncio.sleep(ms / 1000)
