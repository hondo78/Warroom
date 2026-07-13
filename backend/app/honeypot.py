"""Honeypot management + event ingestion.

A honeypot pod is the ``honeypot_agent`` running on a remote Linux host. It
simulates decoy services (SSH, HTTP, …) and reports any access here — every hit
is suspicious by definition, since nothing legitimate should ever touch a decoy.
Warroom stores the events, geo-enriches them and raises a (de-duplicated)
Telegram/Teams alert. Pods are created here (name + chosen services), get a
one-time token, and pull their desired service config on each heartbeat.
"""
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.database import async_session
from app.geoip_service import get_redis, lookup_ip
from app.models import Honeypot, HoneypotEvent

logger = logging.getLogger(__name__)

# Canonical decoy services the agent can run. port = the default listen port;
# these are the most-scanned / most-attacked services, so any touch is high
# signal. The agent binds low ports only when it has the privilege to.
SERVICES: dict[str, dict] = {
    "ssh":    {"port": 22,   "label": "SSH"},
    "telnet": {"port": 23,   "label": "Telnet"},
    "ftp":    {"port": 21,   "label": "FTP"},
    "http":   {"port": 80,   "label": "HTTP"},
    "https":  {"port": 443,  "label": "HTTPS"},
    "smb":    {"port": 445,  "label": "SMB"},
    "rdp":    {"port": 3389, "label": "RDP"},
    "mysql":  {"port": 3306, "label": "MySQL"},
    "mssql":  {"port": 1433, "label": "MSSQL"},
    "redis":  {"port": 6379, "label": "Redis"},
    "vnc":    {"port": 5900, "label": "VNC"},
    "postgres": {"port": 5432, "label": "PostgreSQL"},
}
DEFAULT_SERVICES = ["ssh", "telnet", "ftp", "http", "rdp", "smb", "mysql", "vnc"]

# Decoy-file bait kinds (the agent holds the actual bait content). label +
# a suggested default path shown in the UI.
FILE_TEMPLATES: dict[str, dict] = {
    "credentials": {"label": "Zugangsdaten (TXT)", "example": "/root/credentials.txt"},
    "aws":         {"label": "AWS-Credentials",     "example": "/root/.aws/credentials"},
    "ssh_key":     {"label": "SSH Private Key",     "example": "/root/.ssh/id_rsa_backup"},
    "env":         {"label": ".env (App-Secrets)",  "example": "/var/www/.env"},
    "db_dump":     {"label": "DB-Dump (SQL)",       "example": "/root/backup/dump.sql"},
    "password_list": {"label": "Passwortliste",     "example": "/home/admin/passwords.txt"},
}


def normalize_files(files) -> list[dict]:
    """Coerce input into a clean [{path, kind}] list over known kinds."""
    out: list[dict] = []
    seen: set[str] = set()
    if not isinstance(files, (list, tuple)):
        return out
    for f in files:
        if not isinstance(f, dict):
            continue
        path = str(f.get("path") or "").strip()
        kind = str(f.get("kind") or "credentials")
        if not path or path in seen:
            continue
        if kind not in FILE_TEMPLATES:
            kind = "credentials"
        seen.add(path)
        out.append({"path": path[:400], "kind": kind})
    return out[:50]

# How long to suppress repeat alerts from the same (pod, source IP).
_ALERT_DEDUP_SECONDS = 300


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> tuple[str, str]:
    """Return (clear_token, token_hash). The clear token is shown once."""
    tok = "hp_" + secrets.token_urlsafe(30)
    return tok, hash_token(tok)


def normalize_services(services) -> dict[str, bool]:
    """Coerce arbitrary input into {service: bool} over the known service names."""
    out = {name: False for name in SERVICES}
    if isinstance(services, dict):
        for k, v in services.items():
            if k in out:
                out[k] = bool(v)
    elif isinstance(services, (list, tuple)):
        for k in services:
            if k in out:
                out[k] = True
    return out


def desired_ports(services: dict[str, bool]) -> list[dict]:
    """The list of {service, port} the agent should be listening on."""
    return [{"service": name, "port": SERVICES[name]["port"]}
            for name, on in (services or {}).items() if on and name in SERVICES]


async def authenticate(token: str | None) -> Honeypot | None:
    """Resolve a pod by its bearer token (constant-time via hash lookup)."""
    if not token:
        return None
    th = hash_token(token.strip())
    async with async_session() as db:
        return (await db.execute(
            select(Honeypot).where(Honeypot.token_hash == th)
        )).scalar_one_or_none()


async def touch(pod_id: str, host_ip: str | None, host_info: dict | None) -> dict:
    """Record a heartbeat and return the pod's desired service config."""
    now = datetime.now(timezone.utc)
    async with async_session() as db:
        pod = await db.get(Honeypot, pod_id)
        if pod is None:
            return {"enabled": False, "listen": []}
        pod.last_seen = now
        if host_ip:
            pod.host_ip = host_ip
        if host_info:
            pod.host_info = host_info
        await db.commit()
        services = pod.services or {}
        files = pod.files or []
        enabled = bool(pod.enabled)
    return {
        "enabled": enabled,
        "heartbeat_seconds": 30,
        "listen": desired_ports(services) if enabled else [],
        "files": files if enabled else [],
    }


def _alert_html(pod_name: str, ev: dict, geo: dict | None) -> str:
    # File-honeypot events (a decoy file was touched) read very differently from
    # a network hit — surface the path + accessing process/user.
    if ev.get("service") == "file":
        p = ev.get("payload") or {}
        who = ""
        if p.get("process") or p.get("user"):
            who = f"\nProzess: <code>{p.get('process','?')}</code> · User: <code>{p.get('user','?')}</code>"
        return (f"🪤 <b>Datei-Honeypot ausgelöst</b>\n"
                f"Pod: <b>{pod_name}</b>\n"
                f"Datei: <code>{p.get('path','?')}</code>\n"
                f"Zugriff: {p.get('access','?')}{who}")
    svc = SERVICES.get(ev.get("service"), {}).get("label", ev.get("service") or "?")
    src = ev.get("source_ip") or "?"
    loc = ""
    if geo and geo.get("country"):
        loc = f" ({geo['country']}{'/' + geo['city'] if geo.get('city') else ''})"
    p = ev.get("payload") or {}
    cred = ""
    if p.get("username") or p.get("password"):
        cred = f"\nLogin: <code>{p.get('username','')}</code> / <code>{p.get('password','')}</code>"
    req = ""
    if p.get("http_method"):
        req = f"\n{p.get('http_method')} <code>{(p.get('path') or '')[:120]}</code>"
    return (f"🍯 <b>Honeypot-Zugriff</b> — {svc}\n"
            f"Pod: <b>{pod_name}</b>\n"
            f"Quelle: <code>{src}</code>{loc} → Port {ev.get('dest_port','?')}"
            f"{cred}{req}")


async def _should_alert(pod_id: str, ident: str) -> bool:
    """First hit for a (pod, ident) within the window alerts; repeats are muted.
    ``ident`` is the source IP for network hits, or ``file:<path>`` for a decoy
    file (so different files / attackers each alert independently)."""
    redis = await get_redis()
    if not redis:
        return True
    try:
        key = f"hp:alert:{pod_id}:{ident}"
        # SET NX EX — true only when the key didn't exist yet.
        return bool(await redis.set(key, "1", ex=_ALERT_DEDUP_SECONDS, nx=True))
    except Exception:
        return True


def _clean(obj):
    """Strip characters Postgres JSONB rejects (NUL / \\u0000 and other C0
    controls) from any string in the payload. Attacker-controlled bytes reach
    us here, so this must be defensive."""
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\t" or c == "\n" or c == "\r" or ord(c) >= 0x20)
    if isinstance(obj, dict):
        return {str(k): _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj


async def ingest_events(pod: Honeypot, events: list[dict]) -> int:
    """Persist a batch of honeypot events (geo-enriched) and alert on new
    sources. Returns the number stored."""
    if not events:
        return 0
    stored = 0
    to_alert: list[tuple[dict, dict | None]] = []
    async with async_session() as db:
        for ev in events[:500]:
            src = (ev.get("source_ip") or "").strip() or None
            geo = None
            if src:
                try:
                    geo = await lookup_ip(src, db)
                except Exception:
                    geo = None
            row = HoneypotEvent(
                honeypot_id=pod.id,
                service=(ev.get("service") or "")[:20] or None,
                event_type=(ev.get("event_type") or "connect")[:20],
                source_ip=src,
                source_port=ev.get("source_port"),
                dest_port=ev.get("dest_port"),
                payload=_clean(ev.get("payload")) or None,
                attacker_country=(geo or {}).get("country"),
                attacker_city=(geo or {}).get("city"),
                attacker_asn=str((geo or {}).get("asn")) if (geo or {}).get("asn") else None,
                attacker_org=(geo or {}).get("org"),
            )
            db.add(row)
            stored += 1
            # Dedup identity: the decoy file for file events, else the source IP.
            if ev.get("service") == "file":
                ident = "file:" + str((ev.get("payload") or {}).get("path") or "?")
            else:
                ident = src
            if ident and await _should_alert(pod.id, ident):
                to_alert.append((ev, geo))
        await db.commit()

    # Fan out alerts after commit (best-effort).
    if to_alert:
        from app.notifications import notify
        for ev, geo in to_alert[:20]:
            try:
                await notify(_alert_html(pod.name, ev, geo), title="Warroom · Honeypot")
            except Exception as e:
                logger.warning(f"honeypot alert failed: {e}")
    return stored
