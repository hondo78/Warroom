"""MCP server exposing read-only search over the Warroom firewall syslogs.

Mounted into the FastAPI app at ``/mcp`` (Streamable HTTP transport) so an LLM /
MCP client (Claude Desktop/Code, …) can query the ``firewall_logs`` table with
structured tools instead of raw SQL. Gated by ``mcp_enabled`` and a dedicated
bearer token (``mcp_api_key``) — see ``_MCPAuth`` below.

Every log/query tool is read-only and time-bounded (the table holds ~20M rows),
uses parameterized SQL, and only ever interpolates allow-listed column names.

The ``tor_*`` tools are the exception and the reason this line is worth reading
carefully: ``tor_run`` executes a recon command on the Kali box. It is gated by
``kali_mcp_enabled``, guarded by :mod:`app.kali_client` (binary allow-list,
target allow-list, dangerous-pattern rules) and re-validated on the box itself,
but it is not read-only — treat this surface as such when adding tools.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import text as sa_text

from app.config import settings
from app.database import async_session

logger = logging.getLogger(__name__)

# streamable_http_path="/" so, mounted at /mcp, the endpoint is a clean /mcp
# (Starlette 307-redirects /mcp -> /mcp/) instead of /mcp/mcp.
# DNS-rebinding protection validates the Host header, which we can't predict
# behind nginx/NPM — the bearer token (_MCPAuth) is the real guard, so disable it.
mcp = FastMCP(
    "warroom-logs",
    stateless_http=True,
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

# Columns returned by search_logs — a useful, compact projection.
_SELECT_COLS = (
    "id, created_at, log_type, log_subtype, severity, firewall_name, firewall_ip, "
    "source_ip, source_port, destination_ip, destination_port, protocol, "
    "action, rule_name, policy_name, threat_name, user_name, "
    "attacker_country, attacker_city, attacker_asn, attacker_org, "
    "left(message, 500) AS message"
)

# Fields that may be used as a GROUP BY target or an equality filter. Interpolated
# into SQL, so this allow-list is the injection guard — never widen it to raw input.
_GROUPABLE = {
    "source_ip", "destination_ip", "firewall_ip", "firewall_name",
    "action", "log_type", "log_subtype", "severity", "protocol",
    "destination_port", "source_port", "user_name", "threat_name",
    "rule_name", "policy_name", "attacker_country", "attacker_org", "attacker_asn",
}


def _time_clause(params: dict, hours, start, end) -> str:
    """Build the mandatory created_at window. Defaults to the last 24h when the
    caller gives no bound, so no tool ever scans the whole table."""
    clauses = []
    if start:
        params["start"] = start
        clauses.append("created_at >= :start")
    if end:
        params["end"] = end
        clauses.append("created_at <= :end")
    if not start and not end:
        h = int(hours) if hours else 24
        params["since"] = datetime.now(timezone.utc) - timedelta(hours=max(1, h))
        clauses.append("created_at >= :since")
    elif hours and not start:
        params["since"] = datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours)))
        clauses.append("created_at >= :since")
    return " AND ".join(clauses)


def _filters(params: dict, **kw) -> list[str]:
    """Equality / ILIKE filters shared by search + count + aggregate."""
    clauses = []
    exact = {
        "source_ip": "source_ip", "destination_ip": "destination_ip",
        "firewall_ip": "firewall_ip", "severity": "severity",
        "protocol": "protocol", "destination_port": "destination_port",
        "source_port": "source_port", "attacker_country": "attacker_country",
    }
    like = {
        "action": "action", "log_type": "log_type", "user_name": "user_name",
        "threat_name": "threat_name", "firewall_name": "firewall_name",
    }
    for key, col in exact.items():
        v = kw.get(key)
        if v is not None and v != "":
            params[key] = v
            clauses.append(f"{col} = :{key}")
    for key, col in like.items():
        v = kw.get(key)
        if v is not None and v != "":
            params[key] = f"%{v}%"
            clauses.append(f"{col} ILIKE :{key}")
    txt = kw.get("text")
    if txt:
        params["text"] = f"%{txt}%"
        clauses.append("message ILIKE :text")
    return clauses


def _row_to_dict(row) -> dict:
    d = dict(row._mapping)
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


@mcp.tool()
async def search_logs(
    hours: int | None = None,
    start: str | None = None,
    end: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    firewall_ip: str | None = None,
    firewall_name: str | None = None,
    action: str | None = None,
    log_type: str | None = None,
    severity: str | None = None,
    protocol: str | None = None,
    destination_port: int | None = None,
    source_port: int | None = None,
    user_name: str | None = None,
    threat_name: str | None = None,
    attacker_country: str | None = None,
    text: str | None = None,
    limit: int = 50,
) -> dict:
    """Search firewall syslogs (SFOS/Sophos) with structured filters, newest first.

    Always time-bounded — pass `hours` (last N hours) or `start`/`end` (ISO-8601);
    with none given it defaults to the last 24 hours. `action`, `log_type`,
    `user_name`, `threat_name`, `firewall_name` and `text` (searches the message)
    match case-insensitively (substring); IPs, ports, severity, protocol and
    country match exactly. `limit` is capped at 500. Prefer structured filters
    over `text` for speed on this ~20M-row table.
    """
    limit = max(1, min(int(limit), 500))
    params: dict = {}
    where = [_time_clause(params, hours, start, end)]
    where += _filters(
        params, source_ip=source_ip, destination_ip=destination_ip,
        firewall_ip=firewall_ip, firewall_name=firewall_name, action=action,
        log_type=log_type, severity=severity, protocol=protocol,
        destination_port=destination_port, source_port=source_port,
        user_name=user_name, threat_name=threat_name,
        attacker_country=attacker_country, text=text)
    where = [c for c in where if c]
    params["limit"] = limit
    sql = (f"SELECT {_SELECT_COLS} FROM firewall_logs "
           f"WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT :limit")
    async with async_session() as db:
        rows = (await db.execute(sa_text(sql), params)).fetchall()
    dict_rows = [_row_to_dict(r) for r in rows]

    # Hand the LLM OSINT context for the external IPs in the result — from cache/
    # history + the free Tor check only (no provider calls / quota). IPs with no
    # cached data come back {"cached": false}; the LLM should ask the user before
    # fetching fresh OSINT for them via the osint_lookup tool.
    from app import osint
    ip_candidates = [r[k] for r in dict_rows for k in ("source_ip", "destination_ip") if r.get(k)]
    osint_map = await osint.enrich_cached(ip_candidates, cap=30)
    result = {"returned": len(dict_rows), "rows": dict_rows, "osint": osint_map}
    uncached = [ip for ip, v in osint_map.items() if not v.get("cached")]
    if uncached:
        result["osint_note"] = (
            f"{len(uncached)} external IP(s) have no cached OSINT (Tor status only). "
            "Ask the user whether to fetch full OSINT, then call osint_lookup with those IPs: "
            + ", ".join(uncached[:15])
        )
    return result


@mcp.tool()
async def count_logs(
    hours: int | None = None,
    start: str | None = None,
    end: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    firewall_ip: str | None = None,
    action: str | None = None,
    log_type: str | None = None,
    severity: str | None = None,
    protocol: str | None = None,
    destination_port: int | None = None,
    user_name: str | None = None,
    threat_name: str | None = None,
    attacker_country: str | None = None,
    text: str | None = None,
) -> dict:
    """Count firewall syslogs matching the filters over a time window (same
    filters as search_logs). Time-bounded; defaults to the last 24 hours."""
    params: dict = {}
    where = [_time_clause(params, hours, start, end)]
    where += _filters(
        params, source_ip=source_ip, destination_ip=destination_ip,
        firewall_ip=firewall_ip, action=action, log_type=log_type,
        severity=severity, protocol=protocol, destination_port=destination_port,
        user_name=user_name, threat_name=threat_name,
        attacker_country=attacker_country, text=text)
    where = [c for c in where if c]
    sql = f"SELECT count(*) AS c FROM firewall_logs WHERE {' AND '.join(where)}"
    async with async_session() as db:
        c = await db.scalar(sa_text(sql), params)
    return {"count": int(c or 0)}


@mcp.tool()
async def aggregate_logs(
    group_by: str,
    hours: int = 24,
    top: int = 20,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    action: str | None = None,
    log_type: str | None = None,
    severity: str | None = None,
    attacker_country: str | None = None,
) -> dict:
    """Top-N counts grouped by a field over a time window — e.g. the noisiest
    source_ip, most common action, top threat_name or attacker_country.

    `group_by` must be one of: source_ip, destination_ip, firewall_ip,
    firewall_name, action, log_type, log_subtype, severity, protocol,
    destination_port, source_port, user_name, threat_name, rule_name,
    policy_name, attacker_country, attacker_org, attacker_asn. Optional filters
    narrow the set first. `top` is capped at 200; `hours` defaults to 24.
    """
    if group_by not in _GROUPABLE:
        return {"error": f"group_by must be one of: {sorted(_GROUPABLE)}"}
    top = max(1, min(int(top), 200))
    params: dict = {}
    where = [_time_clause(params, hours, None, None)]
    where += _filters(
        params, source_ip=source_ip, destination_ip=destination_ip,
        action=action, log_type=log_type, severity=severity,
        attacker_country=attacker_country)
    where = [c for c in where if c]
    params["top"] = top
    sql = (f"SELECT {group_by} AS key, count(*) AS count FROM firewall_logs "
           f"WHERE {' AND '.join(where)} AND {group_by} IS NOT NULL "
           f"GROUP BY {group_by} ORDER BY count DESC LIMIT :top")
    async with async_session() as db:
        rows = (await db.execute(sa_text(sql), params)).fetchall()
    return {"group_by": group_by, "buckets": [{"key": r[0], "count": int(r[1])} for r in rows]}


@mcp.tool()
async def osint_lookup(ips: list[str], limit: int = 10) -> dict:
    """Run a LIVE OSINT lookup (AbuseIPDB, VirusTotal, GreyNoise, Tor — no Shodan)
    for the given external IPs and return a risk summary per IP.

    Use this ONLY after asking the user whether to run it — typically for IPs that
    search_logs reported as OSINT-uncached (osint_note). Distinct public IPs only,
    capped at `limit` (max 15); results are cached for reuse. Costs provider quota,
    so keep the list small."""
    from app import osint
    limit = max(1, min(int(limit), 15))
    return {"osint": await osint.enrich_live(ips or [], cap=limit, context="mcp")}


@mcp.tool()
async def ip_dossier(ip: str, days: int = 30) -> dict:
    """Everything Warroom knows about one IP in a single view: firewall-log
    activity (as source and destination), NetFlow volume, OSINT + Tor exit-node
    status, honeypot hits, blocklist/whitelist status, recent AI-agent decisions,
    and host identity (hostname/MAC for internal IPs). Read-only — use it to
    triage an IP you found in the logs."""
    from app.ip_dossier import build_dossier
    return await build_dossier(ip, max(1, min(int(days), 365)))


@mcp.tool()
async def describe_logs() -> dict:
    """Describe the firewall_logs dataset: available fields, the current time
    span, total rows, and the distinct values of the key categorical fields
    (log_type, action, severity, protocol) — call this first to learn what to
    filter on."""
    out: dict = {
        "table": "firewall_logs",
        "fields": {
            "time": ["created_at (ISO)"],
            "network": ["source_ip", "source_port", "destination_ip",
                        "destination_port", "protocol", "firewall_ip", "firewall_name"],
            "classification": ["log_type", "log_subtype", "severity", "action",
                               "rule_name", "policy_name", "threat_name", "user_name"],
            "geo (external IP)": ["attacker_country", "attacker_city",
                                  "attacker_asn", "attacker_org"],
            "raw": ["message (full text)", "raw_data (jsonb)"],
        },
        "tools": ["search_logs", "count_logs", "aggregate_logs"],
    }
    async with async_session() as db:
        span = (await db.execute(sa_text(
            "SELECT count(*) AS n, min(created_at) AS oldest, max(created_at) AS newest "
            "FROM firewall_logs"))).first()
        out["total_rows"] = int(span[0] or 0)
        out["oldest"] = span[1].isoformat() if span[1] else None
        out["newest"] = span[2].isoformat() if span[2] else None
        # Distinct values for the small categorical fields (last 7 days, bounded).
        since = datetime.now(timezone.utc) - timedelta(days=7)
        for col in ("log_type", "action", "severity", "protocol"):
            vals = (await db.execute(sa_text(
                f"SELECT DISTINCT {col} FROM firewall_logs "
                f"WHERE created_at >= :since AND {col} IS NOT NULL LIMIT 60"
            ), {"since": since})).fetchall()
            out.setdefault("distinct_values_last_7d", {})[col] = sorted(v[0] for v in vals)
    return out


@mcp.tool()
async def tor_run(command: str) -> dict:
    """Run a single recon/OSINT command on the Tor-only Kali box (egress is
    anonymized through Tor). This is NOT a shell: exactly one program from the
    allow-list (nmap, whois, dig, host, nslookup, curl, wget, whatweb, nikto,
    sslscan, wafw00f, dnsrecon, ncat) with no shell metacharacters, and EVERY
    host/IP/URL argument must be inside the operator's target allow-list —
    scanning anything outside it is refused. Dangerous patterns (reverse shells,
    flood rates, intrusive/brute/exploit scripts) are blocked.

    Depending on policy the command may be queued for human approval before it
    runs (status 'pending') — poll tor_command_status(id) for the result. If it
    returns 'blocked', the reason explains which rule it hit. Use tor_targets()
    to see what you're allowed to scan, and tor_exit_ip() to confirm the Tor
    exit in use."""
    if not settings.kali_mcp_enabled:
        return {"error": "the Kali/Tor MCP surface is disabled (enable kali_mcp_enabled)"}
    from app import kali_client
    return await kali_client.submit_command(command, actor="mcp-agent")


@mcp.tool()
async def tor_command_status(command_id: int) -> dict:
    """Status + output of a previously submitted tor_run command (e.g. one that
    was queued for approval). Returns its status (pending / done / blocked /
    rejected / error), exit code, stdout/stderr and the Tor exit IP used."""
    if not settings.kali_mcp_enabled:
        return {"error": "the Kali/Tor MCP surface is disabled"}
    from app.models import KaliCommand
    async with async_session() as db:
        rec = await db.get(KaliCommand, command_id)
    if rec is None:
        return {"error": "not found"}
    return {"id": rec.id, "status": rec.status, "command": rec.command,
            "targets": rec.targets, "reason": rec.reason, "exit_code": rec.exit_code,
            "stdout": rec.stdout, "stderr": rec.stderr, "tor_exit_ip": rec.tor_exit_ip}


@mcp.tool()
async def tor_targets() -> dict:
    """The target allow-list the Kali box may scan (CIDRs / IPs / domain
    suffixes). Anything not covered here is refused. An empty list means nothing
    is scannable."""
    if not settings.kali_mcp_enabled:
        return {"error": "the Kali/Tor MCP surface is disabled"}
    entries = [e.strip() for e in (settings.kali_target_allowlist or "").split(",") if e.strip()]
    return {"allowlist": entries, "require_approval": bool(settings.kali_require_approval)}


@mcp.tool()
async def tor_exit_ip() -> dict:
    """The current Tor exit IP the Kali box egresses from (and whether Tor
    confirms it). Use to prove traffic is anonymized before/after a run."""
    if not settings.kali_mcp_enabled:
        return {"error": "the Kali/Tor MCP surface is disabled"}
    from app import kali_client
    try:
        return await kali_client.get_exit_ip()
    except Exception as e:
        return {"error": f"could not reach the Tor/Kali box: {str(e)[:300]}"}


class _MCPAuth:
    """ASGI wrapper enforcing the feature flag + bearer token on the /mcp mount.

    Mounted sub-apps bypass the parent FastAPI's global X-API-Key dependency, so
    this is the /mcp endpoint's only guard. Reads settings live (DB-overlaid), so
    toggling mcp_enabled / rotating mcp_api_key takes effect without a restart.
    """

    def __init__(self, app):
        self.app = app

    async def _deny(self, send, status: int, msg: str):
        body = json.dumps({"error": msg}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if not settings.mcp_enabled:
            await self._deny(send, 404, "MCP server disabled")
            return
        expected = (settings.mcp_api_key or "").strip()
        if not expected and (settings.kali_mcp_enabled
                             or settings.mcp_honeypot_reveal_passwords):
            # An empty key leaves this mount open to anyone on the LAN, which was
            # a considered trade while every tool here was read-only log search.
            # tor_run executes recon commands on the Kali box and the honeypot
            # tools can hand out captured plaintext passwords — those surfaces
            # do not get to be anonymous.
            await self._deny(send, 503, "set mcp_api_key before enabling the "
                                        "Kali/Tor or password-reveal MCP tools")
            return
        if expected:
            auth = ""
            for k, v in scope.get("headers", []):
                if k == b"authorization":
                    auth = v.decode()
                    break
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if token != expected:
                await self._deny(send, 401, "invalid or missing bearer token")
                return
        await self.app(scope, receive, send)


def mcp_asgi_app():
    """The auth-wrapped Streamable-HTTP ASGI app to mount at /mcp."""
    return _MCPAuth(mcp.streamable_http_app())


# --- decoy login page ---------------------------------------------------------
# Nobody legitimate reaches the decoy, so every row is hostile by construction —
# which makes it the cleanest dataset in Warroom and the one worth handing to a
# model. Passwords are the exception: they are masked unless the operator turns
# `mcp_honeypot_reveal_passwords` on, because at the other end of this transport
# sits a language model that may not be local.

def _mask(pw: str | None) -> str | None:
    """A password's shape without its value: length and character classes.

    Enough to answer the questions that matter — is this a leaked-credential
    replay, does it look like one of ours, is the attacker guessing patterns —
    without the secret itself crossing the wire."""
    if pw is None:
        return None
    if settings.mcp_honeypot_reveal_passwords:
        return pw
    classes = "".join(sorted({
        "a" if c.islower() else "A" if c.isupper() else
        "9" if c.isdigit() else "#" for c in pw
    }))
    return f"<{len(pw)} chars, classes={classes or '-'}>"


@mcp.tool()
async def honeypot_logins(hours: int = 168, limit: int = 50,
                          kind: str | None = None, q: str | None = None) -> dict:
    """Credentials and probes captured by the decoy login page.

    The decoy is linked from nowhere and grants access to nothing, so every
    entry is an attacker: `kind='login'` means credentials were submitted,
    `kind='probe'` means the page or its API path was merely requested
    (reconnaissance). Filter free-text with `q` over username, source IP and
    path.

    Passwords come back masked as their shape (length + character classes)
    unless the operator has enabled `mcp_honeypot_reveal_passwords` — the
    `passwords_revealed` flag in the response says which you are looking at."""
    hours = max(1, min(int(hours), 24 * 365))
    limit = max(1, min(int(limit), 500))
    where = ["created_at >= :since"]
    params: dict = {"since": datetime.now(timezone.utc) - timedelta(hours=hours),
                    "lim": limit}
    if kind in ("login", "probe"):
        where.append("kind = :kind")
        params["kind"] = kind
    if q:
        where.append("(username ILIKE :q OR source_ip ILIKE :q OR path ILIKE :q)")
        params["q"] = f"%{q.strip()}%"

    async with async_session() as db:
        rows = (await db.execute(sa_text(f"""
            SELECT created_at, kind, method, username, password, source_ip,
                   attacker_country, attacker_org, path, user_agent, action
            FROM honeypot_logins
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC
            LIMIT :lim
        """), params)).all()

    return {
        "hours": hours,
        "passwords_revealed": bool(settings.mcp_honeypot_reveal_passwords),
        "count": len(rows),
        "entries": [{
            "time": r[0].isoformat() if r[0] else None,
            "kind": r[1], "method": r[2], "username": r[3],
            "password": _mask(r[4]),
            "source_ip": r[5], "country": r[6], "org": r[7],
            "path": r[8], "user_agent": r[9], "action": r[10],
        } for r in rows],
    }


@mcp.tool()
async def honeypot_stats(hours: int = 168, top: int = 15) -> dict:
    """Aggregated view of the decoy captures: the most-tried usernames, the
    busiest sources, countries, the paths attackers went looking for, and the
    split between credential submissions and bare probes.

    Start here — it answers "what is being tried against us" in one call,
    without pulling individual rows. Passwords are counted, never returned."""
    hours = max(1, min(int(hours), 24 * 365))
    top = max(1, min(int(top), 50))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    async def _top(col: str, db, only_login: bool = False) -> list[dict]:
        extra = " AND kind = 'login'" if only_login else ""
        rows = (await db.execute(sa_text(f"""
            SELECT {col} AS v, count(*) AS n
            FROM honeypot_logins
            WHERE created_at >= :since AND {col} IS NOT NULL AND {col} <> ''{extra}
            GROUP BY 1 ORDER BY n DESC LIMIT :lim
        """), {"since": since, "lim": top})).all()
        return [{"value": r[0], "count": int(r[1])} for r in rows]

    async with async_session() as db:
        totals = (await db.execute(sa_text("""
            SELECT kind, count(*), count(DISTINCT source_ip)
            FROM honeypot_logins WHERE created_at >= :since GROUP BY kind
        """), {"since": since})).all()
        out = {
            "hours": hours,
            "totals": {r[0]: {"entries": int(r[1]), "distinct_ips": int(r[2])}
                       for r in totals},
            "top_usernames": await _top("username", db, only_login=True),
            "top_sources": await _top("source_ip", db),
            "top_countries": await _top("attacker_country", db),
            "top_orgs": await _top("attacker_org", db),
            "top_paths": await _top("path", db),
            "top_user_agents": await _top("user_agent", db),
        }
        # Password *shapes*, never values: the length distribution says whether
        # someone is spraying a leaked list or hand-guessing.
        lens = (await db.execute(sa_text("""
            SELECT length(password) AS l, count(*) FROM honeypot_logins
            WHERE created_at >= :since AND password IS NOT NULL AND password <> ''
            GROUP BY 1 ORDER BY 2 DESC LIMIT 15
        """), {"since": since})).all()
        out["password_lengths"] = [{"length": int(r[0]), "count": int(r[1])} for r in lens]
    return out
