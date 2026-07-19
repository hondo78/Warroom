"""MCP server exposing read-only search over the Warroom firewall syslogs.

Mounted into the FastAPI app at ``/mcp`` (Streamable HTTP transport) so an LLM /
MCP client (Claude Desktop/Code, …) can query the ``firewall_logs`` table with
structured tools instead of raw SQL. Gated by ``mcp_enabled`` and a dedicated
bearer token (``mcp_api_key``) — see ``_MCPAuth`` below.

Every tool is read-only and time-bounded (the table holds ~20M rows), uses
parameterized SQL, and only ever interpolates allow-listed column names.
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
    return {"osint": await osint.enrich_live(ips or [], cap=limit)}


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
