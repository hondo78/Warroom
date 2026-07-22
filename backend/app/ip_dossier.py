"""Aggregate everything Warroom knows about a single IP into one 'dossier'.

Pulls from every relevant source — firewall syslogs, NetFlow, OSINT (incl. Tor),
honeypot hits, blocklist/whitelist provenance, AI-agent decisions, and host
identity — for fast triage. All firewall/netflow queries are index-driven
(source_ip/destination_ip/src_ip/dst_ip + a time window) so they stay fast on the
large tables.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, text

from app import osint
from app.database import async_session
from app.models import BlockedIp, IpHostname, WhitelistedIp

logger = logging.getLogger(__name__)


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


async def _fw_direction(db, col: str, ip: str, since: datetime, with_ports: bool) -> dict:
    base = f"WHERE {col} = :ip AND created_at >= :since"
    p = {"ip": ip, "since": since}
    agg = (await db.execute(text(
        f"SELECT count(*) c, min(created_at) f, max(created_at) l FROM firewall_logs {base}"
    ), p)).first()
    out: dict[str, Any] = {"count": int(agg[0] or 0), "first_seen": _iso(agg[1]), "last_seen": _iso(agg[2])}
    if not out["count"]:
        return out
    out["top_actions"] = [
        {"action": r[0], "count": int(r[1])} for r in (await db.execute(text(
            f"SELECT action, count(*) c FROM firewall_logs {base} AND action IS NOT NULL "
            f"GROUP BY action ORDER BY c DESC LIMIT 5"), p)).all()
    ]
    if with_ports:
        out["top_dst_ports"] = [
            {"port": r[0], "count": int(r[1])} for r in (await db.execute(text(
                f"SELECT destination_port, count(*) c FROM firewall_logs {base} "
                f"AND destination_port IS NOT NULL GROUP BY destination_port "
                f"ORDER BY c DESC LIMIT 5"), p)).all()
        ]
    return out


async def _netflow(db, ip: str, since: datetime) -> dict:
    out = (await db.execute(text(
        "SELECT "
        " (SELECT COALESCE(sum(flows),0) FROM netflow_buckets WHERE src_ip=:ip AND bucket_start>=:s),"
        " (SELECT COALESCE(sum(bytes),0) FROM netflow_buckets WHERE src_ip=:ip AND bucket_start>=:s),"
        " (SELECT COALESCE(sum(flows),0) FROM netflow_buckets WHERE dst_ip=:ip AND bucket_start>=:s),"
        " (SELECT COALESCE(sum(bytes),0) FROM netflow_buckets WHERE dst_ip=:ip AND bucket_start>=:s)"
    ), {"ip": ip, "s": since})).first()
    top_ports = [
        {"port": r[0], "flows": int(r[1])} for r in (await db.execute(text(
            "SELECT dst_port, sum(flows) f FROM netflow_buckets "
            "WHERE src_ip=:ip AND bucket_start>=:s AND dst_port IS NOT NULL "
            "GROUP BY dst_port ORDER BY f DESC LIMIT 5"), {"ip": ip, "s": since})).all()
    ]
    return {
        "out_flows": int(out[0] or 0), "out_bytes": int(out[1] or 0),
        "in_flows": int(out[2] or 0), "in_bytes": int(out[3] or 0),
        "top_dst_ports": top_ports,
    }


async def _honeypot(db, ip: str) -> dict:
    r = (await db.execute(text(
        "SELECT count(*), max(created_at), "
        " array_agg(DISTINCT event_type) FILTER (WHERE event_type IS NOT NULL), "
        " array_agg(DISTINCT honeypot_id) FILTER (WHERE honeypot_id IS NOT NULL) "
        "FROM honeypot_events WHERE source_ip = :ip"), {"ip": ip})).first()
    return {
        "hits": int(r[0] or 0), "last_seen": _iso(r[1]),
        "event_types": list(r[2] or []), "honeypots": list(r[3] or []),
    }


async def _agent(db, ip: str) -> list[dict]:
    rows = (await db.execute(text(
        "SELECT action, status, source_type, created_at, left(reasoning, 400) "
        "FROM agent_decisions WHERE source_ip = :ip ORDER BY id DESC LIMIT 8"
    ), {"ip": ip})).all()
    return [
        {"action": r[0], "status": r[1], "source_type": r[2],
         "created_at": _iso(r[3]), "reasoning": r[4]}
        for r in rows
    ]


def _osint_slim(payload: dict) -> dict:
    s = osint._risk_summary(payload)
    tor = payload.get("tor") or {}
    sh = payload.get("shodan") or {}
    s["tor_exit_node"] = bool(tor.get("is_exit_node"))
    s["rdns"] = (payload.get("rdns") or {}).get("hostname")
    s["shodan_ports"] = sh.get("ports") if isinstance(sh.get("ports"), list) else None
    s["shodan_cves"] = len(sh.get("vulns") or []) if isinstance(sh.get("vulns"), (list, dict)) else None
    return s


async def build_dossier(ip: str, days: int = 30) -> dict:
    """Everything known about `ip` over the last `days`."""
    since = datetime.now(timezone.utc) - timedelta(days=max(1, days))
    out: dict[str, Any] = {"ip": ip, "is_public": osint.is_public(ip), "days": days}

    async with async_session() as db:
        b = await db.get(BlockedIp, ip)
        out["blocklist"] = ({
            "blocked": True, "comment": b.comment, "source": b.source,
            "blocked_by": b.blocked_by, "blocked_at": _iso(b.blocked_at),
            "monitored": bool(b.monitored),
        } if b else {"blocked": False})

        w = await db.get(WhitelistedIp, ip)
        out["whitelist"] = ({"whitelisted": True, "source": w.source, "comment": w.comment}
                            if w else {"whitelisted": False})

        h = await db.get(IpHostname, ip)
        out["host"] = ({"hostname": h.hostname, "mac": h.mac, "source": h.source,
                        "resolved_at": _iso(h.resolved_at)} if h else None)

        out["firewall"] = {
            "as_source": await _fw_direction(db, "source_ip", ip, since, with_ports=True),
            "as_destination": await _fw_direction(db, "destination_ip", ip, since, with_ports=False),
        }
        out["netflow"] = await _netflow(db, ip, since)
        out["honeypot"] = await _honeypot(db, ip)
        out["agent_decisions"] = await _agent(db, ip)

    if out["is_public"]:
        try:
            out["osint"] = _osint_slim(await osint.lookup(ip))
        except Exception as e:
            out["osint"] = {"error": str(e)[:120]}
    else:
        out["osint"] = None
    return out
