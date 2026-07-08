"""Connection monitoring for specially-flagged ("monitored") IPs.

Some blocklist / watchlist IPs are flagged for monitoring. This job runs on a
short interval and answers: *which of my internal hosts talk to these IPs, and
when?* It reads the NetFlow ledger, maintains a persistent baseline of
(host ↔ monitored-IP) pairs (NetFlow itself only keeps ~30 days), and raises an
event — pushed to Telegram / Teams — whenever:

  * a host talks to a monitored IP for the **first time** (`new_pair`), or
  * a **known** pair resurfaces after a quiet gap (`reappeared`).

Continuously-active pairs keep their `last_seen` fresh and do not re-alert.
"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from app.config import settings
from app.database import async_session
from app.models import BlockedIp, MonitoredConnection, MonitoredEvent, WatchlistIp

logger = logging.getLogger(__name__)

_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def _proto_name(p) -> str:
    if p is None:
        return "-"
    return _PROTO.get(int(p), f"proto-{p}")


async def _load_monitored(db) -> dict[str, dict]:
    """Return {ip -> {"lists": {names}, "comment": str|None}} for every IP flagged
    monitored on either list. The watchlist comment is preferred (the user reads
    it in the alert), falling back to the blocklist comment."""
    out: dict[str, dict] = {}
    for ip, comment in (await db.execute(
        select(BlockedIp.ip, BlockedIp.comment).where(BlockedIp.monitored.is_(True))
    )).all():
        e = out.setdefault(ip, {"lists": set(), "comment": None})
        e["lists"].add("blocked")
        if comment and not e["comment"]:
            e["comment"] = comment
    for ip, comment in (await db.execute(
        select(WatchlistIp.ip, WatchlistIp.comment).where(WatchlistIp.monitored.is_(True))
    )).all():
        e = out.setdefault(ip, {"lists": set(), "comment": None})
        e["lists"].add("watchlist")
        if comment:                      # watchlist comment takes precedence
            e["comment"] = comment
    return out


async def _netflow_pairs(db, ips: list[str], since: datetime, direction: str) -> dict:
    """Aggregate NetFlow for the given monitored IPs in one direction.

    outbound → host is the source (host → monitored IP), so the monitored IP is
    dst_ip. inbound → host is the destination (monitored IP → host).
    Returns {(monitored_ip, host_ip): {bytes, flows, first, last, port, proto}}.
    """
    if direction == "outbound":
        mip_col, host_col = "dst_ip", "src_ip"
    else:
        mip_col, host_col = "src_ip", "dst_ip"

    sql = text(f"""
        SELECT n.{mip_col} AS mip, n.{host_col} AS host,
               n.dst_port AS port, n.protocol AS proto,
               SUM(n.bytes) AS bytes, SUM(n.flows) AS flows,
               MIN(n.bucket_start) AS first_seen, MAX(n.bucket_start) AS last_seen
        FROM netflow_buckets n
        WHERE n.{mip_col} = ANY(:ips) AND n.bucket_start >= :since
              AND n.{host_col} IS NOT NULL
        GROUP BY n.{mip_col}, n.{host_col}, n.dst_port, n.protocol
    """)
    rows = (await db.execute(sql, {"ips": ips, "since": since})).all()

    agg: dict[tuple, dict] = {}
    for mip, host, port, proto, byts, flows, first_seen, last_seen in rows:
        key = (mip, host)
        cur = agg.get(key)
        if cur is None:
            cur = {"bytes": 0, "flows": 0, "first": first_seen, "last": last_seen,
                   "port": port, "proto": proto, "_top": -1}
            agg[key] = cur
        cur["bytes"] += int(byts or 0)
        cur["flows"] += int(flows or 0)
        if first_seen and (cur["first"] is None or first_seen < cur["first"]):
            cur["first"] = first_seen
        if last_seen and (cur["last"] is None or last_seen > cur["last"]):
            cur["last"] = last_seen
        # Keep the (port, proto) that moved the most bytes as the representative.
        if int(byts or 0) > cur["_top"]:
            cur["_top"] = int(byts or 0)
            cur["port"], cur["proto"] = port, proto
    return agg


async def _countries(db, ips: list[str]) -> dict[str, str]:
    if not ips:
        return {}
    rows = (await db.execute(
        text("SELECT ip, country FROM geoip_cache WHERE ip = ANY(:ips)"),
        {"ips": ips},
    )).all()
    return {r[0]: r[1] for r in rows if r[1]}


def _fmt_event(ev_type: str, host: str, mip: str, direction: str,
               port, proto, country: str | None, lists: set[str],
               comment: str | None = None) -> str:
    import html
    icon = "🆕" if ev_type == "new_pair" else "🔁"
    verb = ("Neue Verbindung zu überwachter IP" if ev_type == "new_pair"
            else "Überwachte Verbindung wieder aktiv")
    arrow = f"{host} → {mip}" if direction == "outbound" else f"{mip} → {host}"
    loc = f" ({country})" if country else ""
    src = "/".join(sorted(lists)) if lists else "?"
    port_s = f"{port}/{_proto_name(proto)}" if port is not None else _proto_name(proto)
    msg = (f"{icon} <b>{verb}</b>\n"
           f"Host: <code>{host}</code>\n"
           f"Überwachte IP: <code>{mip}</code>{loc} [{src}]\n"
           f"Richtung: {arrow} · Port {port_s}")
    if comment:
        # Free-text comment — escape so it can't break Telegram's HTML parse.
        msg += f"\nKommentar: {html.escape(comment)}"
    return msg


async def monitor_scan() -> dict:
    """One scan pass. Returns a small summary dict (also handy for tests)."""
    if not settings.ip_monitor_enabled:
        return {"skipped": "disabled"}

    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=max(1, settings.ip_monitor_lookback_minutes))
    gap = timedelta(hours=max(1, settings.ip_monitor_session_gap_hours))
    cap = max(1, settings.ip_monitor_max_alerts_per_scan)

    pending_notifs: list[tuple[int, str]] = []   # (event_id, html) to send after commit
    new_pairs = reappeared = 0

    async with async_session() as db:
        monitored = await _load_monitored(db)
        if not monitored:
            return {"monitored_ips": 0}
        ips = list(monitored.keys())
        countries = await _countries(db, ips)

        # NetFlow can be slow; bound it and never let the scan hang.
        await db.execute(text("SET LOCAL statement_timeout = '12s'"))
        observed: dict[tuple, dict] = {}
        for direction in ("outbound", "inbound"):
            for (mip, host), v in (await _netflow_pairs(db, ips, since, direction)).items():
                observed[(mip, host, direction)] = v

        for (mip, host, direction), v in observed.items():
            row = (await db.execute(
                select(MonitoredConnection).where(
                    MonitoredConnection.monitored_ip == mip,
                    MonitoredConnection.host_ip == host,
                    MonitoredConnection.direction == direction,
                )
            )).scalar_one_or_none()

            ev_type = None
            if row is None:
                ev_type = "new_pair"
                row = MonitoredConnection(
                    monitored_ip=mip, host_ip=host, direction=direction,
                    first_seen=v["first"], last_seen=v["last"],
                    flows=v["flows"], bytes=v["bytes"],
                    dst_port=v["port"], protocol=v["proto"],
                    country=countries.get(mip),
                )
                db.add(row)
            else:
                # Known pair: a stale last_seen means it resurfaced after a gap.
                if row.last_seen is not None and (now - row.last_seen) >= gap:
                    ev_type = "reappeared"
                if v["first"] and (row.first_seen is None or v["first"] < row.first_seen):
                    row.first_seen = v["first"]
                if v["last"] and (row.last_seen is None or v["last"] > row.last_seen):
                    row.last_seen = v["last"]
                row.flows = (row.flows or 0) + v["flows"]
                row.bytes = (row.bytes or 0) + v["bytes"]
                row.dst_port, row.protocol = v["port"], v["proto"]
                if countries.get(mip):
                    row.country = countries[mip]

            if ev_type:
                if ev_type == "new_pair":
                    new_pairs += 1
                else:
                    reappeared += 1
                row.last_notified_at = now
                row.notify_count = (row.notify_count or 0) + 1
                minfo = monitored[mip]
                ev = MonitoredEvent(
                    monitored_ip=mip, host_ip=host, direction=direction,
                    event_type=ev_type, dst_port=v["port"], protocol=v["proto"],
                    country=countries.get(mip), source_list="/".join(sorted(minfo["lists"])),
                )
                db.add(ev)
                await db.flush()   # get ev.id
                html = _fmt_event(ev_type, host, mip, direction, v["port"],
                                  v["proto"], countries.get(mip), minfo["lists"],
                                  minfo["comment"])
                pending_notifs.append((ev.id, html))

        await db.commit()

    # Fan out notifications (best-effort) after the DB is consistent, honouring
    # the per-scan cap so a burst can't flood the channels.
    if pending_notifs:
        from app.notifications import notify
        sent = 0
        for ev_id, html in pending_notifs:
            if sent >= cap:
                logger.warning(f"ip_monitor: {len(pending_notifs) - cap} more events not "
                               f"pushed this scan (cap {cap})")
                break
            body = html + (f"\n<i>… und {len(pending_notifs) - cap} weitere</i>"
                           if len(pending_notifs) > cap and sent == cap - 1 else "")
            res = await notify(body, title="Warroom · IP-Überwachung")
            async with async_session() as db2:
                ev = await db2.get(MonitoredEvent, ev_id)
                if ev:
                    ev.notified = bool(res["channels"])
                    ev.notify_error = "; ".join(f"{k}:{v}" for k, v in res["errors"].items()) or None
                    await db2.commit()
            sent += 1

    return {"monitored_ips": len(monitored), "observed": len(observed),
            "new_pairs": new_pairs, "reappeared": reappeared,
            "notified": len(pending_notifs)}
