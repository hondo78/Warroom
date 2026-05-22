"""NetFlow v9 / IPFIX collector.

Listens on UDP, parses incoming flow records, aggregates them in 60-second
buckets and writes them into the `netflow_buckets` table. Buckets are keyed
by (firewall_ip, src_ip, dst_ip, dst_port, protocol) — high-cardinality
enough for top-talker / top-port analytics, low enough that hourly DB load
stays sane.

Retention: rows older than `RETENTION_DAYS` are deleted hourly.
"""
import asyncio
import logging
import os
import socket
import struct
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("netflow")

DATABASE_URL = os.environ["DATABASE_URL"]
PORT = int(os.environ.get("NETFLOW_PORT", "2055"))
BUCKET_INTERVAL = int(os.environ.get("BUCKET_INTERVAL", "60"))
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=5)
Session = async_sessionmaker(engine, expire_on_commit=False)

# v9 templates are stateful: each exporter sends templates first; data records
# afterwards reference them by (source_id, template_id). We cache them per
# exporter source.
_v9_templates: dict = {}
_ipfix_templates: dict = {}

# Aggregation buffer keyed by tuple; flushed periodically.
_buffer: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0, "flows": 0})
_iface_buffer: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0, "flows": 0})
_buffer_lock = asyncio.Lock()


def _ipv4(addr: int | bytes) -> str:
    if isinstance(addr, int):
        return socket.inet_ntoa(struct.pack("!I", addr & 0xFFFFFFFF))
    if isinstance(addr, bytes) and len(addr) == 4:
        return socket.inet_ntoa(addr)
    return str(addr)


def _ipv6(addr: bytes) -> str:
    if isinstance(addr, bytes) and len(addr) == 16:
        return socket.inet_ntop(socket.AF_INET6, addr)
    return str(addr)


def _extract_field(flow_data: dict, *keys, default=None):
    """NetFlow libs name fields differently per version. Try multiple keys."""
    for k in keys:
        if k in flow_data and flow_data[k] is not None:
            return flow_data[k]
    return default


async def _ingest_flow(exporter_ip: str, flow_data: dict) -> None:
    """Map one flow record to a bucket key and accumulate counters."""
    src = _extract_field(flow_data, "IPV4_SRC_ADDR", "sourceIPv4Address")
    dst = _extract_field(flow_data, "IPV4_DST_ADDR", "destinationIPv4Address")
    src6 = _extract_field(flow_data, "IPV6_SRC_ADDR", "sourceIPv6Address")
    dst6 = _extract_field(flow_data, "IPV6_DST_ADDR", "destinationIPv6Address")

    if src is not None and not isinstance(src, str):
        src = _ipv4(src)
    if dst is not None and not isinstance(dst, str):
        dst = _ipv4(dst)
    if src6 is not None and not isinstance(src6, str):
        src6 = _ipv6(src6)
    if dst6 is not None and not isinstance(dst6, str):
        dst6 = _ipv6(dst6)

    src_addr = src or src6
    dst_addr = dst or dst6
    if not src_addr or not dst_addr:
        return

    dst_port = _extract_field(flow_data, "L4_DST_PORT", "DST_PORT", "destinationTransportPort", default=0) or 0
    protocol = _extract_field(flow_data, "PROTOCOL", "PROTO", "protocolIdentifier", default=0) or 0
    octets = _extract_field(flow_data, "IN_BYTES", "IN_OCTETS", "octetDeltaCount", "BYTES", default=0) or 0
    packets = _extract_field(flow_data, "IN_PKTS", "IN_PACKETS", "packetDeltaCount", "PKTS", default=0) or 0
    in_iface = _extract_field(flow_data, "INPUT_SNMP", "INPUT", "ingressInterface")
    out_iface = _extract_field(flow_data, "OUTPUT_SNMP", "OUTPUT", "egressInterface")

    try:
        dst_port = int(dst_port)
        protocol = int(protocol)
        octets = int(octets)
        packets = int(packets)
    except (TypeError, ValueError):
        return

    key = (exporter_ip, src_addr, dst_addr, dst_port, protocol)
    async with _buffer_lock:
        agg = _buffer[key]
        agg["bytes"] += octets
        agg["packets"] += packets
        agg["flows"] += 1

        # Per-interface counters: one record per direction.
        if in_iface is not None:
            try:
                k = (exporter_ip, int(in_iface), "in")
                a = _iface_buffer[k]
                a["bytes"] += octets
                a["packets"] += packets
                a["flows"] += 1
            except (TypeError, ValueError):
                pass
        if out_iface is not None:
            try:
                k = (exporter_ip, int(out_iface), "out")
                a = _iface_buffer[k]
                a["bytes"] += octets
                a["packets"] += packets
                a["flows"] += 1
            except (TypeError, ValueError):
                pass


async def _parse_packet(data: bytes, addr: tuple[str, int]) -> int:
    """Parse a UDP datagram. Returns number of flow records ingested."""
    if len(data) < 4:
        return 0
    version = struct.unpack("!H", data[:2])[0]

    try:
        if version == 9:
            from netflow.v9 import V9ExportPacket
            pkt = V9ExportPacket(data, _v9_templates)
            count = 0
            for flow in pkt.flows:
                if hasattr(flow, "data") and isinstance(flow.data, dict):
                    await _ingest_flow(addr[0], flow.data)
                    count += 1
            return count
        elif version == 10:  # IPFIX
            from netflow.ipfix import IPFIXExportPacket
            pkt = IPFIXExportPacket(data, _ipfix_templates)
            count = 0
            for flow in pkt.flows:
                if hasattr(flow, "data") and isinstance(flow.data, dict):
                    await _ingest_flow(addr[0], flow.data)
                    count += 1
            return count
        elif version == 5:
            from netflow.v5 import V5ExportPacket
            pkt = V5ExportPacket(data)
            count = 0
            for flow in pkt.flows:
                if hasattr(flow, "data") and isinstance(flow.data, dict):
                    await _ingest_flow(addr[0], flow.data)
                    count += 1
            return count
        else:
            return 0
    except Exception as e:
        log.debug(f"parse error from {addr[0]} v{version}: {e}")
        return 0


async def _flush_loop():
    while True:
        await asyncio.sleep(BUCKET_INTERVAL)
        async with _buffer_lock:
            snapshot = list(_buffer.items())
            iface_snapshot = list(_iface_buffer.items())
            _buffer.clear()
            _iface_buffer.clear()

        if not snapshot and not iface_snapshot:
            continue

        bucket_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        rows = [
            {
                "bs": bucket_start,
                "fw": k[0], "src": k[1], "dst": k[2], "dp": k[3], "p": k[4],
                "b": v["bytes"], "pk": v["packets"], "f": v["flows"],
            }
            for k, v in snapshot
        ]
        iface_rows = [
            {
                "bs": bucket_start,
                "fw": k[0], "idx": k[1], "dir": k[2],
                "b": v["bytes"], "pk": v["packets"], "f": v["flows"],
            }
            for k, v in iface_snapshot
        ]
        try:
            async with Session() as s:
                if rows:
                    await s.execute(
                        text(
                            """
                            INSERT INTO netflow_buckets
                            (bucket_start, firewall_ip, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows)
                            VALUES (:bs, :fw, :src, :dst, :dp, :p, :b, :pk, :f)
                            """
                        ),
                        rows,
                    )
                if iface_rows:
                    await s.execute(
                        text(
                            """
                            INSERT INTO netflow_iface_buckets
                            (bucket_start, firewall_ip, iface_idx, direction, bytes, packets, flows)
                            VALUES (:bs, :fw, :idx, :dir, :b, :pk, :f)
                            """
                        ),
                        iface_rows,
                    )
                await s.commit()
            log.info(f"flushed {len(rows)} flow + {len(iface_rows)} iface buckets at {bucket_start.isoformat()}")
        except Exception as e:
            log.error(f"flush failed: {e}")


async def _retention_loop():
    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
            async with Session() as s:
                r1 = await s.execute(text("DELETE FROM netflow_buckets WHERE bucket_start < :c"), {"c": cutoff})
                r2 = await s.execute(text("DELETE FROM netflow_iface_buckets WHERE bucket_start < :c"), {"c": cutoff})
                await s.commit()
                if r1.rowcount or r2.rowcount:
                    log.info(f"retention: deleted {r1.rowcount} flow + {r2.rowcount} iface rows < {cutoff.isoformat()}")
        except Exception as e:
            log.error(f"retention failed: {e}")
        await asyncio.sleep(3600)


async def _ensure_schema():
    """Wait for the DB to be migrated by the backend before starting."""
    for attempt in range(30):
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1 FROM netflow_buckets LIMIT 1"))
            log.info("schema check OK")
            return
        except Exception as e:
            log.info(f"waiting for schema (attempt {attempt + 1}): {e}")
            await asyncio.sleep(2)
    log.warning("schema check timed out — proceeding anyway")


async def _udp_listener():
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind(("0.0.0.0", PORT))
    log.info(f"netflow listener on UDP/{PORT}, bucket={BUCKET_INTERVAL}s, retention={RETENTION_DAYS}d")

    total = 0
    last_log = datetime.now(timezone.utc)
    while True:
        data, addr = await loop.sock_recvfrom(sock, 65535)
        n = await _parse_packet(data, addr)
        total += n
        now = datetime.now(timezone.utc)
        if (now - last_log).total_seconds() > 60:
            log.info(f"ingested {total} flow records in last 60s; buffer keys: {len(_buffer)}")
            total = 0
            last_log = now


async def main():
    await _ensure_schema()
    await asyncio.gather(_udp_listener(), _flush_loop(), _retention_loop())


if __name__ == "__main__":
    asyncio.run(main())
