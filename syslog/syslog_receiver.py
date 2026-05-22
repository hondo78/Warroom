"""
Syslog receiver for Sophos XG/XGS Firewall logs.

Sophos SFOS sends syslog in key=value format, e.g.:
device_name="XGS" date=2026-03-06 time=12:00:00 timezone="CET"
log_id="010101600001" log_type="Firewall" log_component="Firewall Rule"
log_subtype="Allowed" status="Allow" priority="Information"
src_ip="192.168.1.100" dst_ip="8.8.8.8" ...
"""

import asyncio
import json
import logging
import os
import re
import signal
from datetime import datetime, timezone

import asyncpg

from geoip_lookup import lookup_ip, is_public_ip

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("syslog_receiver")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://warroom:changeme@postgres:5432/warroom",
)
LISTEN_PORT = int(os.environ.get("SYSLOG_PORT", "5514"))

# Sophos SFOS log types we care about for security
SECURITY_LOG_TYPES = {
    "Firewall", "IDP", "ATP", "Anti-Virus", "Anti-Spam",
    "WAF", "Sandstorm", "Content Filtering",
}

# Map Sophos priority to severity
PRIORITY_MAP = {
    "Emergency": "critical",
    "Alert": "critical",
    "Critical": "critical",
    "Error": "high",
    "Warning": "medium",
    "Notification": "low",
    "Information": "low",
    "Debug": "low",
}

_KV_RE = re.compile(r'(\w+)="([^"]*)"|\b(\w+)=(\S+)')

# Some SFOS subtypes (e.g. IPSec "Couldn't parse IKE header from 1.2.3.4[port]")
# embed the attacker IP only in the free-text message and never set src_ip=.
# This pattern recovers it so source_ip / GeoIP enrichment work.
_MSG_IP_RE = re.compile(r'\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\[\d+\])?')


def parse_sophos_log(message: str) -> dict | None:
    """Parse Sophos SFOS key=value syslog message."""
    fields = {}

    for m in _KV_RE.finditer(message):
        if m.group(1):
            fields[m.group(1)] = m.group(2)
        elif m.group(3):
            fields[m.group(3)] = m.group(4)

    if not fields:
        return None

    return fields


def fields_to_record(fields: dict, sender_ip: str) -> dict | None:
    """Convert parsed fields to a database record (without geo enrichment).

    Geo enrichment happens in the async insert worker so it can use the
    shared Redis + Postgres cache.
    """
    log_type = fields.get("log_type", "")
    log_subtype = fields.get("log_subtype", "")

    src_ip = fields.get("src_ip", "")
    dst_ip = fields.get("dst_ip", "")

    if not src_ip:
        msg_text = fields.get("message") or fields.get("msg") or ""
        m = _MSG_IP_RE.search(msg_text)
        if m and is_public_ip(m.group(1)):
            src_ip = m.group(1)

    # Determine which IP is the external attacker
    # For inbound: src is attacker, dst is internal
    # For outbound ATP/C2: dst is threat, src is internal
    attacker_ip = None
    if log_type in ("ATP", "IDP", "Anti-Virus", "Sandstorm"):
        # For threat detections, external IP is the attacker
        if is_public_ip(src_ip):
            attacker_ip = src_ip
        elif is_public_ip(dst_ip):
            attacker_ip = dst_ip
    elif log_subtype in ("Denied", "Dropped", "Drop"):
        # For denied traffic, the source is usually the attacker
        if is_public_ip(src_ip):
            attacker_ip = src_ip
    else:
        # General: pick the public one
        if is_public_ip(src_ip):
            attacker_ip = src_ip
        elif is_public_ip(dst_ip):
            attacker_ip = dst_ip

    # Parse timestamp
    date_str = fields.get("date", "")
    time_str = fields.get("time", "")
    tz_str = fields.get("timezone", "UTC")
    created_at = None
    if date_str and time_str:
        try:
            dt_str = f"{date_str} {time_str}"
            created_at = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
            created_at = created_at.replace(tzinfo=timezone.utc)
        except ValueError:
            created_at = datetime.now(timezone.utc)
    else:
        created_at = datetime.now(timezone.utc)

    severity = PRIORITY_MAP.get(fields.get("priority", ""), "low")

    src_port = None
    dst_port = None
    try:
        src_port = int(fields.get("src_port", ""))
    except (ValueError, TypeError):
        pass
    try:
        dst_port = int(fields.get("dst_port", ""))
    except (ValueError, TypeError):
        pass

    return {
        "log_type": log_type or None,
        "log_subtype": log_subtype or None,
        "severity": severity,
        "firewall_name": fields.get("device_name") or fields.get("device"),
        "firewall_ip": sender_ip,
        "source_ip": src_ip or None,
        "source_port": src_port,
        "destination_ip": dst_ip or None,
        "destination_port": dst_port,
        "protocol": fields.get("protocol"),
        "rule_name": fields.get("fw_rule_id") or fields.get("rule_id"),
        "policy_name": fields.get("policy_name") or fields.get("log_component"),
        "action": fields.get("status") or fields.get("log_subtype"),
        "message": fields.get("message") or fields.get("reason") or fields.get("msg"),
        "threat_name": fields.get("threat") or fields.get("virus") or fields.get("category"),
        "user_name": fields.get("user_name") or fields.get("user"),
        "created_at": created_at,
        "raw_data": fields,
        "_attacker_ip": attacker_ip,
        "attacker_lat": None,
        "attacker_lon": None,
        "attacker_country": None,
        "attacker_city": None,
        "attacker_asn": None,
        "attacker_org": None,
    }


class SyslogServer:
    def __init__(self):
        self.pool: asyncpg.Pool | None = None
        self.insert_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._running = True

    async def init_db(self):
        # Parse DATABASE_URL for asyncpg (strip +asyncpg if present)
        dsn = DATABASE_URL.replace("+asyncpg", "")
        self.pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
        logger.info("Database pool created")

        # Ensure table exists
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS firewall_logs (
                    id BIGSERIAL PRIMARY KEY,
                    log_type VARCHAR(50),
                    log_subtype VARCHAR(50),
                    severity VARCHAR(20),
                    firewall_name VARCHAR(255),
                    firewall_ip VARCHAR(45),
                    source_ip VARCHAR(45),
                    source_port INTEGER,
                    destination_ip VARCHAR(45),
                    destination_port INTEGER,
                    protocol VARCHAR(20),
                    rule_name VARCHAR(255),
                    policy_name VARCHAR(255),
                    action VARCHAR(50),
                    message TEXT,
                    threat_name VARCHAR(255),
                    user_name VARCHAR(255),
                    created_at TIMESTAMP WITH TIME ZONE,
                    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    raw_data JSONB,
                    attacker_lat DOUBLE PRECISION,
                    attacker_lon DOUBLE PRECISION,
                    attacker_country VARCHAR(100),
                    attacker_city VARCHAR(255),
                    attacker_asn VARCHAR(255),
                    attacker_org VARCHAR(255)
                )
            """)

    async def insert_worker(self):
        """Batch insert worker - collects records and inserts in batches."""
        while self._running:
            batch = []
            try:
                # Wait for first item
                record = await asyncio.wait_for(self.insert_queue.get(), timeout=5.0)
                batch.append(record)
                # Drain queue for batch
                while len(batch) < 100:
                    try:
                        record = self.insert_queue.get_nowait()
                        batch.append(record)
                    except asyncio.QueueEmpty:
                        break
            except asyncio.TimeoutError:
                continue

            if batch:
                await self._insert_batch(batch)

    async def _enrich_batch(self, batch: list[dict]):
        """Resolve GeoIP for all unique attacker IPs in the batch."""
        unique_ips = {r["_attacker_ip"] for r in batch if r.get("_attacker_ip")}
        if not unique_ips:
            return
        results = await asyncio.gather(
            *(lookup_ip(ip, self.pool) for ip in unique_ips),
            return_exceptions=True,
        )
        geo_by_ip: dict[str, dict] = {}
        for ip, geo in zip(unique_ips, results):
            if isinstance(geo, dict):
                geo_by_ip[ip] = geo
        for r in batch:
            ip = r.get("_attacker_ip")
            geo = geo_by_ip.get(ip) if ip else None
            if geo:
                r["attacker_lat"] = geo.get("lat")
                r["attacker_lon"] = geo.get("lon")
                r["attacker_country"] = geo.get("country")
                r["attacker_city"] = geo.get("city")
                r["attacker_asn"] = geo.get("asn")
                r["attacker_org"] = geo.get("org")

    async def _insert_batch(self, batch: list[dict]):
        await self._enrich_batch(batch)
        try:
            async with self.pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO firewall_logs (
                        log_type, log_subtype, severity, firewall_name, firewall_ip,
                        source_ip, source_port, destination_ip, destination_port,
                        protocol, rule_name, policy_name, action, message,
                        threat_name, user_name, created_at, raw_data,
                        attacker_lat, attacker_lon, attacker_country, attacker_city,
                        attacker_asn, attacker_org
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, $12, $13, $14, $15, $16, $17, $18,
                        $19, $20, $21, $22, $23, $24
                    )
                    """,
                    [
                        (
                            r["log_type"], r["log_subtype"], r["severity"],
                            r["firewall_name"], r["firewall_ip"],
                            r["source_ip"], r["source_port"],
                            r["destination_ip"], r["destination_port"],
                            r["protocol"], r["rule_name"], r["policy_name"],
                            r["action"], r["message"], r["threat_name"],
                            r["user_name"], r["created_at"],
                            json.dumps(r["raw_data"]),
                            r["attacker_lat"], r["attacker_lon"],
                            r["attacker_country"], r["attacker_city"],
                            r["attacker_asn"], r["attacker_org"],
                        )
                        for r in batch
                    ],
                )
            logger.info(f"Inserted {len(batch)} firewall log records")
        except Exception as e:
            logger.error(f"Failed to insert batch: {e}")

    def handle_message(self, data: bytes, sender_ip: str):
        """Process a single syslog message."""
        try:
            message = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        if not message:
            return

        # Strip syslog header (PRI, timestamp, hostname)
        # Sophos logs typically start with device_name= or have key=value format
        fields = parse_sophos_log(message)
        if not fields:
            return

        record = fields_to_record(fields, sender_ip)
        if record is None:
            return

        try:
            self.insert_queue.put_nowait(record)
        except asyncio.QueueFull:
            logger.warning("Insert queue full, dropping message")


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: SyslogServer):
        self.server = server

    def datagram_received(self, data: bytes, addr: tuple):
        self.server.handle_message(data, addr[0])


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, server: SyslogServer):
    addr = writer.get_extra_info("peername")
    sender_ip = addr[0] if addr else "unknown"
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            server.handle_message(data, sender_ip)
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def main():
    server = SyslogServer()
    await server.init_db()

    loop = asyncio.get_event_loop()

    # Start UDP listener
    transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(server),
        local_addr=("0.0.0.0", LISTEN_PORT),
    )
    logger.info(f"UDP syslog listener started on port {LISTEN_PORT}")

    # Start TCP listener
    tcp_server = await asyncio.start_server(
        lambda r, w: handle_tcp_client(r, w, server),
        "0.0.0.0",
        LISTEN_PORT,
    )
    logger.info(f"TCP syslog listener started on port {LISTEN_PORT}")

    # Start insert worker
    worker_task = asyncio.create_task(server.insert_worker())

    # Handle shutdown
    stop_event = asyncio.Event()

    def signal_handler():
        server._running = False
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    logger.info("Syslog receiver ready - waiting for Sophos Firewall logs")

    await stop_event.wait()

    transport.close()
    tcp_server.close()
    await tcp_server.wait_closed()
    worker_task.cancel()
    await server.pool.close()
    logger.info("Syslog receiver stopped")


if __name__ == "__main__":
    asyncio.run(main())
