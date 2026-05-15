"""
RFC 5424 / RFC 3164 syslog listener over UDP and TCP.
Runs as asyncio tasks alongside FastAPI.
"""
import asyncio
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional

from database import SessionLocal, SyslogEntry
from normalizer import normalize

logger = logging.getLogger("syslog_listener")

_ALLOW_CACHE: tuple[list, float] = ([], 0.0)
_ALLOW_CACHE_TTL = 60.0  # seconds


def _get_allowed_networks() -> list:
    """Return the current allowed-source network list, refreshed from DB every 60 s."""
    global _ALLOW_CACHE
    networks, ts = _ALLOW_CACHE
    if time.monotonic() - ts > _ALLOW_CACHE_TTL:
        from database import get_service_setting
        from config import settings
        raw = get_service_setting("allowed_syslog_sources") or settings.allowed_syslog_sources
        sources = [s.strip() for s in raw.split(",") if s.strip()] if raw else []
        nets = []
        for cidr in sources:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid allowed_syslog_sources entry: %s", cidr)
        _ALLOW_CACHE = (nets, time.monotonic())
        return nets
    return networks


def _is_allowed(ip: str) -> bool:
    nets = _get_allowed_networks()
    if not nets:
        return True  # no filter — allow all
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in nets)
    except ValueError:
        return False

# RFC 5424  <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424 = re.compile(
    r"^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]|-)\s*(.*)?$",
    re.DOTALL,
)

# RFC 3164  <PRI>TIMESTAMP HOSTNAME TAG: MSG
_RFC3164 = re.compile(
    r"^<(\d{1,3})>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)?$",
    re.DOTALL,
)


def _parse(raw: str, source_ip: str) -> SyslogEntry:
    raw = raw.strip()

    m = _RFC5424.match(raw)
    if m:
        pri = int(m.group(1))
        hostname = m.group(4) if m.group(4) != "-" else source_ip
        app_name = m.group(5) if m.group(5) != "-" else None
        proc_id = m.group(6) if m.group(6) != "-" else None
        msg_id = m.group(7) if m.group(7) != "-" else None
        message = m.group(8) or ""
        return SyslogEntry(
            source_ip=source_ip,
            facility=pri >> 3,
            severity=pri & 0x07,
            hostname=hostname,
            app_name=app_name,
            proc_id=proc_id,
            msg_id=msg_id,
            message=message,
            raw=raw,
        )

    m = _RFC3164.match(raw)
    if m:
        pri = int(m.group(1))
        hostname = m.group(3)
        message = m.group(4) or ""
        return SyslogEntry(
            source_ip=source_ip,
            facility=pri >> 3,
            severity=pri & 0x07,
            hostname=hostname,
            app_name=None,
            message=message,
            raw=raw,
        )

    # Fallback: store raw
    return SyslogEntry(
        source_ip=source_ip,
        facility=1,
        severity=5,
        hostname=source_ip,
        message=raw,
        raw=raw,
    )


def _apply_normalization(entry: SyslogEntry) -> SyslogEntry:
    """Run the message through the normalizer and stamp fields onto the entry."""
    nf = normalize(entry.message or "")
    entry.event_type    = nf.event_type
    entry.src_ip        = nf.src_ip or entry.source_ip
    entry.dst_ip        = nf.dst_ip
    entry.src_port      = nf.src_port
    entry.dst_port      = nf.dst_port
    entry.protocol      = nf.protocol
    entry.action        = nf.action
    entry.direction     = nf.direction
    entry.interface_in  = nf.interface_in
    entry.interface_out = nf.interface_out
    entry.mac_address   = nf.mac_address
    entry.norm_user     = nf.user
    entry.norm_hostname = nf.hostname
    entry.domain        = nf.domain
    entry.rule_name     = nf.rule_name
    entry.extra_json    = json.dumps(nf.extra) if nf.extra else None
    return entry


def _store(entry: SyslogEntry) -> None:
    _apply_normalization(entry)
    db = SessionLocal()
    try:
        db.add(entry)
        db.commit()
    except Exception as exc:
        logger.error("DB write error: %s", exc)
        db.rollback()
    finally:
        db.close()


# ---- UDP ----

class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        source_ip = addr[0]
        if not _is_allowed(source_ip):
            logger.debug("Dropped UDP syslog from disallowed source %s", source_ip)
            return
        try:
            raw = data.decode("utf-8", errors="replace")
            entry = _parse(raw, source_ip)
            _store(entry)
        except Exception as exc:
            logger.warning("UDP parse error from %s: %s", source_ip, exc)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP transport error: %s", exc)


async def start_udp_listener(host: str, port: int) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _SyslogUDPProtocol,
        local_addr=(host, port),
    )
    logger.info("Syslog UDP listener on %s:%d", host, port)
    return transport


# ---- TCP ----

async def _handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    if not _is_allowed(source_ip):
        logger.debug("Rejected TCP syslog connection from disallowed source %s", source_ip)
        writer.close()
        return
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            raw = line.decode("utf-8", errors="replace").rstrip("\n\r")
            if raw:
                entry = _parse(raw, source_ip)
                _store(entry)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception as exc:
        logger.warning("TCP client error from %s: %s", source_ip, exc)
    finally:
        writer.close()


async def start_tcp_listener(host: str, port: int) -> asyncio.Server:
    server = await asyncio.start_server(_handle_tcp_client, host, port)
    logger.info("Syslog TCP listener on %s:%d", host, port)
    return server
