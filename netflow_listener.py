"""
NetFlow v5 / v9 / IPFIX collector.

Listens on a UDP port (default 2055) and stores flow records in the database.
Supports:
  - NetFlow v5  (fixed 48-byte records, most common on UDM Pro)
  - NetFlow v9  (template-based — templates cached per exporter)
  - IPFIX / v10 (template-based — same cache mechanism as v9)
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("netflow")

# ── Protocol constants ────────────────────────────────────────────────────────

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}

# NetFlow v5 header: !HHIIIIBBH  (24 bytes)
_V5_HDR = struct.Struct("!HHIIIIBBH")
# NetFlow v5 record: !IIIHHIIIIHHBBBBHHBBxx  (48 bytes)
_V5_REC = struct.Struct("!IIIHHIIIIHHBBBBHHBBxx")

# NetFlow v9 / IPFIX header
_V9_HDR  = struct.Struct("!HHIII")   # version, count, uptime, unix_secs, seq/src_id
_IPFIX_HDR = struct.Struct("!HHII")  # version, length, unix_secs, seq

# Template caches keyed by (source_ip, source_id, template_id)
_v9_templates:   dict[tuple, dict] = {}
_ipfix_templates: dict[tuple, dict] = {}

# IPFIX / v9 field type → name mapping (subset of common fields)
_FIELD_NAMES = {
    1:  "in_bytes",  2:  "in_pkts",   4:  "protocol",
    5:  "src_tos",   6:  "tcp_flags",  7:  "src_port",
    8:  "src_addr",  11: "dst_port",   12: "dst_addr",
    21: "last_ms",   22: "first_ms",   27: "src_addr6",
    28: "dst_addr6", 150:"flow_start", 152:"flow_start_ms",
    153:"flow_end_ms",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))


def _proto_name(n: int) -> str:
    return PROTO_NAMES.get(n, str(n))


def _store(records: list[dict], source_ip: str) -> None:
    """Write flow records to the database (runs in a thread pool)."""
    if not records:
        return
    try:
        from database import SessionLocal, NetFlowRecord
        db = SessionLocal()
        try:
            db.bulk_insert_mappings(NetFlowRecord, [
                {
                    "received_at":  r.get("received_at", datetime.now(timezone.utc)),
                    "exporter_ip":  source_ip,
                    "src_ip":       r.get("src_ip"),
                    "dst_ip":       r.get("dst_ip"),
                    "src_port":     r.get("src_port"),
                    "dst_port":     r.get("dst_port"),
                    "protocol":     r.get("protocol"),
                    "proto_name":   _proto_name(r.get("protocol", 0)),
                    "bytes":        r.get("bytes", 0),
                    "packets":      r.get("packets", 0),
                    "tcp_flags":    r.get("tcp_flags"),
                    "flow_start":   r.get("flow_start"),
                    "flow_end":     r.get("flow_end"),
                    "tos":          r.get("tos"),
                    "src_as":       r.get("src_as"),
                    "dst_as":       r.get("dst_as"),
                }
                for r in records
            ])
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.error("NetFlow DB write error: %s", exc)


# ── NetFlow v5 parser ─────────────────────────────────────────────────────────

def _parse_v5(data: bytes, source_ip: str, now: datetime) -> list[dict]:
    if len(data) < _V5_HDR.size:
        return []
    hdr = _V5_HDR.unpack_from(data)
    version, count, uptime_ms, unix_secs = hdr[0], hdr[1], hdr[2], hdr[3]
    base_ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

    records = []
    offset = _V5_HDR.size
    for _ in range(min(count, 30)):   # UDM sends ≤30 records per packet
        if offset + _V5_REC.size > len(data):
            break
        f = _V5_REC.unpack_from(data, offset)
        offset += _V5_REC.size
        # f: srcaddr, dstaddr, nexthop, input, output, pkts, bytes,
        #    first_ms, last_ms, srcport, dstport, pad, tcp_flags, prot,
        #    tos, src_as, dst_as, src_mask, dst_mask
        first_ms = f[7]
        last_ms  = f[8]
        dur_ms   = (last_ms - first_ms) & 0xFFFFFFFF
        flow_start = datetime.fromtimestamp(
            unix_secs - (uptime_ms - first_ms) / 1000.0, tz=timezone.utc
        ) if uptime_ms >= first_ms else base_ts
        flow_end = datetime.fromtimestamp(
            unix_secs - (uptime_ms - last_ms) / 1000.0, tz=timezone.utc
        ) if uptime_ms >= last_ms else base_ts

        records.append({
            "received_at": now,
            "src_ip":      _ip(f[0]),
            "dst_ip":      _ip(f[1]),
            "packets":     f[5],
            "bytes":       f[6],
            "flow_start":  flow_start,
            "flow_end":    flow_end,
            "src_port":    f[9],
            "dst_port":    f[10],
            "tcp_flags":   f[12],
            "protocol":    f[13],
            "tos":         f[14],
            "src_as":      f[15],
            "dst_as":      f[16],
        })
    return records


# ── NetFlow v9 parser ─────────────────────────────────────────────────────────

def _parse_v9(data: bytes, source_ip: str, now: datetime) -> list[dict]:
    if len(data) < _V9_HDR.size:
        return []
    version, count, uptime_ms, unix_secs, seq = _V9_HDR.unpack_from(data)
    # source_id is the 5th field in v9 header (re-read)
    source_id = struct.unpack_from("!I", data, 12)[0]
    base_ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

    records: list[dict] = []
    offset = _V9_HDR.size

    for _ in range(count):
        if offset + 4 > len(data):
            break
        flowset_id, flowset_len = struct.unpack_from("!HH", data, offset)
        if flowset_len < 4:
            break

        body_start = offset + 4
        body_end   = offset + flowset_len

        if flowset_id == 0:
            # Template FlowSet
            pos = body_start
            while pos + 4 <= body_end:
                tpl_id, field_count = struct.unpack_from("!HH", data, pos)
                pos += 4
                if tpl_id < 256 or pos + field_count * 4 > body_end:
                    break
                fields = []
                for _ in range(field_count):
                    ftype, flen = struct.unpack_from("!HH", data, pos)
                    pos += 4
                    fields.append((ftype, flen))
                key = (source_ip, source_id, tpl_id)
                _v9_templates[key] = {"fields": fields}

        elif flowset_id == 1:
            # Options Template — skip
            pass
        elif flowset_id >= 256:
            # Data FlowSet
            key = (source_ip, source_id, flowset_id)
            tpl = _v9_templates.get(key)
            if tpl:
                rec_len = sum(f[1] for f in tpl["fields"])
                if rec_len > 0:
                    pos = body_start
                    while pos + rec_len <= body_end:
                        r = _decode_fields(data, pos, tpl["fields"], base_ts, uptime_ms, now)
                        if r:
                            records.append(r)
                        pos += rec_len

        offset += flowset_len

    return records


# ── IPFIX parser ──────────────────────────────────────────────────────────────

def _parse_ipfix(data: bytes, source_ip: str, now: datetime) -> list[dict]:
    if len(data) < _IPFIX_HDR.size:
        return []
    version, length, unix_secs, seq = _IPFIX_HDR.unpack_from(data)
    obs_domain = struct.unpack_from("!I", data, 12)[0]
    base_ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

    records: list[dict] = []
    offset = 16   # IPFIX header is 16 bytes

    while offset + 4 <= len(data):
        set_id, set_len = struct.unpack_from("!HH", data, offset)
        if set_len < 4:
            break
        body_start = offset + 4
        body_end   = offset + set_len

        if set_id == 2:
            # Template Set
            pos = body_start
            while pos + 4 <= body_end:
                tpl_id, field_count = struct.unpack_from("!HH", data, pos)
                pos += 4
                if tpl_id < 256:
                    break
                fields = []
                for _ in range(field_count):
                    if pos + 4 > body_end:
                        break
                    ftype, flen = struct.unpack_from("!HH", data, pos)
                    pos += 4
                    # Enterprise bit set — skip 4-byte enterprise number
                    if ftype & 0x8000:
                        ftype &= 0x7FFF
                        pos += 4
                    fields.append((ftype, flen))
                key = (source_ip, obs_domain, tpl_id)
                _ipfix_templates[key] = {"fields": fields}

        elif set_id == 3:
            pass  # Options Template Set — skip

        elif set_id >= 256:
            key = (source_ip, obs_domain, set_id)
            tpl = _ipfix_templates.get(key)
            if tpl:
                rec_len = sum(f[1] for f in tpl["fields"] if f[1] != 0xFFFF)
                if rec_len > 0:
                    pos = body_start
                    while pos + rec_len <= body_end:
                        r = _decode_fields(data, pos, tpl["fields"], base_ts, 0, now)
                        if r:
                            records.append(r)
                        pos += rec_len

        offset += set_len

    return records


# ── Field decoder (shared v9 / IPFIX) ────────────────────────────────────────

def _decode_fields(data: bytes, offset: int, fields: list[tuple], base_ts: datetime, uptime_ms: int, now: datetime) -> dict | None:
    raw: dict[str, Any] = {}
    pos = offset
    for ftype, flen in fields:
        if flen == 0xFFFF or pos + flen > len(data):
            return None
        val = data[pos:pos + flen]
        pos += flen
        name = _FIELD_NAMES.get(ftype)
        if name == "src_addr" and flen == 4:
            raw["src_ip"] = socket.inet_ntoa(val)
        elif name == "dst_addr" and flen == 4:
            raw["dst_ip"] = socket.inet_ntoa(val)
        elif name == "src_addr6" and flen == 16:
            raw["src_ip"] = socket.inet_ntop(socket.AF_INET6, val)
        elif name == "dst_addr6" and flen == 16:
            raw["dst_ip"] = socket.inet_ntop(socket.AF_INET6, val)
        elif name == "src_port" and flen == 2:
            raw["src_port"] = struct.unpack("!H", val)[0]
        elif name == "dst_port" and flen == 2:
            raw["dst_port"] = struct.unpack("!H", val)[0]
        elif name == "protocol" and flen == 1:
            raw["protocol"] = val[0]
        elif name == "tcp_flags" and flen == 1:
            raw["tcp_flags"] = val[0]
        elif name == "in_bytes" and flen in (4, 8):
            raw["bytes"] = int.from_bytes(val, "big")
        elif name == "in_pkts" and flen in (4, 8):
            raw["packets"] = int.from_bytes(val, "big")
        elif name in ("flow_start_ms", "first_ms") and flen == 4:
            ms = struct.unpack("!I", val)[0]
            if uptime_ms:
                raw["flow_start"] = datetime.fromtimestamp(
                    base_ts.timestamp() - (uptime_ms - ms) / 1000.0, tz=timezone.utc
                )
        elif name in ("flow_end_ms", "last_ms") and flen == 4:
            ms = struct.unpack("!I", val)[0]
            if uptime_ms:
                raw["flow_end"] = datetime.fromtimestamp(
                    base_ts.timestamp() - (uptime_ms - ms) / 1000.0, tz=timezone.utc
                )
        elif name == "flow_start" and flen == 4:
            raw["flow_start"] = datetime.fromtimestamp(struct.unpack("!I", val)[0], tz=timezone.utc)

    if not raw.get("src_ip") or not raw.get("dst_ip"):
        return None
    raw.setdefault("received_at", now)
    return raw


# ── UDP protocol ──────────────────────────────────────────────────────────────

class _NetFlowProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 2:
            return
        source_ip = addr[0]
        now = datetime.now(timezone.utc)
        version = struct.unpack_from("!H", data)[0]
        try:
            if version == 5:
                records = _parse_v5(data, source_ip, now)
            elif version == 9:
                records = _parse_v9(data, source_ip, now)
            elif version == 10:
                records = _parse_ipfix(data, source_ip, now)
            else:
                logger.debug("Unknown NetFlow version %d from %s", version, source_ip)
                return
        except Exception as exc:
            logger.debug("NetFlow parse error from %s: %s", source_ip, exc)
            return

        if records:
            asyncio.get_event_loop().run_in_executor(None, _store, records, source_ip)

    def error_received(self, exc: Exception) -> None:
        logger.warning("NetFlow transport error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("NetFlow connection lost: %s", exc)


async def start_netflow_listener(host: str, port: int) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _NetFlowProtocol,
        local_addr=(host, port),
    )
    logger.info("NetFlow listener started on udp %s:%d (v5/v9/IPFIX)", host, port)
    return transport
