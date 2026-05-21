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

# ── Diagnostics counters (queryable via /api/netflow/status) ──────────────────
_stats = {
    "packets_received": 0,
    "records_stored":   0,
    "parse_errors":     0,
    "last_packet_at":   None,   # ISO string
    "last_exporter":    None,
    "template_count":   0,
}

# ── Protocol constants ────────────────────────────────────────────────────────

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}

# NetFlow v5
# Header: version(H) count(H) sys_uptime(I) unix_secs(I) unix_nsecs(I)
#         flow_sequence(I) engine_type(B) engine_id(B) sampling_interval(H)
# = 24 bytes
_V5_HDR = struct.Struct("!HHIIIIBBH")
# Record: 48 bytes
_V5_REC = struct.Struct("!IIIHHIIIIHHBBBBHHBBxx")

# NetFlow v9 header: version(H) count(H) sys_uptime(I) unix_secs(I)
#                   package_sequence(I) source_id(I)  = 20 bytes
_V9_HDR = struct.Struct("!HHIIII")

# IPFIX header: version(H) length(H) export_time(I) seq_num(I) obs_domain(I)
# = 16 bytes
_IPFIX_HDR = struct.Struct("!HHIII")

# Template caches keyed by (source_ip, source_id, template_id)
_v9_templates:    dict[tuple, dict] = {}
_ipfix_templates: dict[tuple, dict] = {}

# IPFIX / v9 field type → name mapping (subset of IANA-assigned IEs)
_FIELD_NAMES: dict[int, str] = {
    1:   "in_bytes",
    2:   "in_pkts",
    4:   "protocol",
    5:   "src_tos",
    6:   "tcp_flags",
    7:   "src_port",
    8:   "src_addr",
    11:  "dst_port",
    12:  "dst_addr",
    21:  "last_ms",
    22:  "first_ms",
    27:  "src_addr6",
    28:  "dst_addr6",
    32:  "icmp_type",
    85:  "octet_count",   # alias for in_bytes in some exporters
    86:  "pkt_count",     # alias for in_pkts
    136: "flow_end_reason",
    150: "flow_start",
    151: "flow_end",
    152: "flow_start_ms",
    153: "flow_end_ms",
    176: "icmp_type_ipv6",
    189: "src_as",
    190: "dst_as",
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
                    "received_at": r.get("received_at", datetime.now(timezone.utc)),
                    "exporter_ip": source_ip,
                    "src_ip":      r.get("src_ip"),
                    "dst_ip":      r.get("dst_ip"),
                    "src_port":    r.get("src_port"),
                    "dst_port":    r.get("dst_port"),
                    "protocol":    r.get("protocol"),
                    "proto_name":  _proto_name(r.get("protocol") or 0),
                    "bytes":       r.get("bytes", 0),
                    "packets":     r.get("packets", 0),
                    "tcp_flags":   r.get("tcp_flags"),
                    "flow_start":  r.get("flow_start"),
                    "flow_end":    r.get("flow_end"),
                    "tos":         r.get("tos"),
                    "src_as":      r.get("src_as"),
                    "dst_as":      r.get("dst_as"),
                }
                for r in records
            ])
            db.commit()
            _stats["records_stored"] += len(records)
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
    for _ in range(min(count, 30)):
        if offset + _V5_REC.size > len(data):
            break
        f = _V5_REC.unpack_from(data, offset)
        offset += _V5_REC.size

        first_ms = f[7]
        last_ms  = f[8]
        flow_start = datetime.fromtimestamp(
            unix_secs - (uptime_ms - first_ms) / 1000.0, tz=timezone.utc
        ) if uptime_ms >= first_ms else base_ts
        flow_end = datetime.fromtimestamp(
            unix_secs - (uptime_ms - last_ms) / 1000.0, tz=timezone.utc
        ) if uptime_ms >= last_ms else base_ts

        records.append({
            "received_at": now,
            "src_ip":    _ip(f[0]),
            "dst_ip":    _ip(f[1]),
            "packets":   f[5],
            "bytes":     f[6],
            "flow_start": flow_start,
            "flow_end":   flow_end,
            "src_port":  f[9],
            "dst_port":  f[10],
            "tcp_flags": f[12],
            "protocol":  f[13],
            "tos":       f[14],
            "src_as":    f[15],
            "dst_as":    f[16],
        })
    return records


# ── NetFlow v9 parser ─────────────────────────────────────────────────────────
#
# v9 header (20 bytes):
#   version(2) count(2) sys_uptime(4) unix_secs(4) pkg_seq(4) source_id(4)
#
# FlowSet header (4 bytes each):
#   flowset_id(2) length(2)
#   flowset_id == 0  → Template FlowSet
#   flowset_id == 1  → Options Template FlowSet (skip)
#   flowset_id >= 256 → Data FlowSet

def _parse_v9(data: bytes, source_ip: str, now: datetime) -> list[dict]:
    if len(data) < _V9_HDR.size:
        return []

    version, count, uptime_ms, unix_secs, pkg_seq, source_id = _V9_HDR.unpack_from(data)
    base_ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

    records: list[dict] = []
    offset = _V9_HDR.size   # 20 — correct start of first FlowSet

    sets_parsed = 0
    while sets_parsed < count and offset + 4 <= len(data):
        flowset_id, flowset_len = struct.unpack_from("!HH", data, offset)

        # Sanity check — malformed packet guard
        if flowset_len < 4 or offset + flowset_len > len(data):
            logger.debug("v9 bad flowset_len=%d at offset=%d", flowset_len, offset)
            break

        body_start = offset + 4
        body_end   = offset + flowset_len

        if flowset_id == 0:
            # ── Template FlowSet ──────────────────────────────────────────────
            pos = body_start
            while pos + 4 <= body_end:
                tpl_id, field_count = struct.unpack_from("!HH", data, pos)
                pos += 4
                if tpl_id < 256:
                    break   # padding
                if pos + field_count * 4 > body_end:
                    break
                fields: list[tuple[int, int]] = []
                for _ in range(field_count):
                    ftype, flen = struct.unpack_from("!HH", data, pos)
                    pos += 4
                    fields.append((ftype, flen))
                key = (source_ip, source_id, tpl_id)
                _v9_templates[key] = {"fields": fields}
                _stats["template_count"] = len(_v9_templates) + len(_ipfix_templates)
                logger.debug("v9 template %d stored from %s (source_id=%d, %d fields)",
                             tpl_id, source_ip, source_id, len(fields))

        elif flowset_id == 1:
            pass  # Options Template — skip

        elif flowset_id >= 256:
            # ── Data FlowSet ──────────────────────────────────────────────────
            key = (source_ip, source_id, flowset_id)
            tpl = _v9_templates.get(key)
            if tpl is None:
                logger.debug("v9 no template for set_id=%d source=%s sid=%d — "
                             "waiting for template packet", flowset_id, source_ip, source_id)
            else:
                rec_len = sum(f[1] for f in tpl["fields"])
                if rec_len > 0:
                    pos = body_start
                    while pos + rec_len <= body_end:
                        r = _decode_fields(data, pos, tpl["fields"], base_ts, uptime_ms, now)
                        if r:
                            records.append(r)
                        pos += rec_len

        offset += flowset_len
        sets_parsed += 1

    return records


# ── IPFIX / v10 parser ────────────────────────────────────────────────────────
#
# IPFIX header (16 bytes):
#   version(2) length(2) export_time(4) seq_num(4) obs_domain_id(4)

def _parse_ipfix(data: bytes, source_ip: str, now: datetime) -> list[dict]:
    if len(data) < _IPFIX_HDR.size:
        return []

    version, msg_len, unix_secs, seq_num, obs_domain = _IPFIX_HDR.unpack_from(data)
    base_ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

    records: list[dict] = []
    offset = _IPFIX_HDR.size   # 16

    while offset + 4 <= min(len(data), msg_len):
        set_id, set_len = struct.unpack_from("!HH", data, offset)
        if set_len < 4 or offset + set_len > len(data):
            break
        body_start = offset + 4
        body_end   = offset + set_len

        if set_id == 2:
            # ── Template Set ──────────────────────────────────────────────────
            pos = body_start
            while pos + 4 <= body_end:
                tpl_id, field_count = struct.unpack_from("!HH", data, pos)
                pos += 4
                if tpl_id < 256:
                    break
                fields: list[tuple[int, int]] = []
                for _ in range(field_count):
                    if pos + 4 > body_end:
                        break
                    ftype, flen = struct.unpack_from("!HH", data, pos)
                    pos += 4
                    if ftype & 0x8000:          # enterprise bit
                        ftype &= 0x7FFF
                        pos += 4               # skip enterprise number
                    fields.append((ftype, flen))
                key = (source_ip, obs_domain, tpl_id)
                _ipfix_templates[key] = {"fields": fields}
                _stats["template_count"] = len(_v9_templates) + len(_ipfix_templates)

        elif set_id == 3:
            pass  # Options Template Set

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

def _decode_fields(
    data: bytes, offset: int, fields: list[tuple[int, int]],
    base_ts: datetime, uptime_ms: int, now: datetime,
) -> dict[str, Any] | None:
    raw: dict[str, Any] = {}
    pos = offset
    for ftype, flen in fields:
        if flen == 0xFFFF or pos + flen > len(data):
            return None
        val = data[pos: pos + flen]
        pos += flen
        name = _FIELD_NAMES.get(ftype)
        if name is None:
            continue

        if name == "src_addr" and flen == 4:
            raw["src_ip"] = socket.inet_ntoa(val)
        elif name == "dst_addr" and flen == 4:
            raw["dst_ip"] = socket.inet_ntoa(val)
        elif name == "src_addr6" and flen == 16:
            try:
                raw["src_ip"] = socket.inet_ntop(socket.AF_INET6, val)
            except Exception:
                pass
        elif name == "dst_addr6" and flen == 16:
            try:
                raw["dst_ip"] = socket.inet_ntop(socket.AF_INET6, val)
            except Exception:
                pass
        elif name == "src_port" and flen == 2:
            raw["src_port"] = struct.unpack("!H", val)[0]
        elif name == "dst_port" and flen == 2:
            raw["dst_port"] = struct.unpack("!H", val)[0]
        elif name == "protocol" and flen == 1:
            raw["protocol"] = val[0]
        elif name == "tcp_flags" and flen == 1:
            raw["tcp_flags"] = val[0]
        elif name in ("in_bytes", "octet_count") and flen in (4, 8):
            raw["bytes"] = int.from_bytes(val, "big")
        elif name in ("in_pkts", "pkt_count") and flen in (4, 8):
            raw["packets"] = int.from_bytes(val, "big")
        elif name == "src_as" and flen in (2, 4):
            raw["src_as"] = int.from_bytes(val, "big")
        elif name == "dst_as" and flen in (2, 4):
            raw["dst_as"] = int.from_bytes(val, "big")
        elif name in ("first_ms", "flow_start_ms") and flen == 4:
            ms = struct.unpack("!I", val)[0]
            if uptime_ms and uptime_ms >= ms:
                try:
                    raw["flow_start"] = datetime.fromtimestamp(
                        base_ts.timestamp() - (uptime_ms - ms) / 1000.0,
                        tz=timezone.utc,
                    )
                except (OSError, OverflowError):
                    pass
        elif name in ("last_ms", "flow_end_ms") and flen == 4:
            ms = struct.unpack("!I", val)[0]
            if uptime_ms and uptime_ms >= ms:
                try:
                    raw["flow_end"] = datetime.fromtimestamp(
                        base_ts.timestamp() - (uptime_ms - ms) / 1000.0,
                        tz=timezone.utc,
                    )
                except (OSError, OverflowError):
                    pass
        elif name == "flow_start" and flen == 4:
            try:
                raw["flow_start"] = datetime.fromtimestamp(
                    struct.unpack("!I", val)[0], tz=timezone.utc
                )
            except (OSError, OverflowError):
                pass
        elif name == "flow_end" and flen == 4:
            try:
                raw["flow_end"] = datetime.fromtimestamp(
                    struct.unpack("!I", val)[0], tz=timezone.utc
                )
            except (OSError, OverflowError):
                pass

    if not raw.get("src_ip") or not raw.get("dst_ip"):
        return None
    raw.setdefault("received_at", now)
    return raw


# ── UDP datagram protocol ─────────────────────────────────────────────────────

class _NetFlowProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 2:
            return
        source_ip = addr[0]
        now = datetime.now(timezone.utc)
        _stats["packets_received"] += 1
        _stats["last_packet_at"] = now.isoformat()
        _stats["last_exporter"]  = source_ip

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
            _stats["parse_errors"] += 1
            logger.warning("NetFlow parse error (v%d) from %s: %s", version, source_ip, exc)
            return

        if records:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, _store, records, source_ip)

    def error_received(self, exc: Exception) -> None:
        logger.warning("NetFlow transport error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("NetFlow connection lost: %s", exc)


def _open_firewall(port: int) -> None:
    """
    Best-effort: open the NetFlow UDP port in the host firewall.
    Tries ufw, firewall-cmd, and netsh in order.  Logs result, never raises.
    """
    import subprocess, sys, shutil

    def _run(*cmd: str) -> bool:
        try:
            r = subprocess.run(list(cmd), capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    if sys.platform == "win32":
        rule = f"NetFlow Collector UDP {port}"
        # Remove old rule first (idempotent), then add
        _run("netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule}", "protocol=UDP", f"localport={port}")
        ok = _run(
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=in", "action=allow",
            "protocol=UDP", f"localport={port}",
        )
        if ok:
            logger.info("Firewall: opened UDP %d (Windows Firewall)", port)
        else:
            logger.warning("Firewall: could not open UDP %d via netsh — open it manually", port)
        return

    # Linux — try ufw first, then firewall-cmd, then iptables
    if shutil.which("ufw"):
        ok = _run("ufw", "allow", f"{port}/udp", "comment", "NetFlow collector")
        if ok:
            logger.info("Firewall: opened UDP %d via ufw", port)
            return
        logger.warning("Firewall: ufw found but rule failed — may need sudo. Run: sudo ufw allow %d/udp", port)
        return

    if shutil.which("firewall-cmd"):
        ok = _run("firewall-cmd", "--permanent", "--add-port", f"{port}/udp")
        if ok:
            _run("firewall-cmd", "--reload")
            logger.info("Firewall: opened UDP %d via firewall-cmd", port)
        else:
            logger.warning("Firewall: firewall-cmd failed — run manually: "
                           "sudo firewall-cmd --permanent --add-port=%d/udp && sudo firewall-cmd --reload", port)
        return

    if shutil.which("iptables"):
        ok = _run("iptables", "-C", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT")
        if not ok:  # rule doesn't exist yet
            ok = _run("iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT")
        if ok:
            logger.info("Firewall: opened UDP %d via iptables", port)
        else:
            logger.warning("Firewall: iptables failed — run manually: "
                           "sudo iptables -A INPUT -p udp --dport %d -j ACCEPT", port)
        return

    logger.info("Firewall: no supported firewall manager found (ufw/firewall-cmd/iptables/netsh). "
                "Ensure UDP port %d is open manually.", port)


async def start_netflow_listener(host: str, port: int) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _NetFlowProtocol,
        local_addr=(host, port),
    )
    logger.info("NetFlow listener started on udp %s:%d (v5/v9/IPFIX)", host, port)
    # Open firewall in background thread so it doesn't block the event loop
    loop.run_in_executor(None, _open_firewall, port)
    return transport
