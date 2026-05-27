"""
Log normalization for Unifi Dream Machine and common network device logs.

Each normalizer extracts structured fields from the raw message string and
returns a NormalizedFields dataclass. Fields that cannot be extracted are None.

Supported event types:
  firewall_block / firewall_allow  — kernel netfilter (iptables/nftables)
  ids_alert                        — Suricata IDS/IPS alerts
  dhcp_ack / dhcp_request /
  dhcp_discover / dhcp_release     — dnsmasq DHCP
  auth_success / auth_failure      — SSH, PAM, login
  vpn_connect / vpn_disconnect     — StrongSwan / OpenVPN / WireGuard
  dns_query / dns_response         — dnsmasq DNS
  threat_block                     — Unifi Threat Management
  port_scan                        — scan detection
  nas_login / nas_login_fail /
  nas_logout                       — ASUSTOR ADM authentication
  nas_autoblock                    — ASUSTOR auto-block
  nas_drive_event                  — ASUSTOR drive inserted/removed/SMART
  nas_volume_event                 — ASUSTOR RAID/volume status
  nas_file_access                  — ASUSTOR SMB share connection
  nas_backup                       — ASUSTOR backup task result
  nas_system                       — other ASUSTOR ADM events
  connection                       — generic allow/deny connection log
  system                           — OS/service events
  unknown                          — no pattern matched
"""
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NormalizedFields:
    event_type: str = "unknown"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None      # BLOCK, ALLOW, DROP, REJECT, ACCEPT
    direction: Optional[str] = None   # inbound, outbound, lan, wan
    interface_in: Optional[str] = None
    interface_out: Optional[str] = None
    mac_address: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None    # device hostname from DHCP / DNS
    domain: Optional[str] = None      # DNS query target / SNI hostname / URL host
    url_category: Optional[str] = None  # traffic category: Malware, Streaming, Social, etc.
    rule_name: Optional[str] = None   # firewall rule / IDS signature
    extra: Optional[dict] = field(default_factory=dict)


# ── helpers ──────────────────────────────────────────────────────────────────

_IP4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_IP6 = r"([0-9a-fA-F:]{2,39})"
_PORT = r"(\d{1,5})"
_MAC = r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})"


_CHAIN_ALLOW_RE = re.compile(r'(?:^|[-_])A(?:[-_\d]|$)', re.IGNORECASE)  # -A- or -A10003
_CHAIN_BLOCK_RE = re.compile(r'(?:^|[-_])D(?:[-_\d]|$)', re.IGNORECASE)  # -D- or -D10000


def _action_from_chain(chain: str, descr: str = "") -> str:
    """
    Derive BLOCK/ALLOW from a Unifi/iptables chain name and optional DESCR field.

    Unifi UDM naming conventions:
      CUSTOM2_WAN-A-10003  →  -A-  = Allow
      CUSTOM1_LAN-D-10000  →  -D-  = Drop (Block)
      LAN_LOCAL-default-D  →  trailing -D = Drop
      WAN_IN-default-A     →  trailing -A = Allow
    """
    cu = chain.upper()

    # 1. Explicit keywords in chain name (highest priority)
    if any(x in cu for x in ("DROP", "BLOCK", "DENY", "REJECT", "FORBID")):
        return "BLOCK"
    if any(x in cu for x in ("ACCEPT", "ALLOW", "PERMIT", "PASS")):
        return "ALLOW"

    # 2. Unifi single-letter action code: -A- = Allow, -D- = Drop
    if _CHAIN_ALLOW_RE.search(chain):
        return "ALLOW"
    if _CHAIN_BLOCK_RE.search(chain):
        return "BLOCK"

    # 3. DESCR field as fallback (e.g. DESCR="Allow - Security to External zone")
    dl = descr.lower()
    if any(x in dl for x in ("allow", "accept", "permit", "pass")):
        return "ALLOW"
    if any(x in dl for x in ("block", "drop", "deny", "reject", "forbid")):
        return "BLOCK"

    # 4. Conservative default — unknown chain → treat as block
    return "BLOCK"


# ── Unifi / iptables firewall ─────────────────────────────────────────────────
# kernel: [LAN_LOCAL-default-D]IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=1234 DPT=443
# UDM extended: DESCR="rule description" SEQ= ACK= WINDOW= SYN DF MARK= ...
_FW_CHAIN       = re.compile(r"\[([^\]]+)\]")
_FW_KV_QUOTED   = re.compile(r'(\w+)="([^"]*)"')          # KEY="value with spaces"
_FW_KV_PLAIN    = re.compile(r'(\w+)=([^\s"]\S*)')         # KEY=value (no quotes)
_FW_KV_EMPTY    = re.compile(r'(\w+)=(?=\s|$)')            # KEY= (empty value)
# Standalone TCP/IP flags (not KEY=VALUE — just the keyword alone)
_FW_FLAGS       = re.compile(
    r'(?<![=\w])(SYN|ACK|FIN|RST|URG|PSH|ECE|CWR|DF|MF)(?![=\w])'
)

def _parse_firewall(msg: str) -> Optional[NormalizedFields]:
    if "SRC=" not in msg or "DST=" not in msg:
        return None
    chain_m = _FW_CHAIN.search(msg)

    # Build KV dict — quoted values first (handles DESCR="Block IoT to Internal")
    kv: dict[str, str] = {}
    for k, v in _FW_KV_QUOTED.findall(msg):
        kv[k] = v
    # Then unquoted non-empty values (skip keys already captured by quoted pass)
    for k, v in _FW_KV_PLAIN.findall(msg):
        if k not in kv:
            kv[k] = v
    # Empty-value keys (IN= OUT= etc.)
    for (k,) in _FW_KV_EMPTY.findall(msg):
        if k not in kv:
            kv[k] = ""

    if not kv.get("SRC"):
        return None

    chain = chain_m.group(1) if chain_m else ""
    action = _action_from_chain(chain, descr=kv.get("DESCR", ""))
    proto = kv.get("PROTO", "").upper() or None

    try:
        spt = int(kv["SPT"]) if kv.get("SPT") else None
        dpt = int(kv["DPT"]) if kv.get("DPT") else None
    except ValueError:
        spt = dpt = None

    iface_in  = kv.get("IN")  or None
    iface_out = kv.get("OUT") or None

    direction = None
    if chain:
        cu = chain.upper()
        if "WAN" in cu:
            direction = "inbound" if action == "BLOCK" else "outbound"
        elif "LAN" in cu:
            direction = "lan"

    # Standalone TCP/IP flags
    flags = _FW_FLAGS.findall(msg)

    # Build extra: all remaining kv fields + flags
    _core = {"SRC", "DST", "SPT", "DPT", "PROTO", "IN", "OUT", "MAC"}
    extra: dict[str, str] = {}
    for k, v in kv.items():
        if k not in _core and v:
            extra[k.lower()] = v
    if flags:
        extra["flags"] = " ".join(sorted(set(flags)))

    mac_raw = kv.get("MAC", "")
    mac = mac_raw[:17] if mac_raw else None

    return NormalizedFields(
        event_type=f"firewall_{action.lower()}",
        src_ip=kv.get("SRC"),
        dst_ip=kv.get("DST"),
        src_port=spt,
        dst_port=dpt,
        protocol=proto,
        action=action,
        direction=direction,
        interface_in=iface_in,
        interface_out=iface_out,
        mac_address=mac,
        rule_name=chain or None,
        extra=extra,
    )


# ── Suricata IDS/IPS ──────────────────────────────────────────────────────────
# JSON line from eve.json piped through syslog, OR plain text alert
_IDS_JSON = re.compile(r'\{.*"event_type".*\}')
_IDS_PLAIN = re.compile(
    r"(?:ET|GPL|SURICATA|EMERGING)\s+\S+.*?" + _IP4 + r":?" + r"(\d+)?" +
    r".*?->\s*" + _IP4 + r":?" + r"(\d+)?",
    re.IGNORECASE,
)

_IDS_CATEGORY = re.compile(r"\[Classification:\s*([^\]]+)\]", re.IGNORECASE)
_IDS_PRIORITY = re.compile(r"\[Priority:\s*(\d+)\]", re.IGNORECASE)

def _parse_ids(msg: str) -> Optional[NormalizedFields]:
    # Try JSON first (Suricata eve.json)
    jm = _IDS_JSON.search(msg)
    if jm:
        try:
            d = json.loads(jm.group(0))
            if d.get("event_type") == "alert":
                alert = d.get("alert", {})
                cat = alert.get("category") or ""
                return NormalizedFields(
                    event_type="ids_alert",
                    src_ip=d.get("src_ip"),
                    dst_ip=d.get("dest_ip"),
                    src_port=d.get("src_port"),
                    dst_port=d.get("dest_port"),
                    protocol=d.get("proto", "").upper() or None,
                    action="BLOCK" if alert.get("action") == "blocked" else "ALERT",
                    rule_name=alert.get("signature"),
                    url_category=cat or None,
                    extra={"category": cat, "severity": alert.get("severity")},
                )
        except (json.JSONDecodeError, KeyError):
            pass

    # Plain text Suricata / Snort style
    if not any(x in msg.upper() for x in ("ET ", "GPL ", "SURICATA", "EMERGING")):
        return None
    m = _IDS_PLAIN.search(msg)
    if m:
        try:
            sp = int(m.group(2)) if m.group(2) else None
            dp = int(m.group(4)) if m.group(4) else None
        except ValueError:
            sp = dp = None
        cat_m = _IDS_CATEGORY.search(msg)
        cat = cat_m.group(1).strip() if cat_m else None
        return NormalizedFields(
            event_type="ids_alert",
            src_ip=m.group(1),
            dst_ip=m.group(3),
            src_port=sp,
            dst_port=dp,
            action="ALERT",
            rule_name=msg[:120],
            url_category=cat,
        )
    return None


# ── Unifi Threat Management ───────────────────────────────────────────────────
# "Threat Management blocked <IP> (category: Malware)"
# "ubnt-threat-mgmt: blocked src=1.2.3.4 category=Botnet"
_THREAT = re.compile(
    r"(?:threat|blocked|malware|botnet|phishing|exploit|ransomware|adware|spyware)",
    re.IGNORECASE,
)
_THREAT_IP = re.compile(r"(?:blocked\s+|src=)" + _IP4, re.IGNORECASE)
_THREAT_CAT = re.compile(r"category[=:\s]+([^,\)\s]+)", re.IGNORECASE)
_THREAT_DOMAIN = re.compile(r"domain[=:\s]+(\S+)", re.IGNORECASE)

def _parse_threat(msg: str) -> Optional[NormalizedFields]:
    if not _THREAT.search(msg):
        return None
    ip_m   = _THREAT_IP.search(msg)
    cat_m  = _THREAT_CAT.search(msg)
    dom_m  = _THREAT_DOMAIN.search(msg)
    cat    = cat_m.group(1).strip() if cat_m else None
    return NormalizedFields(
        event_type="threat_block",
        src_ip=ip_m.group(1) if ip_m else None,
        domain=dom_m.group(1).strip() if dom_m else None,
        action="BLOCK",
        url_category=cat or "Threat",
        rule_name=cat or "Threat Management",
    )


# ── DHCP (dnsmasq) ────────────────────────────────────────────────────────────
# "DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff myhostname"
# "DHCPREQUEST(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff"
_DHCP = re.compile(
    r"(DHCP\w+)\((\S+)\)\s+" + _IP4 + r"(?:\s+" + _MAC + r"(?:\s+(\S+))?)?",
    re.IGNORECASE,
)

def _parse_dhcp(msg: str) -> Optional[NormalizedFields]:
    m = _DHCP.search(msg)
    if not m:
        return None
    msg_type = m.group(1).upper()
    type_map = {
        "DHCPACK": "dhcp_ack", "DHCPOFFER": "dhcp_offer",
        "DHCPREQUEST": "dhcp_request", "DHCPDISCOVER": "dhcp_discover",
        "DHCPRELEASE": "dhcp_release", "DHCPNAK": "dhcp_nak",
    }
    return NormalizedFields(
        event_type=type_map.get(msg_type, "dhcp"),
        src_ip=m.group(3),
        interface_in=m.group(2),
        mac_address=m.group(4),
        hostname=m.group(5),
        action="ALLOW",
    )


# ── Auth / SSH / PAM ──────────────────────────────────────────────────────────
_AUTH_FAIL = re.compile(
    r"(?:Failed|Invalid|failure|authentication failure|FAILED)"
    r".*?(?:for\s+(?:invalid user\s+)?(\S+)\s+)?from\s+" + _IP4 +
    r"(?:\s+port\s+" + _PORT + r")?",
    re.IGNORECASE,
)
_AUTH_OK = re.compile(
    r"(?:Accepted|successful|opened session)"
    r".*?for\s+(\S+)\s+from\s+" + _IP4 +
    r"(?:\s+port\s+" + _PORT + r")?",
    re.IGNORECASE,
)
_AUTH_KEYWORDS = re.compile(
    r"\b(sshd|login|pam|su|sudo|auth)\b", re.IGNORECASE
)

def _parse_auth(msg: str) -> Optional[NormalizedFields]:
    if not _AUTH_KEYWORDS.search(msg):
        return None
    m = _AUTH_FAIL.search(msg)
    if m:
        try:
            port = int(m.group(3)) if m.group(3) else None
        except (ValueError, TypeError):
            port = None
        return NormalizedFields(
            event_type="auth_failure",
            src_ip=m.group(2),
            src_port=port,
            user=m.group(1),
            action="BLOCK",
            protocol="SSH",
        )
    m = _AUTH_OK.search(msg)
    if m:
        try:
            port = int(m.group(3)) if m.group(3) else None
        except (ValueError, TypeError):
            port = None
        return NormalizedFields(
            event_type="auth_success",
            src_ip=m.group(2),
            src_port=port,
            user=m.group(1),
            action="ALLOW",
            protocol="SSH",
        )
    return None


# ── VPN ───────────────────────────────────────────────────────────────────────
_VPN_UP = re.compile(
    r"(?:established|connected|ESTABLISHED|peer.*up)",
    re.IGNORECASE,
)
_VPN_DOWN = re.compile(
    r"(?:disconnected|terminated|TERMINATED|deleting|peer.*down)",
    re.IGNORECASE,
)
_VPN_KEYWORD = re.compile(
    r"\b(ike|ipsec|vpn|openvpn|wireguard|strongswan|charon|l2tp)\b",
    re.IGNORECASE,
)
_VPN_IP = re.compile(r"(?:peer|remote|from)\s+" + _IP4, re.IGNORECASE)

def _parse_vpn(msg: str) -> Optional[NormalizedFields]:
    if not _VPN_KEYWORD.search(msg):
        return None
    ip_m = _VPN_IP.search(msg)
    if _VPN_UP.search(msg):
        etype = "vpn_connect"
    elif _VPN_DOWN.search(msg):
        etype = "vpn_disconnect"
    else:
        return None
    return NormalizedFields(
        event_type=etype,
        src_ip=ip_m.group(1) if ip_m else None,
        action="ALLOW" if etype == "vpn_connect" else "CLOSE",
        protocol="VPN",
    )


# ── DNS (dnsmasq + CoreDNS) ───────────────────────────────────────────────────
# dnsmasq: "query[A] example.com from 192.168.1.5"
# dnsmasq: "reply example.com is 93.184.216.34"
# CoreDNS: [INFO] 10.10.100.50:52341 - 1 "A IN example.com. udp 28 false 512" NOERROR qr,rd 48b 0.001s
_DNS_QUERY = re.compile(
    r"query\[(\w+)\]\s+(\S+)\s+from\s+" + _IP4, re.IGNORECASE
)
_DNS_REPLY = re.compile(
    r"reply\s+(\S+)\s+is\s+(\S+)", re.IGNORECASE
)
_DNS_COREDNS = re.compile(
    r'"(\w+)\s+IN\s+(\S+?)\.' +         # query type + domain (trailing dot)
    r'.*?"\s+\w+',                        # response code
    re.IGNORECASE,
)
_DNS_COREDNS_CLIENT = re.compile(r'\]\s+' + _IP4 + r':\d+\s+-\s+\d+\s+"')
_DNS_KEYWORD = re.compile(r"\b(dnsmasq|named|bind|query|nxdomain|coredns)\b", re.IGNORECASE)
# Also catch raw CoreDNS log lines which start with [INFO]/[ERROR] + IP
_DNS_COREDNS_LINE = re.compile(r'\[(?:INFO|WARN|ERROR)\]\s+' + _IP4 + r':\d+')

def _parse_dns(msg: str) -> Optional[NormalizedFields]:
    # CoreDNS format: [INFO] 10.10.100.50:52341 - 1 "A IN example.com. udp 28 false 512" NOERROR
    if _DNS_COREDNS_LINE.search(msg):
        client_m = _DNS_COREDNS_CLIENT.search(msg)
        query_m  = _DNS_COREDNS.search(msg)
        if query_m:
            domain = query_m.group(2).rstrip(".")
            return NormalizedFields(
                event_type="dns_query",
                src_ip=client_m.group(1) if client_m else None,
                domain=domain,
                protocol="DNS",
                extra={"qtype": query_m.group(1)},
            )

    if not _DNS_KEYWORD.search(msg):
        return None

    # dnsmasq query
    m = _DNS_QUERY.search(msg)
    if m:
        return NormalizedFields(
            event_type="dns_query",
            src_ip=m.group(3),
            domain=m.group(2).rstrip("."),
            protocol="DNS",
            extra={"qtype": m.group(1)},
        )
    # dnsmasq reply
    m = _DNS_REPLY.search(msg)
    if m:
        return NormalizedFields(
            event_type="dns_response",
            domain=m.group(1).rstrip("."),
            dst_ip=m.group(2) if re.match(r"^\d+\.\d+\.\d+\.\d+$", m.group(2)) else None,
            protocol="DNS",
        )
    return None


# ── Content filter / Web category (UDM + Squid + Pi-hole) ────────────────────
# UDM: "content filter blocked: url=http://example.com category=Social Networks client=192.168.1.5"
# Pi-hole: "gravity blocked example.com (from 192.168.1.5)"
# Squid: "DENIED http://example.com/ [Social Networks]"
_CF_URL = re.compile(r'url[=:\s]+(https?://\S+)', re.IGNORECASE)
_CF_HOST = re.compile(r'(?:blocked|denied)\s+(?:https?://)?(\S+?)(?:\s|/|$)', re.IGNORECASE)
_CF_CAT = re.compile(r'categor\w*[=:\s]+([^,\)\]\n]+)', re.IGNORECASE)
_CF_CLIENT = re.compile(r'(?:client|from)[=:\s]+' + _IP4, re.IGNORECASE)
_CF_KEYWORD = re.compile(
    r'(?:content.filter|web.filter|squid|pihole|pi-hole|gravity|adblock|dnsbl)',
    re.IGNORECASE,
)

def _parse_content_filter(msg: str) -> Optional[NormalizedFields]:
    if not _CF_KEYWORD.search(msg):
        return None
    url_m    = _CF_URL.search(msg)
    host_m   = _CF_HOST.search(msg)
    cat_m    = _CF_CAT.search(msg)
    client_m = _CF_CLIENT.search(msg)

    domain = None
    if url_m:
        # Extract host from URL
        import urllib.parse as _up
        try:
            domain = _up.urlparse(url_m.group(1)).netloc or None
        except Exception:
            domain = url_m.group(1)
    elif host_m:
        domain = host_m.group(1).strip("/").rstrip(".")

    cat = cat_m.group(1).strip() if cat_m else None

    return NormalizedFields(
        event_type="content_filter",
        src_ip=client_m.group(1) if client_m else None,
        domain=domain,
        url_category=cat or "Blocked",
        action="BLOCK",
    )


# ── Port scan detection ───────────────────────────────────────────────────────
_SCAN = re.compile(
    r"(?:port.?scan|nmap|masscan|scan detected)",
    re.IGNORECASE,
)
_SCAN_IP = re.compile(r"from\s+" + _IP4, re.IGNORECASE)

def _parse_scan(msg: str) -> Optional[NormalizedFields]:
    if not _SCAN.search(msg):
        return None
    ip_m = _SCAN_IP.search(msg)
    return NormalizedFields(
        event_type="port_scan",
        src_ip=ip_m.group(1) if ip_m else None,
        action="ALERT",
    )


# ── ASUSTOR ADM (AS5304T and compatible NAS devices) ─────────────────────────
# ADM service names that identify ASUSTOR-origin syslog messages.
_NAS_APP_KW = re.compile(
    r"\b(adm_session|nas_disks?|nas_volume|nas_system|auto_block|nas_backup)\b",
    re.IGNORECASE,
)
# ADM login/logout — "User [admin] logged in from [192.168.1.50]."
_NAS_LOGIN_OK   = re.compile(r"User\s+\[([^\]]+)\]\s+logged\s+in\s+from\s+\[([0-9.]+)\]",   re.IGNORECASE)
_NAS_LOGIN_FAIL = re.compile(r"User\s+\[([^\]]+)\]\s+login\s+failed\s+from\s+\[([0-9.]+)\]", re.IGNORECASE)
_NAS_LOGOUT     = re.compile(r"User\s+\[([^\]]+)\]\s+logged\s+out\s+from\s+\[([0-9.]+)\]",   re.IGNORECASE)
# ADM auto-block — "IP [192.168.1.100] has been auto-blocked due to..."
_NAS_AUTOBLOCK  = re.compile(r"IP\s+\[([0-9.]+)\]\s+has\s+been\s+auto[-\s]?block",           re.IGNORECASE)
# ADM drive events — "Drive [1] has been removed."
_NAS_DRIVE      = re.compile(r"Drive\s+\[(\d+)\]\s+has\s+been\s+(\w+)",                       re.IGNORECASE)
# ADM SMART — "SMART test result for Drive [1]: PASSED."
_NAS_SMART      = re.compile(r"SMART\s+test\s+result\s+for\s+Drive\s+\[(\d+)\]:\s+(\w+)",    re.IGNORECASE)
# ADM volume/RAID — "Volume [1] status changed to [Degraded]."
_NAS_VOLUME     = re.compile(r"Volume\s+\[([^\]]+)\]\s+status\s+changed\s+to\s+\[([^\]]+)\]", re.IGNORECASE)
# Samba share connect — "connect to service sharename initially as user admin (ip 192.168.1.50)"
_NAS_SMB        = re.compile(
    r"connect\s+to\s+service\s+(\S+)\s+initially\s+as\s+user\s+(\S+)\s+\(ip\s+([0-9.]+)\)",
    re.IGNORECASE,
)
# ADM backup — "Backup task [My Backup] completed successfully." / "...failed."
_NAS_BACKUP     = re.compile(
    r"Backup\s+task\s+\[([^\]]+)\]\s+(completed\s+successfully|failed)",
    re.IGNORECASE,
)


def _parse_nas(msg: str) -> Optional[NormalizedFields]:
    if not _NAS_APP_KW.search(msg):
        return None

    m = _NAS_LOGIN_FAIL.search(msg)
    if m:
        return NormalizedFields(event_type="nas_login_fail", user=m.group(1), src_ip=m.group(2), action="BLOCK")

    m = _NAS_LOGIN_OK.search(msg)
    if m:
        return NormalizedFields(event_type="nas_login", user=m.group(1), src_ip=m.group(2), action="ALLOW")

    m = _NAS_LOGOUT.search(msg)
    if m:
        return NormalizedFields(event_type="nas_logout", user=m.group(1), src_ip=m.group(2), action="ALLOW")

    m = _NAS_AUTOBLOCK.search(msg)
    if m:
        return NormalizedFields(event_type="nas_autoblock", src_ip=m.group(1), action="BLOCK")

    # Check SMART before generic drive so the more specific pattern wins
    m = _NAS_SMART.search(msg)
    if m:
        passed = m.group(2).lower() == "passed"
        return NormalizedFields(
            event_type="nas_drive_event",
            action="ALLOW" if passed else "ALERT",
            extra={"drive": m.group(1), "smart": m.group(2).lower()},
        )

    m = _NAS_DRIVE.search(msg)
    if m:
        status = m.group(2).lower()
        return NormalizedFields(
            event_type="nas_drive_event",
            action="ALERT" if status in ("removed", "failed") else "ALLOW",
            extra={"drive": m.group(1), "status": status},
        )

    m = _NAS_VOLUME.search(msg)
    if m:
        status = m.group(2).lower()
        return NormalizedFields(
            event_type="nas_volume_event",
            action="ALLOW" if status in ("normal", "healthy") else "ALERT",
            extra={"volume": m.group(1), "status": status},
        )

    m = _NAS_SMB.search(msg)
    if m:
        return NormalizedFields(
            event_type="nas_file_access",
            rule_name=m.group(1),
            user=m.group(2),
            src_ip=m.group(3),
            action="ALLOW",
            protocol="SMB",
        )

    m = _NAS_BACKUP.search(msg)
    if m:
        success = "completed" in m.group(2).lower()
        return NormalizedFields(
            event_type="nas_backup",
            action="ALLOW" if success else "ALERT",
            extra={"task": m.group(1), "result": "success" if success else "failed"},
        )

    return NormalizedFields(event_type="nas_system")


# ── AI-registered dynamic parsers ─────────────────────────────────────────────
# The AI agent can register new log source parsers at runtime via the
# register_log_source tool. Patterns are stored in the DB and compiled into
# this in-memory cache. Call load_custom_parsers() on startup and after any
# DB write to keep the cache current.

_custom_lock: threading.Lock = threading.Lock()
_custom_cache: list[dict] = []


def load_custom_parsers(parsers: list[dict]) -> None:
    """Compile and hot-reload custom parsers from DB records.

    Each entry in `parsers` must have:
      app_keywords: list[str]   — any one must be present to try this parser
      patterns:     list[dict]  — {regex, event_type, action?, fields?}
        fields maps NormalizedFields attribute names to 1-based capture group index
    """
    compiled: list[dict] = []
    for p in parsers:
        if not p.get("enabled", True):
            continue
        try:
            kw_re = re.compile(
                "|".join(re.escape(k) for k in p["app_keywords"] if k),
                re.IGNORECASE,
            )
            rules: list[dict] = []
            for rule in p.get("patterns", []):
                rules.append({
                    "re":         re.compile(rule["regex"], re.IGNORECASE),
                    "event_type": rule["event_type"],
                    "action":     rule.get("action"),
                    "fields":     {k: int(v) for k, v in rule.get("fields", {}).items()},
                })
            if rules:
                compiled.append({"kw": kw_re, "rules": rules})
        except re.error:
            continue
    with _custom_lock:
        _custom_cache[:] = compiled


def _parse_custom(msg: str) -> Optional[NormalizedFields]:
    with _custom_lock:
        snapshot = list(_custom_cache)
    for parser in snapshot:
        if not parser["kw"].search(msg):
            continue
        for rule in parser["rules"]:
            m = rule["re"].search(msg)
            if not m:
                continue
            groups = m.groups()
            kwargs: dict = {"event_type": rule["event_type"]}
            if rule["action"]:
                kwargs["action"] = rule["action"]
            for field_name, idx in rule["fields"].items():
                try:
                    val = groups[idx - 1]
                    if val is not None:
                        kwargs[field_name] = val
                except IndexError:
                    pass
            return NormalizedFields(**kwargs)
    return None


# ── Pipeline ──────────────────────────────────────────────────────────────────

_PARSERS = [
    _parse_firewall,
    _parse_ids,
    _parse_threat,
    _parse_content_filter,
    _parse_dhcp,
    _parse_nas,       # ASUSTOR ADM — before auth to catch ADM login format first
    _parse_auth,
    _parse_vpn,
    _parse_dns,
    _parse_scan,
    _parse_custom,    # AI-registered sources — checked last before unknown fallback
]


def normalize(message: str) -> NormalizedFields:
    """Run message through all parsers; return first match or unknown."""
    if not message:
        return NormalizedFields()
    for parser in _PARSERS:
        try:
            result = parser(message)
            if result is not None:
                return result
        except Exception:
            continue
    return NormalizedFields(event_type="unknown")
