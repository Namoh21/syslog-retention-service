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
  connection                       — generic allow/deny connection log
  system                           — OS/service events
  unknown                          — no pattern matched
"""
import json
import re
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
    domain: Optional[str] = None      # DNS query target
    rule_name: Optional[str] = None   # firewall rule / IDS signature
    extra: Optional[dict] = field(default_factory=dict)


# ── helpers ──────────────────────────────────────────────────────────────────

_IP4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_IP6 = r"([0-9a-fA-F:]{2,39})"
_PORT = r"(\d{1,5})"
_MAC = r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})"


def _action_from_chain(chain: str) -> str:
    chain = chain.upper()
    if any(x in chain for x in ("DROP", "BLOCK", "DENY", "REJECT", "FORBID")):
        return "BLOCK"
    if any(x in chain for x in ("ACCEPT", "ALLOW", "PERMIT", "PASS")):
        return "ALLOW"
    return "BLOCK"  # Unifi default-D means default-Drop


# ── Unifi / iptables firewall ─────────────────────────────────────────────────
# kernel: [LAN_LOCAL-default-D]IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=1234 DPT=443
_FW_CHAIN = re.compile(r"\[([^\]]+)\]")
_FW_KV = re.compile(r"(\w+)=(\S*)")

def _parse_firewall(msg: str) -> Optional[NormalizedFields]:
    if "SRC=" not in msg or "DST=" not in msg:
        return None
    chain_m = _FW_CHAIN.search(msg)
    kv = dict(_FW_KV.findall(msg))
    if not kv.get("SRC"):
        return None
    chain = chain_m.group(1) if chain_m else ""
    action = _action_from_chain(chain)
    proto = kv.get("PROTO", "").upper() or None
    try:
        spt = int(kv["SPT"]) if "SPT" in kv else None
        dpt = int(kv["DPT"]) if "DPT" in kv else None
    except ValueError:
        spt = dpt = None
    iface_in = kv.get("IN") or None
    iface_out = kv.get("OUT") or None
    direction = None
    if chain:
        cu = chain.upper()
        if "WAN" in cu:
            direction = "inbound" if action == "BLOCK" else "outbound"
        elif "LAN" in cu:
            direction = "lan"
    extra = {}
    for k in ("LEN", "TTL", "ID", "WINDOW", "TOS"):
        if k in kv:
            extra[k.lower()] = kv[k]
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

def _parse_ids(msg: str) -> Optional[NormalizedFields]:
    # Try JSON first (Suricata eve.json)
    jm = _IDS_JSON.search(msg)
    if jm:
        try:
            d = json.loads(jm.group(0))
            if d.get("event_type") == "alert":
                alert = d.get("alert", {})
                return NormalizedFields(
                    event_type="ids_alert",
                    src_ip=d.get("src_ip"),
                    dst_ip=d.get("dest_ip"),
                    src_port=d.get("src_port"),
                    dst_port=d.get("dest_port"),
                    protocol=d.get("proto", "").upper() or None,
                    action="BLOCK" if alert.get("action") == "blocked" else "ALERT",
                    rule_name=alert.get("signature"),
                    extra={"category": alert.get("category"), "severity": alert.get("severity")},
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
        return NormalizedFields(
            event_type="ids_alert",
            src_ip=m.group(1),
            dst_ip=m.group(3),
            src_port=sp,
            dst_port=dp,
            action="ALERT",
            rule_name=msg[:120],
        )
    return None


# ── Unifi Threat Management ───────────────────────────────────────────────────
# "Threat Management blocked <IP> (category: Malware)"
_THREAT = re.compile(
    r"(?:threat|blocked|malware|botnet|phishing|exploit)",
    re.IGNORECASE,
)
_THREAT_IP = re.compile(r"blocked\s+" + _IP4, re.IGNORECASE)
_THREAT_CAT = re.compile(r"category[:\s]+([^,\)]+)", re.IGNORECASE)

def _parse_threat(msg: str) -> Optional[NormalizedFields]:
    if not _THREAT.search(msg):
        return None
    ip_m = _THREAT_IP.search(msg)
    cat_m = _THREAT_CAT.search(msg)
    return NormalizedFields(
        event_type="threat_block",
        src_ip=ip_m.group(1) if ip_m else None,
        action="BLOCK",
        rule_name=cat_m.group(1).strip() if cat_m else "Threat Management",
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


# ── DNS (dnsmasq) ─────────────────────────────────────────────────────────────
# "query[A] example.com from 192.168.1.5"
# "reply example.com is 93.184.216.34"
_DNS_QUERY = re.compile(
    r"query\[(\w+)\]\s+(\S+)\s+from\s+" + _IP4, re.IGNORECASE
)
_DNS_REPLY = re.compile(
    r"reply\s+(\S+)\s+is\s+(\S+)", re.IGNORECASE
)
_DNS_KEYWORD = re.compile(r"\b(dnsmasq|named|bind|query|nxdomain)\b", re.IGNORECASE)

def _parse_dns(msg: str) -> Optional[NormalizedFields]:
    if not _DNS_KEYWORD.search(msg):
        return None
    m = _DNS_QUERY.search(msg)
    if m:
        return NormalizedFields(
            event_type="dns_query",
            src_ip=m.group(3),
            domain=m.group(2),
            protocol="DNS",
            extra={"qtype": m.group(1)},
        )
    m = _DNS_REPLY.search(msg)
    if m:
        return NormalizedFields(
            event_type="dns_response",
            domain=m.group(1),
            dst_ip=m.group(2) if re.match(_IP4, m.group(2)) else None,
            protocol="DNS",
        )
    return None


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


# ── Pipeline ──────────────────────────────────────────────────────────────────

_PARSERS = [
    _parse_firewall,
    _parse_ids,
    _parse_threat,
    _parse_dhcp,
    _parse_auth,
    _parse_vpn,
    _parse_dns,
    _parse_scan,
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
