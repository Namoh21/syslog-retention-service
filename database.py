import base64
import hashlib
import logging
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("database")


def _fernet():
    """Fernet cipher derived from the effective SECRET_KEY (OS keystore preferred)."""
    from cryptography.fernet import Fernet
    from config import EFFECTIVE_SECRET_KEY
    key = base64.urlsafe_b64encode(
        hashlib.sha256(EFFECTIVE_SECRET_KEY.encode()).digest()
    )
    return Fernet(key)


def encrypt_value(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except Exception:
        return ""

from sqlalchemy import (
    Boolean, Column, DateTime, Index, Integer, String, Text, UniqueConstraint,
    create_engine, func, text,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import settings

# Normalized columns added in v1.1 — kept as a list so _migrate_db can add
# them to existing installs without dropping data.
_NORMALIZED_COLUMNS = [
    ("event_type",    "VARCHAR(64)"),
    ("src_ip",        "VARCHAR(45)"),
    ("dst_ip",        "VARCHAR(45)"),
    ("src_port",      "INTEGER"),
    ("dst_port",      "INTEGER"),
    ("protocol",      "VARCHAR(16)"),
    ("action",        "VARCHAR(16)"),
    ("direction",     "VARCHAR(16)"),
    ("interface_in",  "VARCHAR(32)"),
    ("interface_out", "VARCHAR(32)"),
    ("mac_address",   "VARCHAR(17)"),
    ("norm_user",     "VARCHAR(128)"),
    ("norm_hostname", "VARCHAR(255)"),
    ("domain",        "VARCHAR(255)"),
    ("url_category",  "VARCHAR(128)"),
    ("rule_name",     "VARCHAR(255)"),
    ("extra_json",    "TEXT"),
]


def _ensure_db_dir(db_path_str: str) -> str:
    """
    Ensure the database directory is writable.
    If the configured path is on an external mount that is unavailable or
    not writable, fall back to the local data/ directory so the service
    always starts rather than crashing on a missing M.2 drive.
    """
    import sys as _sys
    path = Path(db_path_str)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Quick write-permission probe
        test = path.parent / ".write_test"
        test.touch()
        test.unlink()
        return db_path_str
    except OSError as err:
        fallback = Path(__file__).parent / "data" / "syslog.db"
        print(
            f"WARNING: Cannot write to DB_PATH directory '{path.parent}': {err}\n"
            f"  This usually means the M.2 drive is not mounted or has wrong ownership.\n"
            f"  Falling back to local storage: {fallback}\n"
            f"  Fix: sudo chown -R syslog-siem:syslog-siem /mnt/syslog-data\n"
            f"  Then restart the service to use the configured path again.",
            file=_sys.stderr,
        )
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return str(fallback)

_resolved_db_path = _ensure_db_dir(settings.db_path)

engine = create_engine(
    f"sqlite:///{_resolved_db_path}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# SQLite performance pragmas — applied on every new connection
from sqlalchemy import event as _sa_event

@_sa_event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")       # concurrent reads don't block writes
    cur.execute("PRAGMA synchronous=NORMAL")      # safe but faster than FULL
    cur.execute("PRAGMA cache_size=-32000")       # 32 MB page cache in memory
    cur.execute("PRAGMA temp_store=MEMORY")       # temp tables in RAM, not SD card
    cur.execute("PRAGMA busy_timeout=5000")       # wait up to 5 s instead of failing
    cur.close()


class Base(DeclarativeBase):
    pass


class SyslogEntry(Base):
    __tablename__ = "syslog_entries"

    id = Column(Integer, primary_key=True, index=True)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    log_source_ip = Column(String(45), index=True)  # IP of the device that sent the syslog packet
    facility = Column(Integer)
    severity = Column(Integer, index=True)
    hostname = Column(String(255), index=True)
    app_name = Column(String(128))
    proc_id = Column(String(128))
    msg_id = Column(String(128))
    message = Column(Text)
    raw = Column(Text)

    # Normalized fields (v1.1)
    event_type    = Column(String(64),  nullable=True, index=True)
    src_ip        = Column(String(45),  nullable=True, index=True)
    dst_ip        = Column(String(45),  nullable=True)
    src_port      = Column(Integer,     nullable=True)
    dst_port      = Column(Integer,     nullable=True, index=True)
    protocol      = Column(String(16),  nullable=True)
    action        = Column(String(16),  nullable=True, index=True)
    direction     = Column(String(16),  nullable=True)
    interface_in  = Column(String(32),  nullable=True)
    interface_out = Column(String(32),  nullable=True)
    mac_address   = Column(String(17),  nullable=True)
    norm_user     = Column(String(128), nullable=True)
    norm_hostname = Column(String(255), nullable=True)
    domain        = Column(String(255), nullable=True)
    url_category  = Column(String(128), nullable=True)
    rule_name     = Column(String(255), nullable=True)
    extra_json    = Column(Text,        nullable=True)   # JSON blob for leftover fields

    __table_args__ = (
        Index("ix_entries_received_severity", "received_at", "severity"),
        Index("ix_entries_logsource_received", "log_source_ip", "received_at"),
        Index("ix_entries_event_type", "event_type", "received_at"),
        Index("ix_entries_src_ip", "src_ip", "received_at"),
        Index("ix_entries_action", "action", "received_at"),
    )


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Incremented on password change to invalidate outstanding JWTs
    token_version = Column(Integer, default=0, nullable=False)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(256), unique=True, index=True, nullable=False)
    label = Column(String(128))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    read_only = Column(Boolean, default=True)


class RetentionPolicy(Base):
    __tablename__ = "retention_policy"

    id = Column(Integer, primary_key=True)
    retention_days = Column(Integer, default=90)
    max_entries = Column(Integer, default=5_000_000)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ServiceSetting(Base):
    """Encrypted key-value store for sensitive service configuration."""
    __tablename__ = "service_settings"

    key = Column(String(128), primary_key=True)
    encrypted_value = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    """Immutable record of admin actions for accountability."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    username = Column(String(64), index=True)
    action = Column(String(64), index=True)
    detail = Column(Text)
    ip_address = Column(String(45))


class AlertRule(Base):
    """User-defined condition that triggers a notification."""
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    enabled = Column(Boolean, default=True)
    # condition_type: threshold | pattern | severity | new_ip
    condition_type = Column(String(32), nullable=False)
    condition_params = Column(Text)          # JSON: filters to apply
    window_minutes = Column(Integer, default=5)
    threshold = Column(Integer, default=1)   # events in window to trigger
    cooldown_minutes = Column(Integer, default=60)
    notify_webhook = Column(String(512))
    notify_email = Column(String(256))
    last_fired_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AlertEvent(Base):
    """Record of a fired alert rule."""
    __tablename__ = "alert_events"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, nullable=False, index=True)
    rule_name = Column(String(128))
    fired_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    detail = Column(Text)
    acknowledged = Column(Boolean, default=False)


class AIAnalysis(Base):
    """Persisted record of each AI analysis run."""
    __tablename__ = "ai_analyses"

    id           = Column(Integer, primary_key=True, index=True)
    analyzed_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    focus        = Column(String(256))
    hours_covered = Column(Integer)
    log_count    = Column(Integer)
    threat_level = Column(String(16))
    summary      = Column(Text)
    immediate_actions_json = Column(Text)   # JSON array of strings
    findings_json          = Column(Text)   # JSON array of finding dicts


class AIRecommendation(Base):
    """Individual finding/recommendation extracted from an analysis."""
    __tablename__ = "ai_recommendations"

    id          = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, index=True, nullable=False)
    title       = Column(String(256))
    severity    = Column(String(16))   # AI-assigned: CRITICAL/HIGH/MEDIUM/LOW/INFO
    detail      = Column(Text)
    recommendation = Column(Text)
    # open | implemented | working | investigating | dismissed
    status      = Column(String(32), default="open", nullable=False)
    # User-assigned priority: critical | high | medium | low (overrides AI severity)
    priority    = Column(String(16), nullable=True)
    user_notes  = Column(Text)
    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AINetworkContext(Base):
    """User-maintained notes about the network, included in every analysis."""
    __tablename__ = "ai_network_context"

    id         = Column(Integer, primary_key=True)
    content    = Column(Text, default="")
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AIContextEntry(Base):
    """Structured knowledge-base entries injected into every AI analysis."""
    __tablename__ = "ai_context_entries"

    id         = Column(Integer, primary_key=True, index=True)
    title      = Column(String(256), nullable=False)
    category   = Column(String(64), nullable=False, default="custom")
    content    = Column(Text, nullable=False, default="")
    active     = Column(Integer, nullable=False, default=1)   # 1=included, 0=excluded
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DpiRecord(Base):
    """Per-client DPI record fetched from the UniFi Network Application API."""
    __tablename__ = "dpi_records"

    id           = Column(Integer, primary_key=True)
    polled_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    mac_address  = Column(String(17),  nullable=True, index=True)
    src_ip       = Column(String(45),  nullable=True, index=True)
    hostname     = Column(String(255), nullable=True)
    app_name     = Column(String(128), nullable=True)   # e.g. "Netflix", "YouTube"
    url_category = Column(String(128), nullable=True)   # e.g. "Streaming", "Social"
    tx_bytes     = Column(Integer,     nullable=True, default=0)
    rx_bytes     = Column(Integer,     nullable=True, default=0)


class UnifiConfigSnapshot(Base):
    __tablename__ = "unifi_config_snapshots"
    id           = Column(Integer, primary_key=True)
    taken_at     = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    config_json  = Column(Text, nullable=False)   # full JSON snapshot
    changes_json = Column(Text, nullable=True)    # diff from previous snapshot (JSON)
    has_changes  = Column(Boolean, default=False, index=True)


class UnifiConfigChange(Base):
    __tablename__ = "unifi_config_changes"
    id          = Column(Integer, primary_key=True)
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    section     = Column(String(64),  nullable=False)   # firewall_rules, port_forwards, etc.
    change_type = Column(String(16),  nullable=False)   # added, removed, modified
    item_name   = Column(String(256), nullable=True)
    before_json = Column(Text, nullable=True)
    after_json  = Column(Text, nullable=True)


class CustomAgent(Base):
    __tablename__ = "custom_agents"
    id         = Column(Integer, primary_key=True)
    key        = Column(String(64), unique=True, nullable=False)   # slug, e.g. "my_agent"
    label      = Column(String(128), nullable=False)
    description= Column(Text, nullable=True)
    system_prompt = Column(Text, nullable=False)
    use_kb_history = Column(Boolean, default=True)
    schema_type = Column(String(32), default="auto")  # siem_cti | nre | auto
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


class CustomParser(Base):
    """AI-registered log source parsers stored as JSON pattern rules.

    app_keywords: JSON list[str] — any substring that gates this parser
    patterns:     JSON list[dict] — {regex, event_type, action?, fields?}
                  fields maps NormalizedFields attribute names → 1-based group index
    created_by:   "ai_agent" when registered autonomously, username otherwise
    """
    __tablename__ = "custom_parsers"
    id           = Column(Integer, primary_key=True)
    name         = Column(String(128), unique=True, nullable=False)
    description  = Column(Text, default="")
    app_keywords = Column(Text, nullable=False)
    patterns     = Column(Text, nullable=False)
    enabled      = Column(Boolean, default=True)
    created_at   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_by   = Column(String(128), default="ai_agent")


class NetFlowRecord(Base):
    """A single IP flow record received from the NetFlow exporter (UDM Pro)."""
    __tablename__ = "netflow_records"

    id          = Column(Integer, primary_key=True, index=True)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    exporter_ip = Column(String(45), index=True)   # IP of the device sending NetFlow
    src_ip      = Column(String(45), index=True)
    dst_ip      = Column(String(45), index=True)
    src_port    = Column(Integer)
    dst_port    = Column(Integer, index=True)
    protocol    = Column(Integer)                  # IP protocol number
    proto_name  = Column(String(16))               # TCP / UDP / ICMP / etc.
    bytes       = Column(Integer, default=0)
    packets     = Column(Integer, default=0)
    tcp_flags   = Column(Integer)
    flow_start  = Column(DateTime(timezone=True))
    flow_end    = Column(DateTime(timezone=True))
    tos         = Column(Integer)
    src_as      = Column(Integer)                  # BGP AS number
    dst_as      = Column(Integer)
    domain      = Column(String(255), nullable=True, index=True)  # resolved from DNS cache


class DnsCache(Base):
    """DNS query/response cache — domain↔IP mappings from dnsmasq syslog events."""
    __tablename__ = "dns_cache"

    id          = Column(Integer, primary_key=True)
    recorded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    domain      = Column(String(255), nullable=False, index=True)
    resolved_ip = Column(String(45),  nullable=False, index=True)
    client_ip   = Column(String(45),  nullable=True)


class IpReputationCache(Base):
    """Cached AbuseIPDB + GeoIP results — avoids re-querying the same IP repeatedly."""
    __tablename__ = "ip_reputation_cache"

    ip = Column(String(45), primary_key=True)
    abuse_score = Column(Integer, nullable=True)     # 0-100
    abuse_reports = Column(Integer, nullable=True)
    country_code = Column(String(4), nullable=True)
    country_name = Column(String(64), nullable=True)
    isp = Column(String(128), nullable=True)
    is_tor = Column(Boolean, nullable=True)
    is_vpn = Column(Boolean, nullable=True)
    threat_categories = Column(Text, nullable=True)  # JSON list
    geo_city = Column(String(64), nullable=True)
    fetched_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id             = Column(Integer, primary_key=True, index=True)
    rule_id        = Column(String(64), unique=True, index=True, nullable=False)
    name           = Column(String(256), nullable=False)
    description    = Column(Text, nullable=True)
    severity       = Column(String(16), nullable=False, default="medium")
    category       = Column(String(64), nullable=True, index=True)
    tags_json      = Column(Text, nullable=True)
    condition_json = Column(Text, nullable=False)
    false_positives_json = Column(Text, nullable=True)
    enabled        = Column(Boolean, default=True, index=True)
    source_file    = Column(String(512), nullable=True)
    version        = Column(String(32), nullable=True)
    author         = Column(String(128), nullable=True)
    created_at     = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at     = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    file_hash      = Column(String(64), nullable=True)
    __table_args__ = (Index("ix_detection_rules_enabled_category", "enabled", "category"),)


class DetectionMatch(Base):
    __tablename__ = "detection_matches"
    id            = Column(Integer, primary_key=True, index=True)
    rule_id       = Column(Integer, nullable=False, index=True)
    rule_name     = Column(String(256), nullable=False)
    rule_str_id   = Column(String(64), nullable=False, index=True)
    entry_id      = Column(Integer, nullable=False, index=True)
    matched_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    severity      = Column(String(16), nullable=False, index=True)
    mitre_techniques_json = Column(Text, nullable=True)
    matched_fields_json   = Column(Text, nullable=True)
    entry_received_at     = Column(DateTime(timezone=True), nullable=True, index=True)
    acknowledged  = Column(Boolean, default=False, index=True)
    notified      = Column(Boolean, default=False)
    __table_args__ = (
        Index("ix_detmatches_rule_matched", "rule_id", "matched_at"),
        Index("ix_detmatches_severity_matched", "severity", "matched_at"),
    )


class ThreatIntelFeed(Base):
    __tablename__ = "threat_intel_feeds"
    id            = Column(Integer, primary_key=True, index=True)
    name          = Column(String(128), nullable=False, unique=True)
    feed_type     = Column(String(32), nullable=False)   # cisa_kev|otx|misp|taxii
    config_json   = Column(Text, nullable=True)          # URL, collection, etc (non-secret)
    encrypted_api_key = Column(Text, nullable=True)      # via existing encrypt_value()
    poll_interval_minutes = Column(Integer, default=60)
    enabled       = Column(Boolean, default=True, index=True)
    last_polled_at = Column(DateTime(timezone=True), nullable=True)
    last_error    = Column(Text, nullable=True)
    indicator_count = Column(Integer, default=0)
    created_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id            = Column(Integer, primary_key=True, index=True)
    feed_id       = Column(Integer, nullable=False, index=True)
    indicator_type = Column(String(32), nullable=False, index=True)  # ip|domain|cve|hash|url
    value         = Column(String(512), nullable=False, index=True)
    confidence    = Column(Integer, default=50)          # 0-100
    severity      = Column(String(16), nullable=True)    # critical|high|medium|low
    tags_json     = Column(Text, nullable=True)          # ["ransomware", "apt"]
    source_ref    = Column(String(256), nullable=True)   # CVE ID, OTX pulse, etc
    first_seen    = Column(DateTime(timezone=True), nullable=True)
    last_seen     = Column(DateTime(timezone=True), nullable=True)
    expires_at    = Column(DateTime(timezone=True), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        Index("ix_threat_indicators_type_value", "indicator_type", "value"),
        UniqueConstraint("feed_id", "indicator_type", "value", name="uq_indicator_feed_type_value"),
    )


class IocMatch(Base):
    __tablename__ = "ioc_matches"
    id            = Column(Integer, primary_key=True, index=True)
    indicator_id  = Column(Integer, nullable=False, index=True)
    entry_id      = Column(Integer, nullable=True, index=True)   # SyslogEntry.id
    netflow_id    = Column(Integer, nullable=True, index=True)   # NetFlowRecord.id if exists
    matched_field = Column(String(64), nullable=False)           # src_ip, dst_ip, domain, etc
    matched_value = Column(String(512), nullable=False)
    matched_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    severity      = Column(String(16), nullable=False, index=True)
    acknowledged  = Column(Boolean, default=False, index=True)
    notified      = Column(Boolean, default=False)
    __table_args__ = (Index("ix_ioc_matches_indicator_matched", "indicator_id", "matched_at"),)


class Investigation(Base):
    __tablename__ = "investigations"
    id            = Column(Integer, primary_key=True, index=True)
    trigger_type  = Column(String(32), nullable=False)   # detection_match|alert|ioc_match|manual
    trigger_id    = Column(Integer, nullable=True, index=True)
    title         = Column(String(256), nullable=False)
    status        = Column(String(32), nullable=False, default="running", index=True)  # running|complete|failed|cancelled
    verdict       = Column(String(32), nullable=True)    # true_positive|false_positive|inconclusive
    severity      = Column(String(16), nullable=True, index=True)
    summary       = Column(Text, nullable=True)          # AI-generated narrative
    mitre_techniques_json = Column(Text, nullable=True)  # confirmed techniques
    entities_json = Column(Text, nullable=True)          # {ips:[], domains:[], users:[], hosts:[]}
    created_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    completed_at  = Column(DateTime(timezone=True), nullable=True)
    model_used    = Column(String(64), nullable=True)


class InvestigationStep(Base):
    __tablename__ = "investigation_steps"
    id            = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, nullable=False, index=True)
    step_number   = Column(Integer, nullable=False)
    tool_name     = Column(String(64), nullable=False)   # query_logs|enrich_ip|lookup_ioc|get_netflow|search_dns
    tool_input_json  = Column(Text, nullable=False)
    tool_output_json = Column(Text, nullable=True)
    reasoning     = Column(Text, nullable=True)          # AI reasoning for this step
    duration_ms   = Column(Integer, nullable=True)
    created_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def _migrate_db():
    """Add any missing columns to existing tables (safe to re-run)."""
    with engine.connect() as conn:
        # syslog_entries normalized columns
        existing = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(syslog_entries)")).fetchall()
        }
        for col_name, col_type in _NORMALIZED_COLUMNS:
            if col_name not in existing:
                conn.execute(text(f"ALTER TABLE syslog_entries ADD COLUMN {col_name} {col_type}"))

        # Rename source_ip → log_source_ip for clarity (source_ip was the syslog sender IP,
        # easily confused with src_ip which is the traffic source inside the log message)
        if "source_ip" in existing and "log_source_ip" not in existing:
            conn.execute(text("ALTER TABLE syslog_entries RENAME COLUMN source_ip TO log_source_ip"))

        # netflow_records.domain — DNS-enriched destination domain
        nf_cols = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(netflow_records)")).fetchall()
        }
        if "domain" not in nf_cols:
            conn.execute(text("ALTER TABLE netflow_records ADD COLUMN domain VARCHAR(255)"))

        # dns_cache table — populated from dnsmasq syslog dns_response events
        tables = {
            row[0] for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).fetchall()
        }
        if "dns_cache" not in tables:
            conn.execute(text("""
                CREATE TABLE dns_cache (
                    id INTEGER PRIMARY KEY,
                    recorded_at DATETIME,
                    domain VARCHAR(255) NOT NULL,
                    resolved_ip VARCHAR(45) NOT NULL,
                    client_ip VARCHAR(45)
                )"""))
            conn.execute(text("CREATE INDEX ix_dns_cache_resolved_ip ON dns_cache (resolved_ip)"))
            conn.execute(text("CREATE INDEX ix_dns_cache_domain ON dns_cache (domain)"))
            conn.execute(text("CREATE INDEX ix_dns_cache_recorded_at ON dns_cache (recorded_at)"))

        # users.token_version — added v1.2 for JWT revocation
        user_cols = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(users)")).fetchall()
        }
        if "token_version" not in user_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0"))

        conn.commit()


def _migrate_ai_tables():
    """Create AI analysis/recommendation tables if they don't exist yet."""
    with engine.connect() as conn:
        existing = {
            row[0] for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            ).fetchall()
        }
        if "ai_analyses" not in existing:
            conn.execute(text("""
                CREATE TABLE ai_analyses (
                    id INTEGER PRIMARY KEY,
                    analyzed_at DATETIME,
                    focus VARCHAR(256),
                    hours_covered INTEGER,
                    log_count INTEGER,
                    threat_level VARCHAR(16),
                    summary TEXT,
                    immediate_actions_json TEXT,
                    findings_json TEXT
                )"""))
        if "ai_recommendations" not in existing:
            conn.execute(text("""
                CREATE TABLE ai_recommendations (
                    id INTEGER PRIMARY KEY,
                    analysis_id INTEGER,
                    title VARCHAR(256),
                    severity VARCHAR(16),
                    detail TEXT,
                    recommendation TEXT,
                    status VARCHAR(32) DEFAULT 'open',
                    user_notes TEXT,
                    created_at DATETIME,
                    updated_at DATETIME
                )"""))
        # Add priority column to existing ai_recommendations table if missing
        try:
            ai_rec_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(ai_recommendations)")).fetchall()]
            if "priority" not in ai_rec_cols:
                conn.execute(text("ALTER TABLE ai_recommendations ADD COLUMN priority VARCHAR(16)"))
        except Exception:
            pass
        if "ai_network_context" not in existing:
            conn.execute(text("""
                CREATE TABLE ai_network_context (
                    id INTEGER PRIMARY KEY,
                    content TEXT DEFAULT '',
                    updated_at DATETIME
                )"""))
            conn.execute(text("INSERT INTO ai_network_context (id, content, updated_at) VALUES (1, '', datetime('now'))"))
        if "ai_context_entries" not in existing:
            conn.execute(text("""
                CREATE TABLE ai_context_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title VARCHAR(256) NOT NULL,
                    category VARCHAR(64) NOT NULL DEFAULT 'custom',
                    content TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at DATETIME,
                    updated_at DATETIME
                )"""))
        if "netflow_records" not in existing:
            conn.execute(text("""
                CREATE TABLE netflow_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at DATETIME,
                    exporter_ip VARCHAR(45),
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol INTEGER,
                    proto_name VARCHAR(16),
                    bytes INTEGER DEFAULT 0,
                    packets INTEGER DEFAULT 0,
                    tcp_flags INTEGER,
                    flow_start DATETIME,
                    flow_end DATETIME,
                    tos INTEGER,
                    src_as INTEGER,
                    dst_as INTEGER
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_netflow_received_at ON netflow_records(received_at)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_netflow_src_ip ON netflow_records(src_ip)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_netflow_dst_ip ON netflow_records(dst_ip)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_netflow_dst_port ON netflow_records(dst_port)"))
        conn.commit()


def _migrate_dpi_tables():
    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "dpi_records" not in existing:
            conn.execute(text("""
                CREATE TABLE dpi_records (
                    id INTEGER PRIMARY KEY,
                    polled_at DATETIME,
                    mac_address VARCHAR(17),
                    src_ip VARCHAR(45),
                    hostname VARCHAR(255),
                    app_name VARCHAR(128),
                    url_category VARCHAR(128),
                    tx_bytes INTEGER DEFAULT 0,
                    rx_bytes INTEGER DEFAULT 0
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dpi_polled_at ON dpi_records(polled_at)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dpi_src_ip ON dpi_records(src_ip)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dpi_mac ON dpi_records(mac_address)"))
            conn.commit()


def _migrate_unifi_change_tables():
    """Create unifi_config_snapshots and unifi_config_changes tables if they don't exist."""
    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "unifi_config_snapshots" not in existing:
            conn.execute(text("""
                CREATE TABLE unifi_config_snapshots (
                    id INTEGER PRIMARY KEY,
                    taken_at DATETIME,
                    config_json TEXT NOT NULL,
                    changes_json TEXT,
                    has_changes BOOLEAN DEFAULT 0
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_unifi_snapshots_taken_at ON unifi_config_snapshots(taken_at)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_unifi_snapshots_has_changes ON unifi_config_snapshots(has_changes)"))
        if "unifi_config_changes" not in existing:
            conn.execute(text("""
                CREATE TABLE unifi_config_changes (
                    id INTEGER PRIMARY KEY,
                    detected_at DATETIME,
                    section VARCHAR(64) NOT NULL,
                    change_type VARCHAR(16) NOT NULL,
                    item_name VARCHAR(256),
                    before_json TEXT,
                    after_json TEXT
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_unifi_changes_detected_at ON unifi_config_changes(detected_at)"))
        conn.commit()


def _migrate_threat_intel_tables():
    """Create threat intel tables if they don't exist yet."""
    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "threat_intel_feeds" not in existing:
            conn.execute(text("""
                CREATE TABLE threat_intel_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(128) NOT NULL UNIQUE,
                    feed_type VARCHAR(32) NOT NULL,
                    config_json TEXT,
                    encrypted_api_key TEXT,
                    poll_interval_minutes INTEGER DEFAULT 60,
                    enabled BOOLEAN DEFAULT 1,
                    last_polled_at DATETIME,
                    last_error TEXT,
                    indicator_count INTEGER DEFAULT 0,
                    created_at DATETIME,
                    updated_at DATETIME
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_intel_feeds_enabled ON threat_intel_feeds(enabled)"))
        if "threat_indicators" not in existing:
            conn.execute(text("""
                CREATE TABLE threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_id INTEGER NOT NULL,
                    indicator_type VARCHAR(32) NOT NULL,
                    value VARCHAR(512) NOT NULL,
                    confidence INTEGER DEFAULT 50,
                    severity VARCHAR(16),
                    tags_json TEXT,
                    source_ref VARCHAR(256),
                    first_seen DATETIME,
                    last_seen DATETIME,
                    expires_at DATETIME,
                    created_at DATETIME,
                    UNIQUE(feed_id, indicator_type, value)
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_indicators_feed_id ON threat_indicators(feed_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_indicators_type ON threat_indicators(indicator_type)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_indicators_value ON threat_indicators(value)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_indicators_type_value ON threat_indicators(indicator_type, value)"))
        if "ioc_matches" not in existing:
            conn.execute(text("""
                CREATE TABLE ioc_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_id INTEGER NOT NULL,
                    entry_id INTEGER,
                    netflow_id INTEGER,
                    matched_field VARCHAR(64) NOT NULL,
                    matched_value VARCHAR(512) NOT NULL,
                    matched_at DATETIME,
                    severity VARCHAR(16) NOT NULL,
                    acknowledged BOOLEAN DEFAULT 0,
                    notified BOOLEAN DEFAULT 0
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_matches_indicator_id ON ioc_matches(indicator_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_matches_entry_id ON ioc_matches(entry_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_matches_matched_at ON ioc_matches(matched_at)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_matches_severity ON ioc_matches(severity)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_matches_acknowledged ON ioc_matches(acknowledged)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_matches_indicator_matched ON ioc_matches(indicator_id, matched_at)"))
        conn.commit()


def _migrate_agent_tables():
    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "custom_agents" not in existing:
            conn.execute(text("""
                CREATE TABLE custom_agents (
                    id INTEGER PRIMARY KEY,
                    key VARCHAR(64) UNIQUE NOT NULL,
                    label VARCHAR(128) NOT NULL,
                    description TEXT,
                    system_prompt TEXT NOT NULL,
                    use_kb_history BOOLEAN DEFAULT 1,
                    schema_type VARCHAR(32) DEFAULT 'auto',
                    created_at DATETIME,
                    updated_at DATETIME
                )
            """))
            conn.commit()


def _migrate_custom_parsers():
    """Create custom_parsers table for AI-registered log source parsers."""
    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "custom_parsers" not in existing:
            conn.execute(text("""
                CREATE TABLE custom_parsers (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(128) UNIQUE NOT NULL,
                    description TEXT DEFAULT '',
                    app_keywords TEXT NOT NULL,
                    patterns TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at DATETIME,
                    created_by VARCHAR(128) DEFAULT 'ai_agent'
                )
            """))
            conn.commit()


def _migrate_secret_key_to_keystore():
    """
    On first run (or after upgrade), move SECRET_KEY from .env into the OS
    keystore (DPAPI on Windows, chmod-600 file on Linux) so the raw key no
    longer lives next to the database it protects.

    Skips silently if already stored or if the keystore is unavailable.
    """
    from keystore import is_stored, store_secret, load_secret
    if is_stored():
        return  # already migrated

    raw = settings.secret_key
    if not raw:
        return

    try:
        store_secret(raw)
        # Verify the round-trip before scrubbing .env
        if load_secret() != raw:
            logger.error("Keystore round-trip verification failed — SECRET_KEY NOT removed from .env")
            return

        # Scrub SECRET_KEY from .env now that it lives in the keystore
        from config import ENV_FILE
        env_path = ENV_FILE
        if env_path.exists():
            text = env_path.read_text(encoding="utf-8")
            import re as _re
            new_text = _re.sub(
                r"^(SECRET_KEY=).+$",
                r"\1(stored-in-os-keystore)",
                text,
                flags=_re.MULTILINE,
            )
            if new_text != text:
                env_path.write_text(new_text, encoding="utf-8")
                logger.info(
                    "SECRET_KEY migrated to OS keystore and removed from %s. "
                    "Raw key no longer stored on disk in plaintext.",
                    env_path,
                )
    except Exception as exc:
        logger.warning(
            "Could not migrate SECRET_KEY to OS keystore: %s — "
            "key remains in .env (install pywin32 on Windows or check /etc permissions on Linux)",
            exc,
        )


def _migrate_investigation_tables():
    """Create Phase 3 investigation tables if they don't exist yet."""
    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "investigations" not in existing:
            conn.execute(text("""
                CREATE TABLE investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trigger_type VARCHAR(32) NOT NULL,
                    trigger_id INTEGER,
                    title VARCHAR(256) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'running',
                    verdict VARCHAR(32),
                    severity VARCHAR(16),
                    summary TEXT,
                    mitre_techniques_json TEXT,
                    entities_json TEXT,
                    created_at DATETIME,
                    completed_at DATETIME,
                    model_used VARCHAR(64)
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_status ON investigations(status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_trigger_id ON investigations(trigger_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_severity ON investigations(severity)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_investigations_created_at ON investigations(created_at)"))
        if "investigation_steps" not in existing:
            conn.execute(text("""
                CREATE TABLE investigation_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    step_number INTEGER NOT NULL,
                    tool_name VARCHAR(64) NOT NULL,
                    tool_input_json TEXT NOT NULL,
                    tool_output_json TEXT,
                    reasoning TEXT,
                    duration_ms INTEGER,
                    created_at DATETIME
                )"""))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_inv_steps_investigation_id ON investigation_steps(investigation_id)"))
        conn.commit()


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_db()
    _migrate_ai_tables()
    _migrate_dpi_tables()
    _migrate_agent_tables()
    _migrate_unifi_change_tables()
    _migrate_custom_parsers()
    _migrate_threat_intel_tables()
    _migrate_investigation_tables()
    _seed_defaults()
    _migrate_secret_key_to_keystore()
    _secure_env_file()


def _seed_defaults():
    """Seed the admin user, retention policy, and any env-configured API keys."""
    from auth import get_password_hash
    from config import _SEEDED_SENTINEL
    db = SessionLocal()
    try:
        # Admin user
        pw = settings.admin_password
        is_real_password = pw and pw not in ("changeme", _SEEDED_SENTINEL, "(seeded)")
        existing_user = db.query(User).filter_by(username=settings.admin_username).first()

        if not existing_user:
            if is_real_password:
                # Legacy path: .env had a real password (upgrade from old install)
                db.add(User(
                    username=settings.admin_username or "admin",
                    hashed_password=get_password_hash(pw),
                    is_active=True,
                    is_admin=True,
                ))
                logger.info("Admin user '%s' created from .env (legacy seed).", settings.admin_username)
            else:
                # New install: no credentials in .env — web setup wizard will create the admin
                logger.info("No admin credentials in .env. First-run setup wizard will configure the admin account.")
        elif is_real_password:
            # .env has a real password and user already exists — update the hash.
            # This handles re-installs where the wizard set a new password.
            existing_user.hashed_password = get_password_hash(pw)
            logger.info("Admin user '%s' password updated from .env.", settings.admin_username)

        # Retention policy
        if not db.query(RetentionPolicy).first():
            db.add(RetentionPolicy(
                retention_days=settings.retention_days,
                max_entries=settings.max_log_entries,
            ))

        # Migrate EXTERNAL_API_KEYS from .env into the DB (hashed), then clear
        for raw_key in settings.get_external_api_keys():
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            if not db.query(ApiKey).filter_by(key_hash=key_hash).first():
                db.add(ApiKey(
                    key_hash=key_hash,
                    label="imported-from-env",
                    read_only=True,
                    is_active=True,
                ))
                logger.info("Imported API key from EXTERNAL_API_KEYS into DB.")

        # Import ANTHROPIC_API_KEY from .env into encrypted DB storage
        _import_setting(db, "anthropic_api_key", settings.anthropic_api_key)

        # Seed configurable service settings (only if not already in DB — never overwrite)
        _seed_setting_if_missing(db, "allowed_syslog_sources", settings.allowed_syslog_sources)
        _seed_setting_if_missing(db, "login_max_attempts", str(settings.login_max_attempts))
        _seed_setting_if_missing(db, "login_lockout_seconds", str(settings.login_lockout_seconds))
        _seed_setting_if_missing(db, "access_token_expire_minutes", str(settings.access_token_expire_minutes))
        _seed_setting_if_missing(db, "ai_analysis_max_logs", str(settings.ai_analysis_max_logs))

        db.commit()
    finally:
        db.close()


def _seed_setting_if_missing(db, key: str, value: str) -> None:
    """Store a setting in DB only if not already present — never overwrites user changes."""
    if not value:
        return
    if db.query(ServiceSetting).filter_by(key=key).first():
        return
    db.add(ServiceSetting(key=key, encrypted_value=encrypt_value(str(value))))


def _import_setting(db, key: str, env_value: str) -> None:
    """Store an env value into ServiceSetting (encrypted) if it's a real value."""
    from config import _SEEDED_SENTINEL
    if not env_value or env_value == _SEEDED_SENTINEL:
        return
    existing = db.query(ServiceSetting).filter_by(key=key).first()
    encrypted = encrypt_value(env_value)
    if existing:
        existing.encrypted_value = encrypted
        existing.updated_at = datetime.now(timezone.utc)
    else:
        db.add(ServiceSetting(key=key, encrypted_value=encrypted))
    logger.info("Imported '%s' from .env into encrypted DB storage.", key)


def get_service_setting(key: str, default: str = "", db: "Session | None" = None) -> str:
    """Read a decrypted setting from the DB. Pass db to reuse a request-scoped session."""
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        row = db.query(ServiceSetting).filter_by(key=key).first()
        if not row:
            return default
        return decrypt_value(row.encrypted_value) or default
    finally:
        if own_session:
            db.close()


def set_service_setting(key: str, value: str, db: "Session | None" = None) -> None:
    """Write an encrypted setting to the DB. Pass db to reuse a request-scoped session."""
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        row = db.query(ServiceSetting).filter_by(key=key).first()
        if row:
            row.encrypted_value = encrypt_value(value)
            row.updated_at = datetime.now(timezone.utc)
        else:
            db.add(ServiceSetting(key=key, encrypted_value=encrypt_value(value)))
        if own_session:
            db.commit()
    finally:
        if own_session:
            db.close()


def write_audit(
    db: "Session",
    username: str,
    action: str,
    detail: str,
    ip_address: str = "",
) -> None:
    """Append an immutable audit log entry. Caller must commit the session."""
    db.add(AuditLog(
        username=username,
        action=action,
        detail=detail,
        ip_address=ip_address,
    ))


def _secure_env_file():
    """
    After seeding, replace plaintext secrets in .env with a sentinel so the
    file is no longer a credential store. Also restricts file permissions.
    """
    from config import ENV_FILE
    env_path = ENV_FILE

    if not env_path.exists():
        return

    # Restrict permissions: owner read/write only (0600)
    try:
        if sys.platform != "win32":
            os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)
        else:
            # Windows: remove Everyone/Users, keep only current user
            import subprocess
            p = str(env_path)
            subprocess.run(["icacls", p, "/inheritance:r"], capture_output=True)
            subprocess.run(["icacls", p, "/grant:r", f"{os.environ.get('USERNAME','Administrator')}:(R,W)"], capture_output=True)
    except Exception as exc:
        logger.warning("Could not restrict .env permissions: %s", exc)

    # Scrub plaintext secrets from the file
    try:
        text = env_path.read_text(encoding="utf-8")
        changed = False

        # Replace ADMIN_PASSWORD if it still has a real value
        from config import _SEEDED_SENTINEL

        def _scrub(content, key):
            pattern = re.compile(rf"^({re.escape(key)}=)(?!{re.escape(_SEEDED_SENTINEL)})(.+)$", re.MULTILINE)
            new = pattern.sub(rf"\1{_SEEDED_SENTINEL}", content)
            return new, new != content

        text, c1 = _scrub(text, "ADMIN_PASSWORD")
        text, c2 = _scrub(text, "EXTERNAL_API_KEYS")
        text, c3 = _scrub(text, "ANTHROPIC_API_KEY")
        changed = c1 or c2 or c3

        if changed:
            env_path.write_text(text, encoding="utf-8")
            logger.info(
                "Plaintext secrets removed from %s. "
                "Manage credentials via the web console going forward.",
                env_path,
            )
    except Exception as exc:
        logger.warning("Could not scrub .env secrets: %s", exc)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- query helpers ----------

FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "security", "ftp", "ntp", "logaudit", "logalert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]

SEVERITY_NAMES = [
    "Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug",
]


_SEARCH_MAX_LEN = 400  # longer to accommodate multi-term queries


def _escape_like(val: str) -> str:
    """Escape SQL LIKE wildcards so user input cannot alter match scope."""
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_search_tokens(raw: str):
    """
    Parse the search string into (must_include, must_exclude, or_groups) token lists.

    Syntax:
      - Words/phrases separated by spaces or commas → all must match (AND)
      - "quoted phrase" → treated as a single term (AND)
      - -term or -"phrase" → must NOT match
      - term1|term2 → either must match (OR group); pipe joins alternatives
      - Mixing: "firewall -denied ssh|vpn" → message must contain "firewall",
        must not contain "denied", and must contain "ssh" OR "vpn"
    """
    import re as _re
    must, must_not, or_groups = [], [], []

    # Tokenise: quoted strings first, then unquoted tokens (splitting on space/comma)
    token_re = _re.compile(r'"[^"]*"|\S+')
    tokens = token_re.findall(raw.strip())

    for tok in tokens:
        negate = tok.startswith('-') and len(tok) > 1
        if negate:
            tok = tok[1:]
        # Strip surrounding quotes
        if tok.startswith('"') and tok.endswith('"') and len(tok) > 1:
            tok = tok[1:-1]
        if not tok:
            continue
        if negate:
            must_not.append(tok)
        elif '|' in tok:
            or_groups.append([p for p in tok.split('|') if p])
        else:
            must.append(tok)

    return must, must_not, or_groups


def _apply_search(q, search: str):
    """Apply multi-term search filter to a SQLAlchemy query on SyslogEntry.message."""
    from sqlalchemy import or_, and_
    raw = search[:_SEARCH_MAX_LEN].strip()
    if not raw:
        return q

    # Fall back to simple ILIKE for single plain terms (no special chars)
    must, must_not, or_groups = _parse_search_tokens(raw)

    for term in must:
        pat = f"%{_escape_like(term)}%"
        q = q.filter(SyslogEntry.message.ilike(pat, escape="\\"))
    for term in must_not:
        pat = f"%{_escape_like(term)}%"
        q = q.filter(~SyslogEntry.message.ilike(pat, escape="\\"))
    for group in or_groups:
        clauses = [SyslogEntry.message.ilike(f"%{_escape_like(t)}%", escape="\\") for t in group]
        if clauses:
            q = q.filter(or_(*clauses))

    return q


def _build_log_query(
    db: Session,
    *,
    log_source_ip: Optional[str] = None,
    severity_max: Optional[int] = None,
    hostname: Optional[str] = None,
    search: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    event_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
):
    q = db.query(SyslogEntry)
    if log_source_ip:
        q = q.filter(SyslogEntry.log_source_ip == log_source_ip)
    if severity_max is not None:
        q = q.filter(SyslogEntry.severity <= severity_max)
    if hostname:
        q = q.filter(SyslogEntry.hostname.ilike(f"%{_escape_like(hostname[:_SEARCH_MAX_LEN])}%", escape="\\"))
    if search:
        q = _apply_search(q, search)
    if since:
        q = q.filter(SyslogEntry.received_at >= since)
    if until:
        q = q.filter(SyslogEntry.received_at <= until)
    if event_type:
        q = q.filter(SyslogEntry.event_type == event_type)
    if src_ip:
        q = q.filter(SyslogEntry.src_ip == src_ip)
    if dst_ip:
        q = q.filter(SyslogEntry.dst_ip == dst_ip)
    if dst_port is not None:
        q = q.filter(SyslogEntry.dst_port == dst_port)
    if protocol:
        q = q.filter(SyslogEntry.protocol.ilike(protocol))
    if action:
        q = q.filter(SyslogEntry.action == action.upper())
    return q


def query_logs(db: Session, *, limit: int = 200, offset: int = 0, kql: Optional[str] = None, **kwargs) -> tuple[list[SyslogEntry], int]:
    q = _build_log_query(db, **kwargs)
    if kql:
        from kql_parser import apply_kql
        q = apply_kql(q, kql)
    total = q.count()
    entries = q.order_by(SyslogEntry.received_at.desc()).offset(offset).limit(limit).all()
    return entries, total


def query_logs_for_export(db: Session, *, max_rows: int = 50_000, kql: Optional[str] = None, **kwargs):
    """Return a query iterator for CSV export — does not load all rows into memory."""
    q = _build_log_query(db, **kwargs)
    if kql:
        from kql_parser import apply_kql
        q = apply_kql(q, kql)
    return q.order_by(SyslogEntry.received_at.desc()).limit(max_rows)


def purge_old_entries(db: Session) -> int:
    policy = db.query(RetentionPolicy).first()
    days = policy.retention_days if policy else settings.retention_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = db.query(SyslogEntry).filter(SyslogEntry.received_at < cutoff).delete()

    # Prune UniFi config snapshots — keep only 7 days; full snapshot JSON can be large
    snap_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    db.query(UnifiConfigSnapshot).filter(UnifiConfigSnapshot.taken_at < snap_cutoff).delete()

    # Prune individual config change records — keep 30 days for audit trail
    change_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    db.query(UnifiConfigChange).filter(UnifiConfigChange.detected_at < change_cutoff).delete()

    # Prune DPI records — keep same window as syslog
    db.query(DpiRecord).filter(DpiRecord.polled_at < cutoff).delete()

    # Prune DNS cache — keep 24 hours (IPs change; stale entries cause wrong enrichment)
    dns_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    db.query(DnsCache).filter(DnsCache.recorded_at < dns_cutoff).delete()

    db.commit()
    return deleted


def get_stats(db: Session) -> dict:
    total = db.query(func.count(SyslogEntry.id)).scalar()
    oldest = db.query(func.min(SyslogEntry.received_at)).scalar()
    newest = db.query(func.max(SyslogEntry.received_at)).scalar()
    by_severity = (
        db.query(SyslogEntry.severity, func.count(SyslogEntry.id))
        .group_by(SyslogEntry.severity)
        .all()
    )
    by_source = (
        db.query(SyslogEntry.log_source_ip, func.count(SyslogEntry.id))
        .group_by(SyslogEntry.log_source_ip)
        .order_by(func.count(SyslogEntry.id).desc())
        .limit(10)
        .all()
    )
    by_action = (
        db.query(SyslogEntry.action, func.count(SyslogEntry.id))
        .filter(SyslogEntry.action.isnot(None))
        .group_by(SyslogEntry.action)
        .all()
    )
    by_event_type = (
        db.query(SyslogEntry.event_type, func.count(SyslogEntry.id))
        .filter(SyslogEntry.event_type.isnot(None))
        .group_by(SyslogEntry.event_type)
        .order_by(func.count(SyslogEntry.id).desc())
        .limit(8)
        .all()
    )
    return {
        "total_entries": total,
        "oldest_entry": oldest.isoformat() if oldest else None,
        "newest_entry": newest.isoformat() if newest else None,
        "by_severity": [
            {"severity": s, "name": SEVERITY_NAMES[s] if s < 8 else str(s), "count": c}
            for s, c in by_severity
        ],
        "top_sources": [{"ip": ip, "count": c} for ip, c in by_source],
        "by_action": [{"action": a, "count": c} for a, c in by_action],
        "by_event_type": [{"event_type": et, "count": c} for et, c in by_event_type],
    }
