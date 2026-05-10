import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Index, Integer, String, Text,
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
    ("rule_name",     "VARCHAR(255)"),
    ("extra_json",    "TEXT"),
]


Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{settings.db_path}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class SyslogEntry(Base):
    __tablename__ = "syslog_entries"

    id = Column(Integer, primary_key=True, index=True)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(45), index=True)
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
    rule_name     = Column(String(255), nullable=True)
    extra_json    = Column(Text,        nullable=True)   # JSON blob for leftover fields

    __table_args__ = (
        Index("ix_entries_received_severity", "received_at", "severity"),
        Index("ix_entries_source_received", "source_ip", "received_at"),
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


def _migrate_db():
    """Add any missing normalized columns to an existing database (safe to re-run)."""
    with engine.connect() as conn:
        existing = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(syslog_entries)")).fetchall()
        }
        for col_name, col_type in _NORMALIZED_COLUMNS:
            if col_name not in existing:
                conn.execute(text(f"ALTER TABLE syslog_entries ADD COLUMN {col_name} {col_type}"))
        conn.commit()


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_db()
    _seed_defaults()


def _seed_defaults():
    from auth import get_password_hash
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(username=settings.admin_username).first():
            db.add(User(
                username=settings.admin_username,
                hashed_password=get_password_hash(settings.admin_password),
                is_active=True,
                is_admin=True,
            ))
        if not db.query(RetentionPolicy).first():
            db.add(RetentionPolicy(
                retention_days=settings.retention_days,
                max_entries=settings.max_log_entries,
            ))
        db.commit()
    finally:
        db.close()


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


def query_logs(
    db: Session,
    *,
    source_ip: Optional[str] = None,
    severity_max: Optional[int] = None,
    hostname: Optional[str] = None,
    search: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    # normalized filters
    event_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[SyslogEntry], int]:
    q = db.query(SyslogEntry)
    if source_ip:
        q = q.filter(SyslogEntry.source_ip == source_ip)
    if severity_max is not None:
        q = q.filter(SyslogEntry.severity <= severity_max)
    if hostname:
        q = q.filter(SyslogEntry.hostname.ilike(f"%{hostname}%"))
    if search:
        q = q.filter(SyslogEntry.message.ilike(f"%{search}%"))
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
    total = q.count()
    entries = q.order_by(SyslogEntry.received_at.desc()).offset(offset).limit(limit).all()
    return entries, total


def purge_old_entries(db: Session) -> int:
    policy = db.query(RetentionPolicy).first()
    days = policy.retention_days if policy else settings.retention_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = db.query(SyslogEntry).filter(SyslogEntry.received_at < cutoff).delete()
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
        db.query(SyslogEntry.source_ip, func.count(SyslogEntry.id))
        .group_by(SyslogEntry.source_ip)
        .order_by(func.count(SyslogEntry.id).desc())
        .limit(10)
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
    }
