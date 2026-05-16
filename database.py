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
    severity    = Column(String(16))
    detail      = Column(Text)
    recommendation = Column(Text)
    # open | implemented | working | investigating | dismissed
    status      = Column(String(32), default="open", nullable=False)
    user_notes  = Column(Text)
    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AINetworkContext(Base):
    """User-maintained notes about the network, included in every analysis."""
    __tablename__ = "ai_network_context"

    id         = Column(Integer, primary_key=True)
    content    = Column(Text, default="")
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


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
        if "ai_network_context" not in existing:
            conn.execute(text("""
                CREATE TABLE ai_network_context (
                    id INTEGER PRIMARY KEY,
                    content TEXT DEFAULT '',
                    updated_at DATETIME
                )"""))
            conn.execute(text("INSERT INTO ai_network_context (id, content, updated_at) VALUES (1, '', datetime('now'))"))
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


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_db()
    _migrate_ai_tables()
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


_SEARCH_MAX_LEN = 200  # prevent expensive scans on huge search strings


def _escape_like(val: str) -> str:
    """Escape SQL LIKE wildcards so user input cannot alter match scope."""
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _build_log_query(
    db: Session,
    *,
    source_ip: Optional[str] = None,
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
    if source_ip:
        q = q.filter(SyslogEntry.source_ip == source_ip)
    if severity_max is not None:
        q = q.filter(SyslogEntry.severity <= severity_max)
    if hostname:
        q = q.filter(SyslogEntry.hostname.ilike(f"%{_escape_like(hostname[:_SEARCH_MAX_LEN])}%", escape="\\"))
    if search:
        q = q.filter(SyslogEntry.message.ilike(f"%{_escape_like(search[:_SEARCH_MAX_LEN])}%", escape="\\"))
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


def query_logs(db: Session, *, limit: int = 200, offset: int = 0, **kwargs) -> tuple[list[SyslogEntry], int]:
    q = _build_log_query(db, **kwargs)
    total = q.count()
    entries = q.order_by(SyslogEntry.received_at.desc()).offset(offset).limit(limit).all()
    return entries, total


def query_logs_for_export(db: Session, *, max_rows: int = 50_000, **kwargs):
    """Return a query iterator for CSV export — does not load all rows into memory."""
    q = _build_log_query(db, **kwargs)
    return q.order_by(SyslogEntry.received_at.desc()).limit(max_rows)


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
