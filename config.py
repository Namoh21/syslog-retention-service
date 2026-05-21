import secrets
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field

BASE_DIR = Path(__file__).parent
ENV_FILE = BASE_DIR / ".env"

_SEEDED_SENTINEL = "(seeded-manage-via-web-console)"

PASSWORD_MIN_LENGTH = 8


class Settings(BaseSettings):
    service_name: str = "SyslogRetentionService"
    service_display_name: str = "Syslog Retention & SIEM Service"

    # Syslog listener
    syslog_udp_host: str = "0.0.0.0"
    syslog_udp_port: int = 514
    syslog_tcp_host: str = "0.0.0.0"
    syslog_tcp_port: int = 6514  # non-privileged default; UDM supports custom ports

    # Comma-separated CIDRs allowed to send syslog (empty = allow all)
    # Example: "192.168.1.0/24,10.0.0.0/8"
    allowed_syslog_sources: str = ""

    # NetFlow collector
    netflow_enabled: bool = True
    netflow_host: str = "0.0.0.0"
    netflow_port: int = 2055   # standard NetFlow / IPFIX port

    # Web / API server
    api_host: str = "0.0.0.0"
    api_port: int = 8080

    # Comma-separated allowed CORS origins for the REST API
    # Default: same-origin only (browser direct). Add http://<pi-ip>:8080 if needed.
    cors_origins: str = ""

    # Database
    db_path: str = str(BASE_DIR / "data" / "syslog.db")

    # Security
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480  # 8 hours — avoids hourly logouts

    # Admin credentials — used only on first run to seed the DB, then scrubbed
    admin_username: str = "admin"
    admin_password: str = "changeme"

    # Log retention
    retention_days: int = 90
    max_log_entries: int = 5_000_000

    # Claude AI
    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-4-6"
    ai_analysis_max_logs: int = 200

    # Login rate limiting
    login_max_attempts: int = 10
    login_lockout_seconds: int = 300  # 5 minutes

    # Static API keys — imported to DB on first run, then scrubbed from .env
    external_api_keys: str = ""

    model_config = {
        "env_file": str(ENV_FILE),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    def is_seeded(self) -> bool:
        return self.admin_password in ("", _SEEDED_SENTINEL, "changeme")

    def get_external_api_keys(self) -> list[str]:
        if not self.external_api_keys or self.external_api_keys == _SEEDED_SENTINEL:
            return []
        return [k.strip() for k in self.external_api_keys.split(",") if k.strip()]

    def get_cors_origins(self) -> list[str]:
        """Returns allowed CORS origins. Always includes localhost variants."""
        base = [
            f"http://localhost:{self.api_port}",
            f"http://127.0.0.1:{self.api_port}",
        ]
        if self.cors_origins:
            extra = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
            base.extend(extra)
        return base

    def get_allowed_syslog_sources(self) -> list[str]:
        if not self.allowed_syslog_sources:
            return []
        return [s.strip() for s in self.allowed_syslog_sources.split(",") if s.strip()]


settings = Settings()


def _resolve_secret_key() -> str:
    """Return the effective SECRET_KEY: OS keystore > .env > generated fallback."""
    try:
        from keystore import load_secret
        ks = load_secret()
        if ks:
            return ks
    except Exception:
        pass
    return settings.secret_key


# All crypto that needs the root secret should use this, not settings.secret_key
EFFECTIVE_SECRET_KEY: str = _resolve_secret_key()
