import secrets
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field

BASE_DIR = Path(__file__).parent
ENV_FILE = BASE_DIR / ".env"

# Sentinel written to .env after first-run seeding — never treated as a real value
_SEEDED_SENTINEL = "(seeded-manage-via-web-console)"


class Settings(BaseSettings):
    # Service identity
    service_name: str = "SyslogRetentionService"
    service_display_name: str = "Syslog Retention & SIEM Service"

    # Syslog listener
    syslog_udp_host: str = "0.0.0.0"
    syslog_udp_port: int = 514
    syslog_tcp_host: str = "0.0.0.0"
    syslog_tcp_port: int = 514

    # Web / API server
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_base_url: str = "http://localhost:8080"

    # Database
    db_path: str = str(BASE_DIR / "data" / "syslog.db")

    # Security
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Admin credentials — used only on first run to seed the DB, then scrubbed
    admin_username: str = "admin"
    admin_password: str = "changeme"

    # Log retention
    retention_days: int = 90
    max_log_entries: int = 5_000_000

    # Claude AI
    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-4-6"
    ai_analysis_max_logs: int = 500

    # Static API keys — imported to DB on first run, then scrubbed from .env
    external_api_keys: str = ""

    model_config = {
        "env_file": str(ENV_FILE),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    def is_seeded(self) -> bool:
        """True when the password has already been moved to the DB."""
        return self.admin_password in ("", _SEEDED_SENTINEL, "changeme")

    def get_external_api_keys(self) -> list[str]:
        if not self.external_api_keys or self.external_api_keys == _SEEDED_SENTINEL:
            return []
        return [k.strip() for k in self.external_api_keys.split(",") if k.strip()]


settings = Settings()
