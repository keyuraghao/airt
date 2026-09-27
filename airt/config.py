"""Central configuration. All values can be overridden with AIRT_* environment variables or a .env file."""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AIRT_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- service -----------------------------------------------------------
    app_name: str = "Airt"
    environment: str = Field(default="development", description="development | staging | production")
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 1
    base_dir: Path = Field(default_factory=lambda: Path.cwd())
    data_dir: Path = Field(default_factory=lambda: Path.cwd() / "data")
    log_dir: Path = Field(default_factory=lambda: Path.cwd() / "logs")
    log_level: str = "INFO"
    log_json_console: bool = False  # JSON lines on stdout (recommended in production / containers)

    # --- persistence -------------------------------------------------------
    database_url: str = Field(default="sqlite+aiosqlite:///./data/airt.db")
    db_echo: bool = False

    # --- security ----------------------------------------------------------
    secret_key: str = Field(default="change-me-in-production-please-0123456789", min_length=16)
    encryption_key: str | None = Field(
        default=None, description="Fernet key for upstream credentials; derived from secret_key when unset"
    )
    admin_username: str = "admin"
    admin_password: str = "admin"  # forced rotation is recommended; a warning is logged when left at default
    admin_api_token: str | None = Field(
        default=None, description="Static bearer token for programmatic reviewer access"
    )
    session_max_age_seconds: int = 12 * 3600
    cookie_secure: bool = False

    # --- gateway behaviour ------------------------------------------------
    approval_timeout_seconds: int = Field(
        default=300, description="How long a synchronous request waits for a human decision"
    )
    hold_poll_interval_seconds: float = 1.0
    max_request_body_bytes: int = 4 * 1024 * 1024
    max_stored_response_bytes: int = 512 * 1024
    upstream_timeout_seconds: float = 120.0
    upstream_connect_timeout_seconds: float = 10.0
    default_auto_deny_risk_threshold: int = 90
    default_auto_approve_risk_threshold: int = 0  # 0 = never auto-approve unless agent policy says so
    ticket_retention_days: int = 90
    require_approval_for_redteam_probes: bool = True

    # --- notifications ----------------------------------------------------
    notify_webhook_urls: list[str] = Field(
        default_factory=list,
        description="Webhook URLs (Slack incoming webhooks or generic JSON endpoints) notified on ticket events",
    )
    notify_events: list[str] = Field(
        default_factory=lambda: ["created", "expired", "failed"],
        description="Ticket events that trigger notifications",
    )
    notify_min_risk: int = Field(default=0, description="Only notify for tickets at or above this risk score")
    public_url: str = Field(
        default="", description="Externally reachable base URL used to build dashboard links in notifications"
    )

    # --- analysis ---------------------------------------------------------
    enable_llm_judge: bool = False
    judge_provider: str = "openai"  # openai | anthropic
    judge_base_url: str | None = None
    judge_api_key: str | None = None
    judge_model: str = "gpt-4o-mini"

    # --- red team ---------------------------------------------------------
    redteam_concurrency: int = 4
    redteam_probe_timeout_seconds: float = 90.0

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @property
    def fernet_key(self) -> bytes:
        if self.encryption_key:
            return self.encryption_key.encode()
        digest = hashlib.sha256(("airt-fernet:" + self.secret_key).encode()).digest()
        return base64.urlsafe_b64encode(digest)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "agents").mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s


def reset_settings_cache() -> None:
    get_settings.cache_clear()
