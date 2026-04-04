from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CyberShield AI Backend"
    environment: str = "development"
    debug: bool = True
    host: str = "0.0.0.0"
    port: int = 8000
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    database_url: str = "sqlite:///./scan_logs.db"
    openai_api_key: str = ""
    gemini_api_key: str = ""
    grok_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    virus_total_api_key: str = ""
    falcon_sandbox_api_key: str = ""
    openai_model: str = "gpt-4.1-mini"
    gemini_model: str = "gemini-2.5-flash"
    grok_model: str = "grok-3-mini"
    falcon_sandbox_base_url: str = "https://hybrid-analysis.com/api/v2"
    threat_intel_timeout_seconds: float = 12.0
    gmail_pubsub_topic: str = ""
    gmail_watch_verification_token: str = ""
    public_backend_url: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("debug", mode="before")
    @classmethod
    def normalize_debug(cls, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "debug", "development"}:
                return True
            if normalized in {"0", "false", "no", "off", "release", "prod", "production"}:
                return False
        return bool(value)


@lru_cache
def get_settings() -> Settings:
    return Settings()
