from __future__ import annotations

import json
import logging
import logging.config
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CYBERSHIELD"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite+aiosqlite:///./phishguard.db"
    google_safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    phishtank_app_key: str = ""
    falcon_sandbox_api_key: str = ""
    falcon_sandbox_base_url: str = "https://hybrid-analysis.com/api/v2"
    falcon_sandbox_environment_id: int = 160
    falcon_sandbox_timeout_seconds: int = 20
    falcon_sandbox_poll_attempts: int = 2
    falcon_sandbox_poll_interval_seconds: float = 2.0
    falcon_sandbox_network_settings: str = "default"
    falcon_sandbox_action_script: str = "default"
    groq_api_key: str = ""
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "openai/gpt-oss-20b"
    groq_timeout_seconds: int = 20
    groq_max_input_chars: int = 3000
    api_secret_key: str = "change-me"
    redis_url: str = "redis://localhost:6379"
    log_level: str = "INFO"
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost", "http://127.0.0.1"]
    )
    cors_origin_regex: str = (
        r"^(chrome-extension://.*|moz-extension://.*|http://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?)$"
    )
    rate_limit_per_minute: str = "60/minute"
    request_timeout_seconds: int = 5
    google_safe_browsing_cache_ttl_seconds: int = 3600
    user_agent: str = "CYBERSHIELD/1.0"
    max_attachment_bytes: int = 10 * 1024 * 1024
    max_attachment_count: int = 5
    max_attachment_urls_to_scan: int = 10

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any) -> list[str]:
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                try:
                    decoded = json.loads(stripped)
                    if isinstance(decoded, list):
                        return [str(item).strip() for item in decoded if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [item.strip() for item in value.split(",") if item.strip()]
        return ["http://localhost", "http://127.0.0.1"]


def get_settings() -> Settings:
    return Settings()


def configure_logging(level: str) -> None:
    normalized_level = level.upper()
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "json": {
                    "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                    "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s",
                }
            },
            "handlers": {
                "default": {
                    "class": "logging.StreamHandler",
                    "formatter": "json",
                    "level": normalized_level,
                }
            },
            "root": {
                "handlers": ["default"],
                "level": normalized_level,
            },
        }
    )


def get_client_ip_from_request(request: Any) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
