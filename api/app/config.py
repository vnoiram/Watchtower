from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(default="postgresql+psycopg://watchtower:watchtower@localhost:5432/watchtower")
    api_token: str = Field(default="change-me")
    api_default_role: str = Field(default="admin")
    minio_endpoint: str = Field(default="http://localhost:9000")
    minio_access_key: str = Field(default="watchtower")
    minio_secret_key: str = Field(default="watchtower-secret")
    minio_bucket: str = Field(default="maintenance-artifacts")
    github_app_id: str | None = None
    github_private_key: str | None = None
    github_token: str | None = None
    github_webhook_secret: str | None = None
    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    worker_poll_interval_seconds: int = 5
    worker_job_timeout_seconds: int = 1800
    scan_scheduler_interval_seconds: int = 86400
    scan_scheduler_stale_after_hours: int = 24
    scan_scheduler_limit: int | None = None

    @field_validator("scan_scheduler_limit", mode="before")
    @classmethod
    def empty_scan_scheduler_limit_is_none(cls, value: object) -> object:
        if value == "":
            return None
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
