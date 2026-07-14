from functools import lru_cache

from pydantic import Field
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
    github_webhook_secret: str | None = None
    slack_webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    worker_poll_interval_seconds: int = 5
    worker_job_timeout_seconds: int = 1800


@lru_cache
def get_settings() -> Settings:
    return Settings()

