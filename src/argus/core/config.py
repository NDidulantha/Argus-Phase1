"""Application configuration.

All runtime configuration comes from environment variables (12-factor app).
Nothing is hardcoded; defaults here are for local development only.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARGUS_",
        env_file=".env",
        extra="ignore",
    )

    env: str = "dev"
    log_level: str = "INFO"

    # Local dev default only. In any shared/production environment this MUST
    # be injected via environment variable / secret manager, never committed.
    database_url: str = "postgresql+asyncpg://argus:argus@localhost:5432/argus"
    db_ready_timeout_seconds: float = 2.0


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor so the environment is parsed exactly once."""
    return Settings()
