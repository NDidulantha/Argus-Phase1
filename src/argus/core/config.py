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

    # Auth. Dev defaults only - MUST be overridden via environment/secret
    # manager anywhere beyond the local machine.
    jwt_secret: str = "dev-only-insecure-jwt-secret-0123456789abcdef"  # >=32 bytes for HS256
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    admin_api_key: str = "dev-admin-key-change-me"

    # Enrichment providers: empty key = provider disabled.
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    # abuse.ch unified Auth-Key (free): ThreatFox, MalwareBazaar, URLhaus
    abuse_ch_auth_key: str = ""
    cti_cache_ttl_hours: int = 24
    enrichment_cache_ttl_hours: int = 24

    # Embeddings for RAG over evidence objects.
    embedding_provider: str = "hashing-v1"

    # Auto-correlation after ingest: debounced per tenant so a burst of
    # ingest calls triggers one correlation pass once the tenant goes quiet.
    auto_correlate_enabled: bool = True
    auto_correlate_debounce_seconds: float = 10.0
    auto_correlate_window_minutes: int = 30

    # Reasoning (LLM). Ollama is the local, private, free default; Anthropic
    # is an optional drop-in used only when an API key is configured.
    reasoning_provider: str = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor so the environment is parsed exactly once."""
    return Settings()
