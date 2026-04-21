"""Runtime configuration sourced from environment / .env.local.

clean-skill reads config through pydantic-settings so values can be overridden
in tests without monkeypatching os.environ.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed runtime settings.

    All env vars are prefixed with ``CLEAN_SKILL_`` except a few well-known
    provider keys (ANTHROPIC_API_KEY, OPENAI_API_KEY).
    """

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    judge_model: str = Field(default="claude-sonnet-4-5", alias="CLEAN_SKILL_JUDGE_MODEL")

    db_url: str = Field(
        default="sqlite:///clean_skill.db",
        alias="CLEAN_SKILL_DB_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="CLEAN_SKILL_REDIS_URL")

    sandbox_image: str = Field(
        default="cleanskill/sandbox:latest", alias="CLEAN_SKILL_SANDBOX_IMAGE"
    )
    sandbox_runtime: str = Field(default="runsc", alias="CLEAN_SKILL_SANDBOX_RUNTIME")
    sandbox_timeout_s: int = Field(default=30, alias="CLEAN_SKILL_SANDBOX_TIMEOUT_S")
    sandbox_memory_mb: int = Field(default=512, alias="CLEAN_SKILL_SANDBOX_MEMORY_MB")
    sandbox_cpu_quota: float = Field(default=0.5, alias="CLEAN_SKILL_SANDBOX_CPU_QUOTA")

    rules_dir: Path = Field(default=Path("rules"), alias="CLEAN_SKILL_RULES_DIR")

    api_host: str = Field(default="0.0.0.0", alias="CLEAN_SKILL_API_HOST")  # noqa: S104
    api_port: int = Field(default=8080, alias="CLEAN_SKILL_API_PORT")
    api_token: str | None = Field(default=None, alias="CLEAN_SKILL_API_TOKEN")

    # --- Background pipeline ---------------------------------------------
    # Rescan window in days: the job skips a pipeline run when the same
    # bundle hash has been scanned more recently than this. 7d is a
    # compromise between catching fast-moving threats and thrashing the
    # worker pool on static community skills.
    rescan_days: int = Field(default=7, alias="CLEAN_SKILL_RESCAN_DAYS")
    # Crawl interval for the scheduler's recurring tick. Default 6h keeps
    # registry load polite while catching newly-published skills before
    # they accumulate install counts.
    crawl_interval_hours: int = Field(default=6, alias="CLEAN_SKILL_CRAWL_INTERVAL_HOURS")
    # Whether dynamic analysis is enabled in the background pipeline.
    # Set to false on hosts without Docker (static-only CI, edge deploys).
    dynamic_enabled: bool = Field(default=True, alias="CLEAN_SKILL_DYNAMIC_ENABLED")


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a lazily-cached Settings singleton.

    Tests can monkeypatch ``_settings`` directly to override configuration.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
