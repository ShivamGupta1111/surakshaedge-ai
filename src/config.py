"""Environment-driven configuration with safe localhost defaults."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and `.env`."""

    model_config = SettingsConfigDict(
        env_prefix="SURAKSHAEDGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "test", "production"] = "development"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    database_path: Path = PROJECT_ROOT / "data" / "surakshaedge.sqlite3"
    model_dir: Path = PROJECT_ROOT / "models"
    data_dir: Path = PROJECT_ROOT / "data"
    log_level: str = "INFO"
    offline_mode: bool = True
    metrics_enabled: bool = True
    lazy_load_models: bool = True
    memory_safe_mode: bool = True

    max_message_length: int = Field(default=4000, ge=32, le=50_000)
    max_url_length: int = Field(default=2048, ge=16, le=16_384)
    max_batch_size: int = Field(default=25, ge=1, le=100)
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)

    retention_days: int = Field(default=30, ge=0, le=3650)

    auth_enabled: bool = False
    api_key_sha256: str = ""

    cors_origins: str = ""

    advisor_backend: Literal["local_template", "executorch_llama"] = "local_template"
    executorch_model_path: str = ""
    advisor_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    store_raw_content: bool = False
    allow_private_url_analysis: bool = False

    risk_weight_sms: float = 0.30
    risk_weight_url: float = 0.30
    risk_weight_network: float = 0.25
    risk_weight_malware: float = 0.15
    risk_low_max: float = 0.35
    risk_medium_max: float = 0.60
    risk_high_max: float = 0.85
    weak_signal_cap: float = 0.59
    single_weak_evidence_cap: float = 0.84

    @field_validator("database_path", "model_dir", "data_dir", mode="before")
    @classmethod
    def _resolve_path(cls, value: str | Path) -> Path:
        path = Path(value)
        if not path.is_absolute():
            path = (PROJECT_ROOT / path).resolve()
        return path

    @property
    def cors_origin_list(self) -> list[str]:
        if not self.cors_origins.strip():
            return []
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings


def reset_settings_cache() -> None:
    get_settings.cache_clear()
