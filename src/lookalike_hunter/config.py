"""Centralised configuration: YAML file, overridable by LH_* environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, SecretStr, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

DEFAULT_CONFIG_PATH = Path("configs/default.yaml")


class BrandConfig(BaseModel):
    name: str
    tokens: list[str]
    official_domains: list[str]
    negative_tokens: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _lowercase(self) -> BrandConfig:
        self.tokens = [t.lower() for t in self.tokens]
        self.official_domains = [d.lower() for d in self.official_domains]
        self.negative_tokens = [t.lower() for t in self.negative_tokens]
        return self


class CTConfig(BaseModel):
    source: Literal["certstream", "replay"] = "certstream"
    certstream_url: str = "ws://localhost:8080/"
    replay_path: Path | None = None
    flush_interval_s: float = 5.0
    flush_max_rows: int = 500
    reconnect_max_backoff_s: float = 60.0


class ScoringWeights(BaseModel):
    known_variant: float = 1.0
    typo_similarity: float = 0.9
    token_in_registered_label: float = 0.6
    token_in_subdomain: float = 0.5
    homoglyph_bonus: float = 0.1
    keyword_bonus: float = 0.1
    max_keyword_hits: int = 2
    free_dv_bonus: float = 0.05


class ScoringConfig(BaseModel):
    alert_threshold: float = 0.7
    store_floor: float = 0.4
    min_typo_similarity: float = 0.8
    # One edit on a short token collides with too much real namespace ("app14" vs
    # "apple", "xcloud" vs "icloud"); short tokens rely on exact dnstwist Variants.
    min_typo_token_len: int = 7
    # Tokens shorter than this must match a whole label part, never a substring.
    min_substring_token_len: int = 5
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    sensitive_keywords: list[str] = Field(default_factory=list)
    free_dv_issuers: list[str] = Field(default_factory=list)


class VariantsConfig(BaseModel):
    swap_tlds: list[str] = Field(default_factory=list)


class CaptureConfig(BaseModel):
    """Passive visit of a suspicious site. Every default here is a safety decision."""

    output_dir: Path = Path("data/captures")
    timeout_s: float = 15.0
    # Time to let client-side phishing kits render after the network settles.
    settle_ms: int = 1500
    viewport_width: int = 1280
    viewport_height: int = 800
    full_page_screenshot: bool = True
    max_html_bytes: int = 2_000_000
    # Suspicious sites routinely have broken or self-signed certificates; refusing
    # them would hide exactly what we want to look at. We never send data there.
    ignore_https_errors: bool = True
    # A redirect must not be able to reach the LAN, the router or cloud metadata.
    block_private_networks: bool = True
    user_agent: str | None = None
    max_per_run: int = 20
    # Re-capture a domain only after this many hours.
    recapture_after_h: float = 24.0


class ClassifyConfig(BaseModel):
    backend: Literal["stub", "mistral", "ollama"] = "stub"
    model: str = "pixtral-12b-2409"
    api_base: str = "https://api.mistral.ai/v1"
    ollama_base: str = "http://localhost:11434"
    timeout_s: float = 90.0
    max_retries: int = 3
    max_html_chars: int = 4000
    max_per_run: int = 20


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LH_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Secret: environment or .env only, never the YAML config (which is committed).
    mistral_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("MISTRAL_API_KEY", "LH_MISTRAL_API_KEY")
    )
    db_path: Path = Path("data/lookalike.duckdb")
    log_level: str = "INFO"
    log_json: bool = True
    ct: CTConfig = Field(default_factory=CTConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    variants: VariantsConfig = Field(default_factory=VariantsConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    classify: ClassifyConfig = Field(default_factory=ClassifyConfig)
    brands: list[BrandConfig] = Field(default_factory=list)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        yaml_path = Path(os.environ.get("LH_CONFIG", DEFAULT_CONFIG_PATH))
        return (
            init_settings,
            env_settings,
            dotenv_settings,  # .env holds secrets such as MISTRAL_API_KEY
            YamlConfigSettingsSource(settings_cls, yaml_file=yaml_path),
        )


def load_settings(config_path: Path | None = None) -> Settings:
    if config_path is not None:
        os.environ["LH_CONFIG"] = str(config_path)
    return Settings()
