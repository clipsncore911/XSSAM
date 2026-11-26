from __future__ import annotations

import os
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ConfigError(ValueError):
    """Raised when a configuration file cannot be loaded or validated."""


class SettingsModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
    )


class ScopeConfig(SettingsModel):
    allowed_domains: list[str] = Field(default_factory=list)
    subdomain_scope: bool = False
    scope_file: str | None = None


class CrawlerConfig(SettingsModel):
    max_depth: int = Field(default=2, ge=0, le=20)
    max_urls: int = Field(default=100, ge=1, le=10_000)
    max_requests: int = Field(default=500, ge=0, le=1_000_000)


class ScannerConfig(SettingsModel):
    reflected: bool = True
    stored: bool = False
    dom: bool = False
    comprehensive_payloads: bool = True
    max_payloads_per_parameter: int = Field(default=12, ge=1, le=100)


class PerformanceConfig(SettingsModel):
    threads: int = Field(default=5, ge=1, le=200)
    delay: float = Field(default=0.1, ge=0, le=60)
    timeout: float = Field(default=10.0, gt=0, le=300)


class BrowserConfig(SettingsModel):
    enabled: bool = False
    headless: bool = True
    navigation_timeout: float = Field(default=15.0, gt=0, le=120)
    settle_time: float = Field(default=0.5, ge=0, le=10)


class ReportingConfig(SettingsModel):
    html: bool = True
    # ``json`` is a nice YAML key but shadows BaseModel.json in Pydantic v2.
    json_report: bool = Field(default=True, alias="json")
    txt: bool = True


class XSSAMSettings(SettingsModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


def _settings_from_path(path: Path) -> XSSAMSettings:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration file {path}: {exc}") from exc

    try:
        data: Any = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"Invalid configuration in {path}: the top level must be a mapping")

    try:
        return XSSAMSettings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid configuration in {path}:\n{exc}") from exc


def _packaged_settings() -> XSSAMSettings:
    resource = resources.files("xssam").joinpath("defaults", "default.yaml")
    with resources.as_file(resource) as path:
        return _settings_from_path(Path(path))


def load_config(
    config_path: str | os.PathLike[str] | None = None,
    *,
    cwd_fallback: bool = True,
) -> XSSAMSettings:
    """Load settings without depending on the process working directory.

    Precedence: explicit path, ``XSSAM_CONFIG``, ``./config/default.yaml``
    when running from the repository, then the copy bundled inside the package.
    Set ``cwd_fallback=False`` to always use the packaged defaults.
    """
    if config_path is not None:
        path = Path(config_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"Configuration file not found: {path}")
        return _settings_from_path(path)

    env_path = os.getenv("XSSAM_CONFIG")
    if env_path:
        return load_config(env_path, cwd_fallback=False)

    if cwd_fallback:
        local_path = Path.cwd() / "config" / "default.yaml"
        if local_path.is_file():
            return _settings_from_path(local_path)

    return _packaged_settings()


# Kept for backwards compatibility with code importing ``settings`` directly.
# The CLI loads its own instance so command-line overrides never mutate a global.
settings = load_config(cwd_fallback=False)
