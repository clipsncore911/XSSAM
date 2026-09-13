import yaml
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional

class ScopeConfig(BaseModel):
    allowed_domains: List[str] = []
    subdomain_scope: bool = True
    scope_file: Optional[str] = None

class CrawlerConfig(BaseModel):
    max_depth: int = 3
    max_urls: int = 1000
    max_requests: int = 5000

class ScannerConfig(BaseModel):
    reflected: bool = True
    stored: bool = True
    dom: bool = True
    comprehensive_payloads: bool = True

class PerformanceConfig(BaseModel):
    threads: int = 10
    delay: float = 0.2
    timeout: int = 15

class BrowserConfig(BaseModel):
    enabled: bool = True
    headless: bool = True

class ReportingConfig(BaseModel):
    html: bool = True
    json: bool = True
    txt: bool = True

class XSSAMSettings(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

def load_config(config_path: Optional[str] = None) -> XSSAMSettings:
    default_path = Path("config/default.yaml")
    path = Path(config_path) if config_path else default_path

    if not path.exists():
        return XSSAMSettings()

    with open(path, "r") as f:
        data = yaml.safe_load(f)

    return XSSAMSettings(**data)

# Singleton instance
settings = load_config()
