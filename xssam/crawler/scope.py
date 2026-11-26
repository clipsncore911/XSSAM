from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel

from xssam.config import XSSAMSettings, load_config
from xssam.crawler.url_normalizer import default_port, effective_port, normalize_url
from xssam.logging import ScanLogger


@dataclass(frozen=True)
class ScopeEntry:
    host: str
    port: int | None = None
    allow_subdomains: bool = False


class ScopeValidator:
    """Restrict crawling to the target origin and any explicit allowlist.

    An empty allowlist used to mean "allow the whole internet". The default is
    now the initial target's host and port; ``--scope`` can extend it.
    """

    def __init__(
        self,
        start_url: str | Iterable[str] | None = None,
        config: XSSAMSettings | str | None = None,
        *,
        allowed_domains: Iterable[str] | None = None,
        scope_file: str | None = None,
        logger: ScanLogger | None = None,
    ) -> None:
        # Compatibility with the old ScopeValidator(allowed_domains, scope_file)
        # positional signature.
        if start_url is not None and not isinstance(start_url, str):
            allowed_domains = start_url
            start_url = None
        if isinstance(config, str):
            scope_file = config
            config = None
        elif config is not None and not isinstance(config, BaseModel):
            raise TypeError("config must be an XSSAMSettings instance")

        self.config = config or load_config(cwd_fallback=False)
        self.logger = logger or ScanLogger(quiet=True)
        self.base_url = normalize_url(start_url) if start_url else None
        self.entries: list[ScopeEntry] = []
        self._legacy_open_scope = False

        if self.base_url:
            parts = urlsplit(self.base_url)
            host = (parts.hostname or "").rstrip(".").lower()
            self.entries.append(
                ScopeEntry(
                    host=host,
                    port=effective_port(parts),
                    allow_subdomains=self.config.scope.subdomain_scope,
                )
            )

        entries = list(self.config.scope.allowed_domains)
        if allowed_domains:
            entries.extend(str(item) for item in allowed_domains)
        for entry in entries:
            parsed = self._parse_entry(entry)
            if parsed:
                self.entries.append(parsed)

        configured_scope_file = scope_file or self.config.scope.scope_file
        if configured_scope_file:
            self._load_scope_file(configured_scope_file)

        # De-duplicate while preserving order.
        self.entries = list(dict.fromkeys(self.entries))
        self.allowed_domains = [entry.host for entry in self.entries]
        if not self.entries and self.base_url is None:
            self._legacy_open_scope = True

    def _parse_entry(self, value: str | None) -> ScopeEntry | None:
        if not value:
            return None
        text = str(value).strip().lower()
        if not text or text.startswith("#"):
            return None

        allow_subdomains = self.config.scope.subdomain_scope
        if text.startswith("*."):
            text = text[2:]
            allow_subdomains = True

        candidate = text if "://" in text else f"//{text}"
        try:
            parts = urlsplit(candidate)
            host = parts.hostname
            port = parts.port
        except ValueError:
            self.logger.warning(f"Ignoring invalid scope entry: {value}")
            return None
        if not host:
            self.logger.warning(f"Ignoring invalid scope entry: {value}")
            return None
        return ScopeEntry(
            host=host.rstrip(".").lower(),
            port=port,
            allow_subdomains=allow_subdomains,
        )

    def _load_scope_file(self, path: str) -> None:
        scope_path = Path(path).expanduser()
        try:
            lines = scope_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self.logger.warning(f"Could not read scope file {scope_path}: {exc}")
            return

        for line in lines:
            value = line.split("#", 1)[0].strip()
            parsed = self._parse_entry(value)
            if parsed:
                self.entries.append(parsed)

    def is_in_scope(self, url: str) -> bool:
        canonical = normalize_url(url)
        if not canonical:
            return False
        if self._legacy_open_scope:
            return True

        parts = urlsplit(canonical)
        try:
            host = (parts.hostname or "").rstrip(".").lower()
            port = parts.port or default_port(parts.scheme.lower())
        except ValueError:
            return False
        if not host:
            return False

        for entry in self.entries:
            if entry.allow_subdomains:
                host_match = host == entry.host or host.endswith(f".{entry.host}")
            else:
                host_match = host == entry.host
            port_match = entry.port is None or entry.port == port
            if host_match and port_match:
                return True
        return False
