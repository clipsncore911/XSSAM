from urllib.parse import urlparse
from typing import List, Optional
from xssam.config import settings

class ScopeValidator:
    def __init__(self, allowed_domains: Optional[List[str]] = None, scope_file: Optional[str] = None):
        self.allowed_domains = allowed_domains or settings.scope.allowed_domains
        self.scope_file = scope_file

        if self.scope_file:
            self._load_scope_file()

    def _load_scope_file(self):
        try:
            with open(self.scope_file, "r") as f:
                domains = [line.strip() for line in f if line.strip()]
                self.allowed_domains.extend(domains)
        except Exception:
            pass

    def is_in_scope(self, url: str) -> bool:
        if not self.allowed_domains:
            return True # If no allowlist is provided, we rely on the initial target URL

        parsed = urlparse(url)
        domain = parsed.netloc

        for allowed in self.allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True

        return False
