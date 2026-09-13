import httpx
import asyncio
from typing import Optional, Dict, Any
from xssam.config import settings
from rich.console import Console

console = Console()

class AsyncHttpClient:
    def __init__(self, cookies: Optional[str] = None, headers: Optional[str] = None, user_agent: Optional[str] = None):
        self.timeout = httpx.Timeout(settings.performance.timeout)
        self.limits = httpx.Limits(max_connections=settings.performance.threads)

        self.custom_headers = {}
        if headers:
            for h in headers.split(","):
                k, v = h.split(":", 1)
                self.custom_headers[k.strip()] = v.strip()

        if user_agent:
            self.custom_headers["User-Agent"] = user_agent
        else:
            self.custom_headers["User-Agent"] = "XSSAM/0.1.0 (Authorized Security Testing)"

        self.cookies_dict = {}
        if cookies:
            for c in cookies.split(";"):
                k, v = c.split("=", 1)
                self.cookies_dict[k.strip()] = v.strip()

        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            limits=self.limits,
            headers=self.custom_headers,
            cookies=self.cookies_dict,
            follow_redirects=True
        )

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            # Implement delay for rate limiting
            if settings.performance.delay > 0:
                await asyncio.sleep(settings.performance.delay)

            response = await self.client.request(method, url, **kwargs)
            return response
        except httpx.RequestError as e:
            # Silently handle request errors to avoid crashing the scan
            return None

    async def close(self):
        await self.client.aclose()
