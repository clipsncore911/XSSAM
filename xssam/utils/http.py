from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel

from xssam.config import XSSAMSettings, load_config
from xssam.logging import ScanLogger


def parse_header_values(headers: str | Iterable[str] | None) -> dict[str, str]:
    """Parse ``Name: Value`` headers; a lone string is comma-separated."""
    if headers is None:
        return {}
    items: Iterable[str]
    if isinstance(headers, str):
        items = headers.split(",")
    else:
        items = headers

    parsed: dict[str, str] = {}
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        if ":" not in text:
            raise ValueError(f"Invalid header {text!r}; expected 'Name: Value'")
        name, value = text.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"Invalid header {text!r}; header name is empty")
        parsed[name] = value.strip()
    return parsed


def parse_cookie_string(cookies: str | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if not cookies:
        return parsed
    for item in cookies.split(";"):
        text = item.strip()
        if not text:
            continue
        if "=" not in text:
            raise ValueError(f"Invalid cookie {text!r}; expected 'name=value'")
        name, value = text.split("=", 1)
        parsed[name.strip()] = value.strip()
    return parsed


class AsyncHttpClient:
    """Shared HTTP client with a concurrency limit, rate limit and budget."""

    def __init__(
        self,
        config: XSSAMSettings | str | None = None,
        cookies: str | None = None,
        headers: str | Iterable[str] | None = None,
        user_agent: str | None = None,
        logger: ScanLogger | None = None,
    ) -> None:
        # Compatibility with the old positional (cookies, headers, user_agent)
        # constructor.
        if isinstance(config, str):
            config, cookies, headers, user_agent = None, config, cookies, headers  # type: ignore[assignment]
        if config is not None and not isinstance(config, BaseModel):
            raise TypeError("config must be an XSSAMSettings instance")

        self.config = config or load_config(cwd_fallback=False)
        self.logger = logger or ScanLogger(quiet=True)
        self.scope_validator: Any | None = None
        performance = self.config.performance

        self.custom_headers = parse_header_values(headers)
        self.custom_headers.setdefault(
            "User-Agent",
            user_agent or "XSSAM/0.1.0 (Authorized Security Testing)",
        )
        self.cookies_dict = parse_cookie_string(cookies)
        self.custom_cookies = dict(self.cookies_dict)

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(performance.timeout),
            limits=httpx.Limits(
                max_connections=performance.threads,
                max_keepalive_connections=performance.threads,
            ),
            headers=self.custom_headers,
            cookies=self.cookies_dict,
            follow_redirects=True,
            max_redirects=5,
            event_hooks={"response": [self._check_redirect_scope]},
        )

        self._semaphore = asyncio.Semaphore(performance.threads)
        self._rate_lock = asyncio.Lock()
        self._last_request_started = 0.0
        self._closed = False
        self.request_count = 0
        self.max_requests = self.config.crawler.max_requests

    async def _check_redirect_scope(self, response: httpx.Response) -> None:
        """Do not let httpx silently follow a redirect outside the allowlist."""
        if self.scope_validator is None or not response.is_redirect:
            return
        location = response.headers.get("location")
        if not location:
            return
        redirect_url = urljoin(str(response.url), location)
        if not self.scope_validator.is_in_scope(redirect_url):
            raise RuntimeError(f"Blocked out-of-scope redirect to {redirect_url}")

    async def _throttle(self) -> None:
        delay = self.config.performance.delay
        if delay <= 0:
            return
        loop = asyncio.get_running_loop()
        async with self._rate_lock:
            wait_for = self._last_request_started + delay - loop.time()
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_request_started = loop.time()

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        if self._closed:
            return None
        if self.max_requests and self.request_count >= self.max_requests:
            self.logger.debug("Request budget exhausted; skipping request")
            return None

        async with self._semaphore:
            if self._closed:
                return None
            if self.max_requests and self.request_count >= self.max_requests:
                return None
            await self._throttle()
            self.request_count += 1
            try:
                return await self.client.request(method, url, **kwargs)
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                self.logger.debug(f"Request failed ({method} {url}): {exc}")
                return None

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.client.aclose()

    async def __aenter__(self) -> AsyncHttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()
