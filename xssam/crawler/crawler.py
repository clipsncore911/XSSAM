from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from xssam.config import XSSAMSettings, load_config
from xssam.crawler.scope import ScopeValidator
from xssam.crawler.url_normalizer import normalize_url
from xssam.logging import ScanLogger
from xssam.utils.http import AsyncHttpClient

PageCallback = Callable[[str, httpx.Response | None], Awaitable[None] | None]
LegacyCallback = Callable[[str], Awaitable[None] | None]


def is_html_response(response: httpx.Response | None) -> bool:
    if response is None:
        return False
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        return True
    head = response.text[:256].lstrip().lower()
    return head.startswith(("<!doctype html", "<html"))


class AsyncCrawler:
    """A bounded, same-scope crawler using a queue and a fixed worker pool."""

    def __init__(
        self,
        start_url: str,
        client: AsyncHttpClient,
        validator: ScopeValidator,
        config: XSSAMSettings | None = None,
        *,
        on_page: PageCallback | None = None,
        on_url_discovered: LegacyCallback | None = None,
        logger: ScanLogger | None = None,
    ) -> None:
        canonical = normalize_url(start_url)
        if not canonical:
            raise ValueError(f"Invalid HTTP(S) start URL: {start_url}")

        self.start_url = canonical
        self.client = client
        self.validator = validator
        self.config = config or load_config(cwd_fallback=False)
        self.logger = logger or ScanLogger(quiet=True)
        self.max_depth = self.config.crawler.max_depth
        self.max_urls = self.config.crawler.max_urls
        self.visited: set[str] = set()
        self.discovered_urls: set[str] = {canonical}
        self.queue: asyncio.Queue[tuple[str, int] | None] = asyncio.Queue()
        self._workers: list[asyncio.Task[None]] = []

        if on_page is None and on_url_discovered is not None:
            legacy_callback = on_url_discovered

            async def wrapped(url: str, _response: httpx.Response | None) -> None:
                result = legacy_callback(url)
                if inspect.isawaitable(result):
                    await result

            on_page = wrapped
        self.on_page = on_page

    async def crawl(self) -> list[str]:
        self.queue.put_nowait((self.start_url, 0))
        worker_count = min(self.config.performance.threads, self.max_urls)
        self._workers = [asyncio.create_task(self._worker()) for _ in range(worker_count)]

        try:
            # queue.join() is race-free: unfinished_tasks is incremented when an
            # item is enqueued, before a worker can mark it done.
            await self.queue.join()
        finally:
            for _ in self._workers:
                self.queue.put_nowait(None)
            await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()

        return sorted(self.discovered_urls)

    async def _worker(self) -> None:
        while True:
            item = await self.queue.get()
            try:
                if item is None:
                    return
                url, depth = item
                await self._process_url(url, depth)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.logger.debug(f"Crawler worker error: {exc}")
            finally:
                self.queue.task_done()

    async def _process_url(self, url: str, depth: int) -> None:
        canonical = normalize_url(url)
        if (
            not canonical
            or canonical in self.visited
            or depth > self.max_depth
            or len(self.visited) >= self.max_urls
        ):
            return
        self.visited.add(canonical)

        response = await self.client.request("GET", canonical)
        if self.on_page:
            try:
                result = self.on_page(canonical, response)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                self.logger.debug(f"Page callback failed for {canonical}: {exc}")

        if not is_html_response(response):
            return

        assert response is not None
        soup = BeautifulSoup(response.text, "html.parser")
        for absolute_url in self._extract_links(soup, canonical):
            self._enqueue(absolute_url, depth + 1)

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        links: list[str] = []
        for tag in soup.find_all(["a", "area"], href=True):
            links.append(urljoin(base_url, str(tag["href"])))
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            links.append(urljoin(base_url, str(action)))
        return links

    def _enqueue(self, url: str, depth: int) -> None:
        if depth > self.max_depth or len(self.discovered_urls) >= self.max_urls:
            return
        canonical = normalize_url(url)
        if (
            not canonical
            or canonical in self.discovered_urls
            or not self.validator.is_in_scope(canonical)
        ):
            return
        self.discovered_urls.add(canonical)
        self.queue.put_nowait((canonical, depth))
