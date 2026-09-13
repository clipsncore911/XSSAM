import asyncio
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Set, List, Optional, Callable, Awaitable
from xssam.utils.http import AsyncHttpClient
from xssam.crawler.scope import ScopeValidator
from xssam.config import settings

class AsyncCrawler:
    def __init__(self, start_url: str, client: AsyncHttpClient, validator: ScopeValidator, on_url_discovered: Optional[Callable[[str], Awaitable[None]]] = None):
        self.start_url = start_url
        self.client = client
        self.validator = validator
        self.on_url_discovered = on_url_discovered
        self.visited: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.max_depth = settings.crawler.max_depth
        self.max_urls = settings.crawler.max_urls

    async def crawl(self):
        # Seed the queue
        await self.queue.put((self.start_url, 0))
        self.discovered_urls.add(self.start_url)

        # Create a pool of workers
        num_workers = settings.performance.threads
        workers = [asyncio.create_task(self._worker()) for _ in range(num_workers)]

        # Wait until all discovered URLs are processed
        # We use a custom logic because we don't want to wait forever if the site is huge
        # and we want to respect max_urls.

        # Since asyncio.Queue doesn't have a 'join()' that works across workers
        # without task_done(), we'll use a simpler approach:
        # Process until the queue is empty AND no workers are actively processing.

        # Actually, the most standard way:
        # 1. Add start URL.
        # 2. Workers take from queue, process, add new URLs to queue.
        # 3. When queue is empty and all workers are idle -> Done.

        # To avoid hanging, we'll use a timeout or the max_urls limit.

        # Let's use a shared counter for active tasks.
        self._active_tasks = 0
        self._condition = asyncio.Condition()

        # We'll run the workers and wait for the completion condition.
        # To simplify for this project, I'll use a loop that checks for idle state.

        while True:
            if self.queue.empty() and self._active_tasks == 0:
                break
            if len(self.visited) >= self.max_urls:
                break
            await asyncio.sleep(0.1)

        # Cancel workers when finished
        for w in workers:
            w.cancel()

        return self.discovered_urls

    async def _worker(self):
        while True:
            try:
                url, depth = await self.queue.get()

                async with self._condition:
                    self._active_tasks += 1

                try:
                    if url not in self.visited and depth <= self.max_depth:
                        await self._process_url(url, depth)
                finally:
                    async with self._condition:
                        self._active_tasks -= 1
                    self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception:
                continue

    async def _process_url(self, url: str, depth: int):
        self.visited.add(url)

        # Trigger the attack pipeline immediately
        if self.on_url_discovered:
            await self.on_url_discovered(url)

        response = await self.client.request("GET", url)
        if not response or "text/html" not in response.headers.get("Content-Type", ""):
            return

        soup = BeautifulSoup(response.text, "html.parser")

        # Discovery: Links
        for link in soup.find_all("a", href=True):
            abs_url = urljoin(url, link["href"])
            if self._is_valid_url(abs_url) and abs_url not in self.visited:
                self.discovered_urls.add(abs_url)
                await self.queue.put((abs_url, depth + 1))

        # Discovery: Forms
        for form in soup.find_all("form", action=True):
            abs_url = urljoin(url, form["action"])
            if self._is_valid_url(abs_url) and abs_url not in self.visited:
                self.discovered_urls.add(abs_url)
                await self.queue.put((abs_url, depth + 1))

    def _is_valid_url(self, url: str) -> bool:
        if not url.startswith("http"):
            return False
        return self.validator.is_in_scope(url)
