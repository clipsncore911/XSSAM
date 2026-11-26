from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from xssam.config import XSSAMSettings, load_config
from xssam.core.models import TargetURL
from xssam.crawler.crawler import AsyncCrawler, is_html_response
from xssam.crawler.scope import ScopeValidator
from xssam.crawler.url_normalizer import normalize_url
from xssam.logging import ScanLogger
from xssam.parameters.extractor import ParameterExtractor
from xssam.reporting.exporter import ReportGenerator
from xssam.scanners.scanner import XSSScanner
from xssam.utils.http import AsyncHttpClient
from xssam.validators.browser import BrowserValidator


class XSSAMEngine:
    def __init__(
        self,
        args: Any,
        settings: XSSAMSettings | None = None,
        logger: ScanLogger | None = None,
    ) -> None:
        self.args = args
        self.settings = settings or load_config(cwd_fallback=False)
        self.logger = logger or ScanLogger()

        canonical = normalize_url(str(args.url))
        if not canonical:
            raise ValueError(f"Invalid HTTP(S) target URL: {args.url}")
        parsed = urlsplit(canonical)
        self.target = TargetURL(
            url=canonical,
            domain=parsed.netloc,
            protocol=parsed.scheme,
        )

        self.output_dir = Path(getattr(args, "output", None) or "output").expanduser().resolve()
        if not getattr(args, "crawl", True):
            self.settings.crawler.max_depth = 0
            self.settings.crawler.max_urls = 1

        self.results: list[Any] = []
        self.scanned_urls: list[str] = []
        self._results_lock = asyncio.Lock()
        self._attack_tasks: set[asyncio.Task[None]] = set()
        self._attack_semaphore = asyncio.Semaphore(
            max(1, self.settings.performance.threads)
        )

        self.http_client = AsyncHttpClient(
            self.settings,
            cookies=getattr(args, "cookies", None),
            headers=self._header_values(),
            user_agent=getattr(args, "user_agent", None),
            logger=self.logger,
        )
        self.scope_validator = ScopeValidator(
            canonical,
            self.settings,
            scope_file=getattr(args, "scope_file", None),
            logger=self.logger,
        )
        # Used by an httpx response hook to prevent out-of-scope redirects.
        self.http_client.scope_validator = self.scope_validator

    def _header_values(self) -> list[str]:
        values: list[str] = []
        legacy_headers = getattr(self.args, "headers", None)
        if legacy_headers:
            if isinstance(legacy_headers, str):
                values.extend(legacy_headers.split(","))
            else:
                values.extend(str(item) for item in legacy_headers)
        repeated_headers = getattr(self.args, "header", None) or []
        values.extend(str(item) for item in repeated_headers)
        return values

    def _prepare_output_dirs(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        for name in ("screenshots", "requests", "responses"):
            (self.output_dir / name).mkdir(parents=True, exist_ok=True)

    async def run_async(self) -> list[Any]:
        self.logger.info(f"\n[+] Target      : {self.target.url}")
        self.logger.info(f"[+] Scope       : {self.target.domain}")
        self.logger.info(f"[+] Crawl depth : {self.settings.crawler.max_depth}")
        self.logger.info(f"[+] Threads     : {self.settings.performance.threads}\n")
        self._prepare_output_dirs()

        scanner: XSSScanner | None = None
        browser: BrowserValidator | None = None
        try:
            if getattr(self.args, "scan", True):
                scanner = XSSScanner(self.http_client, self.settings, self.logger)
            browser = BrowserValidator(self.settings, self.output_dir, self.logger)

            if self.settings.browser.enabled:
                started = await browser.start()
                if not started and browser.disable_reason != "browser validation disabled":
                    self.logger.warning(
                        "Browser validation unavailable: "
                        f"{browser.disable_reason}. Findings will be marked POTENTIAL."
                    )
            validator = browser if browser.is_available() else None

            async def on_page(url: str, response: httpx.Response | None) -> None:
                if scanner is None:
                    async with self._results_lock:
                        if url not in self.scanned_urls:
                            self.scanned_urls.append(url)
                    return
                task = asyncio.create_task(
                    self._attack_url(url, response, scanner, validator)
                )
                self._attack_tasks.add(task)
                task.add_done_callback(self._attack_tasks.discard)

            crawler = AsyncCrawler(
                self.target.url,
                self.http_client,
                self.scope_validator,
                self.settings,
                on_page=on_page,
                logger=self.logger,
            )

            if getattr(self.args, "quiet", False):
                await crawler.crawl()
            else:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=self.logger.console,
                ) as progress:
                    task_id = progress.add_task("Scanning and crawling...", total=1)
                    await crawler.crawl()
                    progress.update(
                        task_id,
                        completed=1,
                        description="Scan complete",
                    )

            await self._drain_attacks()
        finally:
            # Never leave background attack tasks, the browser, or HTTP sockets
            # behind when a scan is cancelled or fails.
            await self._drain_attacks()
            if browser is not None:
                await browser.close()
            await self.http_client.close()

        self.logger.info("\n[+] All tasks finished. Generating reports...")
        self.generate_reports()
        return self.results

    def run(self) -> list[Any]:
        return asyncio.run(self.run_async())

    async def _drain_attacks(self) -> None:
        while self._attack_tasks:
            tasks = tuple(self._attack_tasks)
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, BaseException) and not isinstance(
                    outcome, asyncio.CancelledError
                ):
                    self.logger.debug(f"Attack task failed: {outcome}")
            for task in tasks:
                self._attack_tasks.discard(task)

    async def _attack_url(
        self,
        url: str,
        response: httpx.Response | None,
        scanner: XSSScanner,
        validator: BrowserValidator | None,
    ) -> None:
        async with self._attack_semaphore:
            async with self._results_lock:
                if url not in self.scanned_urls:
                    self.scanned_urls.append(url)

            extractor = ParameterExtractor()
            params = extractor.extract_from_url(url)
            response_text = ""
            if is_html_response(response):
                assert response is not None
                response_text = response.text
                params.extend(extractor.extract_from_html(response_text, url))
            params = extractor._dedupe(params)

            for parameter in params:
                try:
                    findings = await scanner.scan_parameter(
                        url,
                        parameter,
                        validator=validator,
                        response_text=response_text,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.logger.debug(
                        f"Could not scan {parameter.name} on {url}: {exc}"
                    )
                    continue
                async with self._results_lock:
                    self.results.extend(findings)

            if self.settings.scanner.dom and validator is not None and response_text:
                try:
                    findings = await scanner.scan_dom_fragment(
                        url, response_text, validator
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.logger.debug(f"DOM probe failed on {url}: {exc}")
                else:
                    async with self._results_lock:
                        self.results.extend(findings)

    def generate_reports(self) -> list[Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        exporter = ReportGenerator(self.output_dir, self.settings, self.logger)
        paths = exporter.export_all(
            self.results,
            target_url=self.target.url,
            scanned_urls=list(self.scanned_urls),
        )
        if paths:
            names = ", ".join(path.name for path in paths)
            self.logger.success(f"Reports saved to {self.output_dir} ({names})")
        else:
            self.logger.warning("No report formats are enabled; no report was written")
        return paths
