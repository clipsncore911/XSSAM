import asyncio
import os
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from xssam.core.models import TargetURL, FindingStatus
from xssam.config import settings
from xssam.utils.http import AsyncHttpClient
from xssam.crawler.crawler import AsyncCrawler
from xssam.crawler.scope import ScopeValidator
from xssam.parameters.extractor import ParameterExtractor
from xssam.scanners.scanner import XSSScanner
from xssam.validators.browser import BrowserValidator

class XSSAMEngine:
    def __init__(self, args):
        self.args = args
        self.console = Console()
        self.target = TargetURL(
            url=args.url,
            domain=args.url.split("//")[-1].split("/")[0],
            protocol="https" if args.url.startswith("https") else "http"
        )
        self.results = []
        self.http_client = AsyncHttpClient(
            cookies=args.cookies,
            headers=args.headers,
            user_agent=args.user_agent
        )
        self.validator = ScopeValidator(
            allowed_domains=args.scope.split(",") if args.scope else None,
            scope_file=args.scope_file
        )

    async def run_async(self):
        self.console.print(f"\n[+] Target       : [bold cyan]{self.target.url}[/bold cyan]")
        self.console.print(f"[+] Scope         : {self.target.domain}")
        self.console.print(f"[+] Crawl depth  : {settings.crawler.max_depth}")
        self.console.print(f"[+] Threads      : {settings.performance.threads}\n")

        # Create output dirs
        os.makedirs("output/screenshots", exist_ok=True)
        os.makedirs("output/requests", exist_ok=True)
        os.makedirs("output/responses", exist_ok=True)

        # Initialize tools
        extractor = ParameterExtractor()
        scanner = XSSScanner(self.http_client)
        browser_val = BrowserValidator(headless=settings.browser.headless)

        # lock for results list
        self.results_lock = asyncio.Lock()

        async def on_url_discovered(url: str):
            # This is called by the crawler. We create a task so the crawler doesn't wait.
            asyncio.create_task(self._attack_url(url, extractor, scanner, browser_val))

        async def _attack_url(self, url, extractor, scanner, browser_val):
            # 1. Extract parameters
            params = extractor.extract_from_url(url)

            # Also extract from HTML content
            resp = await self.http_client.request("GET", url)
            if resp:
                params.extend(extractor.extract_from_html(resp.text, url))

            # 2. Attack if parameters are found
            if params:
                for param in params:
                    findings = await scanner.scan_parameter(url, param)
                    for f in findings:
                        # 3. Validate with browser
                        status = await browser_val.validate(f)
                        if status:
                            f.status = status

                        async with self.results_lock:
                            self.results.append(f)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:

            recon_task = progress.add_task("[cyan]Scanning & Crawling...", total=None)

            crawler = AsyncCrawler(
                self.target.url,
                self.http_client,
                self.validator,
                on_url_discovered=on_url_discovered
            )

            await crawler.crawl()

            # Give some time for background attack tasks to finish
            self.console.print("[*] Finalizing active attacks...")
            await asyncio.sleep(5)

            progress.update(recon_task, completed=100, description="[green]Scan complete")

        self.console.print("\n[+] All tasks finished. Generating reports...")
        self.generate_reports()
        await self.http_client.close()

    def run(self):
        asyncio.run(self.run_async())

    def generate_reports(self):
        output_dir = self.args.output or "output"
        self.console.print(f"[✓] Reports saved to [bold]{output_dir}[/bold]")

        from xssam.reporting.exporter import ReportGenerator
        exporter = ReportGenerator(output_dir)
        exporter.export_json(self.results)
        exporter.export_txt(self.results)
        exporter.export_html(self.results)
