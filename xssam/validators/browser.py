from __future__ import annotations

import asyncio
import html
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from xssam.config import XSSAMSettings, load_config
from xssam.core.models import Finding, FindingStatus, ProofOfConcept
from xssam.crawler.url_normalizer import normalize_url
from xssam.logging import ScanLogger

CONFIRM_PREFIX = "__XSSAM_CONFIRMED__"


class BrowserValidator:
    """Confirm execution with a payload-specific marker in Chromium.

    The previous implementation treated its own ``XSSAM_SINK_HOOK_LOADED``
    console message as proof of execution, confirming every finding. This one
    only signals when a unique token appears in a dialog, DOM sink, or eval.
    A missing Playwright browser degrades to ``POTENTIAL`` instead of crashing.
    """

    def __init__(
        self,
        config: XSSAMSettings | bool | None = None,
        output_dir: str | Path = "output",
        logger: ScanLogger | None = None,
        *,
        headless: bool | None = None,
    ) -> None:
        legacy_headless: bool | None = None
        if isinstance(config, bool):
            legacy_headless = config
            config = None
        self.config = config or load_config(cwd_fallback=False)
        if headless is not None or legacy_headless is not None:
            self.config = self.config.model_copy(deep=True)
            self.config.browser.headless = (
                headless if headless is not None else bool(legacy_headless)
            )

        self.output_dir = Path(output_dir)
        self.logger = logger or ScanLogger(quiet=True)
        self._playwright_manager: Any | None = None
        self._playwright: Any | None = None
        self.browser: Any | None = None
        self._semaphore = asyncio.Semaphore(max(1, self.config.performance.threads))
        self.disabled = False
        self.disable_reason = ""

    @property
    def enabled(self) -> bool:
        return self.config.browser.enabled

    def is_available(self) -> bool:
        return self.enabled and not self.disabled and self.browser is not None

    async def start(self) -> bool:
        if not self.enabled:
            self.disabled = True
            self.disable_reason = "browser validation disabled"
            return False

        try:
            from playwright.async_api import async_playwright

            self._playwright_manager = async_playwright()
            self._playwright = await self._playwright_manager.start()
            self.browser = await self._playwright.chromium.launch(
                headless=self.config.browser.headless,
                args=["--no-sandbox"],
            )
            self.disabled = False
            self.disable_reason = ""
            return True
        except Exception as exc:
            self.disabled = True
            self.disable_reason = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
            await self.close()
            return False

    async def close(self) -> None:
        if self.browser is not None:
            try:
                await self.browser.close()
            except Exception as exc:
                self.logger.debug(f"Could not close browser: {exc}")
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception as exc:
                self.logger.debug(f"Could not stop Playwright: {exc}")
        self.browser = None
        self._playwright = None
        self._playwright_manager = None

    async def __aenter__(self) -> BrowserValidator:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    def _init_script(self, marker: str) -> str:
        token = json.dumps(marker)
        prefix = json.dumps(CONFIRM_PREFIX)
        return f"""
(() => {{
    const marker = {token};
    const prefix = {prefix};
    let signaled = false;
    const signal = () => {{
        if (!signaled) {{
            signaled = true;
            console.log(prefix + marker);
        }}
    }};
    const contains = (value) => String(value).includes(marker);

    try {{
        const nativeAlert = window.alert;
        window.alert = function(message) {{
            if (contains(message)) signal();
            return nativeAlert ? nativeAlert.apply(this, arguments) : undefined;
        }};
        const nativeConfirm = window.confirm;
        window.confirm = function(message) {{
            if (contains(message)) signal();
            return nativeConfirm ? nativeConfirm.apply(this, arguments) : false;
        }};
        const nativePrompt = window.prompt;
        window.prompt = function(message) {{
            if (contains(message)) signal();
            return nativePrompt ? nativePrompt.apply(this, arguments) : null;
        }};
    }} catch (error) {{}}

    try {{
        const nativeEval = window.eval;
        window.eval = function(code) {{
            if (contains(code)) signal();
            return nativeEval.call(this, code);
        }};
    }} catch (error) {{}}

    const hookSetter = (prototype, property) => {{
        try {{
            const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
            if (!descriptor || !descriptor.set) return;
            Object.defineProperty(prototype, property, {{
                configurable: descriptor.configurable,
                enumerable: descriptor.enumerable,
                get: descriptor.get,
                set: function(value) {{
                    if (contains(value)) signal();
                    return descriptor.set.call(this, value);
                }}
            }});
        }} catch (error) {{}}
    }};
    if (typeof Element !== 'undefined') {{
        hookSetter(Element.prototype, 'innerHTML');
        hookSetter(Element.prototype, 'outerHTML');
    }}

    try {{
        const nativeWrite = document.write.bind(document);
        document.write = function() {{
            for (const value of arguments) {{
                if (contains(value)) signal();
            }}
            return nativeWrite.apply(document, arguments);
        }};
    }} catch (error) {{}}

    document.addEventListener('DOMContentLoaded', () => {{
        for (const node of document.querySelectorAll('[data-xssam-confirmed]')) {{
            if (contains(node.getAttribute('data-xssam-confirmed'))) signal();
        }}
    }});
}})();
"""

    async def validate(self, finding: Finding) -> FindingStatus | None:
        if not self.is_available():
            return None
        poc = self._poc_from_finding(finding)
        if poc is None:
            return None
        marker = self._marker_from_finding(finding)

        async with self._semaphore:
            context = None
            executed = False
            try:
                context = await self.browser.new_context(
                    extra_http_headers=poc.headers or {}
                )
                if poc.cookies:
                    await self._add_cookies(context, poc.url, poc.cookies)
                await context.add_init_script(self._init_script(marker))
                page = await context.new_page()

                async def handle_dialog(dialog: Any) -> None:
                    nonlocal executed
                    message = str(getattr(dialog, "message", ""))
                    if marker in message:
                        executed = True
                    try:
                        result = dialog.dismiss()
                        if hasattr(result, "__await__"):
                            await result
                    except Exception:
                        pass

                async def handle_console(message: Any) -> None:
                    nonlocal executed
                    text = str(getattr(message, "text", ""))
                    if CONFIRM_PREFIX + marker in text:
                        executed = True

                page.on("dialog", handle_dialog)
                page.on("console", handle_console)
                await self._open_poc(page, poc)
                await asyncio.sleep(self.config.browser.settle_time)

                if executed:
                    await self._save_screenshot(page, finding)
                    finding.evidence["browser_validation"] = "confirmed"
                else:
                    finding.evidence["browser_validation"] = "not executed"
                return (
                    FindingStatus.CONFIRMED
                    if executed
                    else FindingStatus.POTENTIAL
                )
            except Exception as exc:
                self.logger.debug(f"Browser validation error: {exc}")
                finding.evidence["browser_validation_error"] = str(exc)
                return FindingStatus.POTENTIAL
            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def _add_cookies(
        self,
        context: Any,
        url: str,
        cookies: dict[str, str],
    ) -> None:
        parsed = urlsplit(url)
        cookie_url = f"{parsed.scheme}://{parsed.netloc}/"
        await context.add_cookies(
            [
                {"name": name, "value": value, "url": cookie_url}
                for name, value in cookies.items()
            ]
        )

    async def _open_poc(self, page: Any, poc: ProofOfConcept) -> None:
        timeout_ms = int(self.config.browser.navigation_timeout * 1000)
        if poc.method.upper() == "POST":
            await page.goto("about:blank")
            await page.set_content(self._build_post_form(poc))
            try:
                await page.evaluate("() => document.forms[0].submit()")
            except Exception:
                # Navigation can destroy the execution context after submit.
                pass
            return
        await page.goto(poc.url, wait_until="domcontentloaded", timeout=timeout_ms)

    @staticmethod
    def _build_post_form(poc: ProofOfConcept) -> str:
        inputs = "".join(
            f'<input type="hidden" name="{html.escape(str(name), quote=True)}" value="{html.escape(str(value), quote=True)}">'
            for name, value in (poc.data or {}).items()
        )
        return (
            "<!doctype html><html><body>"
            f'<form method="post" action="{html.escape(poc.url, quote=True)}">'
            f"{inputs}</form></body></html>"
        )

    async def _save_screenshot(self, page: Any, finding: Finding) -> None:
        screenshot_dir = self.output_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", finding.finding_id)
        path = screenshot_dir / f"{safe_id}.png"
        try:
            await page.screenshot(path=str(path))
            finding.evidence["screenshot"] = str(path)
        except Exception as exc:
            self.logger.debug(f"Could not save screenshot: {exc}")

    @staticmethod
    def _poc_from_finding(finding: Finding) -> ProofOfConcept | None:
        if finding.poc is not None:
            return finding.poc
        if finding.proof_url and normalize_url(finding.proof_url):
            return ProofOfConcept(url=finding.proof_url)
        return None

    @staticmethod
    def _marker_from_finding(finding: Finding) -> str:
        if finding.marker:
            return finding.marker
        text = f"{finding.payload.text} {finding.rendered_payload}"
        match = re.search(r"XSSAM_[A-Za-z0-9]+", text)
        return match.group(0) if match else "XSSAM"
