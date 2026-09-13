import asyncio
from playwright.async_api import async_playwright
from xssam.core.models import Finding, FindingStatus
from typing import Optional

class BrowserValidator:
    def __init__(self, headless: bool = True):
        self.headless = headless
        # A JS snippet to hook dangerous sinks and report them to the console
        self.sink_hook = """
        (function() {
            const sinks = {
                innerHTML: (el, val) => console.log('XSSAM_SINK_HIT: innerHTML', val),
                outerHTML: (el, val) => console.log('XSSAM_SINK_HIT: outerHTML', val),
                write: (val) => console.log('XSSAM_SINK_HIT: document.write', val),
                eval: (val) => console.log('XSSAM_SINK_HIT: eval', val)
            };

            try {
                const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set: function(value) {
                        console.log('XSSAM_SINK_HIT: innerHTML', value);
                        return originalInnerHTML.set.call(this, value);
                    },
                    get: function() {
                        return originalInnerHTML.get.call(this);
                    },
                    configurable: true
                });
            } catch(e) { console.log('XSSAM_HOOK_ERR: innerHTML', e); }

            console.log('XSSAM_SINK_HOOK_LOADED');
        })();
        """

    async def validate(self, finding: Finding) -> Optional[FindingStatus]:
        if not finding.proof_url:
            return None

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context()

            # Inject the sink hook before any page loads
            await context.add_init_script(self.sink_hook)

            page = await context.new_page()
            executed = False

            async def handle_dialog(dialog):
                nonlocal executed
                executed = True
                await dialog.dismiss()

            async def handle_console(msg):
                nonlocal executed
                if "XSSAM" in msg.text:
                    executed = True

            page.on("dialog", handle_dialog)
            page.on("console", handle_console)

            try:
                await page.goto(finding.proof_url, timeout=15000)
                await asyncio.sleep(2)
            except Exception:
                pass

            if executed:
                screenshot_path = f"output/screenshots/{finding.finding_id}.png"
                try:
                    await page.screenshot(path=screenshot_path)
                    finding.evidence["screenshot"] = screenshot_path
                except:
                    pass

            await browser.close()
            return FindingStatus.CONFIRMED if executed else FindingStatus.POTENTIAL
