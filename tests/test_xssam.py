from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import warnings
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from xssam.config import XSSAMSettings, load_config
from xssam.core.models import (
    Finding,
    FindingStatus,
    Parameter,
    ParameterLocation,
    Payload,
    ProofOfConcept,
)
from xssam.crawler.crawler import AsyncCrawler
from xssam.crawler.scope import ScopeValidator
from xssam.logging import ScanLogger
from xssam.parameters.extractor import ParameterExtractor
from xssam.payloads.corpus import ContextAnalyzer, PayloadCorpus
from xssam.reporting.exporter import ReportGenerator
from xssam.scanners.scanner import XSSScanner
from xssam.utils.http import AsyncHttpClient
from xssam.validators.browser import CONFIRM_PREFIX, BrowserValidator

ROOT = Path(__file__).resolve().parents[1]


class VulnerableHandler(BaseHTTPRequestHandler):
    """A tiny, deliberately vulnerable server on an ephemeral local port."""

    def log_message(self, *_args: object) -> None:
        pass

    def _write(self, body: str, status: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        q = params.get("q", [""])[0]
        url = params.get("url", [""])[0]
        name = params.get("name", [""])[0]

        if parsed.path == "/":
            self._write(
                """
                <h1>Local target</h1>
                <a href="/search?q=hello">Search</a>
                <a href="/profile?name=guest">Profile</a>
                <a href="/callback?url=/">Callback</a>
                <a href="/dom">DOM</a>
                <a href="/escaped?q=hello">Safe</a>
                <a href="/item/42">Item</a>
                <a href="/deep">Deep</a>
                <a href="https://example.invalid/out">External</a>
                <form action="/post" method="post">
                  <input name="msg" value="hello">
                </form>
                """
            )
        elif parsed.path == "/search":
            self._write(f"<h1>Search results for: {q}</h1>")
        elif parsed.path == "/profile":
            self._write(f"<input type='text' value='{name}'>")
        elif parsed.path == "/callback":
            self._write(f"<script>var redirectUrl = '{url}';</script>")
        elif parsed.path == "/dom":
            self._write(
                "<div id='result'></div><script>"
                "document.getElementById('result').innerHTML = "
                "decodeURIComponent(location.hash.slice(1));"
                "</script>"
            )
        elif parsed.path == "/escaped":
            self._write(f"<h1>Search results for: {escape(q)}</h1>")
        elif parsed.path == "/item/42":
            self._write("<h1>Item 42</h1>")
        elif parsed.path == "/deep":
            self._write('<a href="/too-deep">One level deeper</a>')
        elif parsed.path == "/too-deep":
            self._write("<h1>Too deep</h1>")
        elif parsed.path == "/redirect":
            self._redirect("https://example.invalid/out")
        elif parsed.path == "/safe-redirect":
            self._redirect("/search?q=redirected")
        else:
            self._write("<h1>Not found</h1>", status=404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        message = parse_qs(body, keep_blank_values=True).get("msg", [""])[0]
        self._write(f"<div id='result'>{message}</div>")


@pytest.fixture(scope="module")
def vulnerable_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def _subprocess_env(extra_cwd: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("XSSAM_CONFIG", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(ROOT) + (os.pathsep + existing if existing else "")
    return env


def _scanner_settings() -> XSSAMSettings:
    settings = XSSAMSettings()
    settings.performance.delay = 0
    settings.performance.threads = 2
    settings.crawler.max_requests = 50
    settings.browser.enabled = False
    return settings


def _make_finding(marker: str) -> Finding:
    payload = Payload(
        payload_id="test_01",
        text=f"<script>alert('{marker}')</script>",
        context="html",
    )
    poc = ProofOfConcept(url="https://example.com/?q=test")
    return Finding(
        finding_id=f"find_{marker}",
        target_url="https://example.com/",
        parameter=Parameter(
            name="q",
            value="test",
            location=ParameterLocation.QUERY,
            discovery_source="test",
        ),
        payload=payload,
        status=FindingStatus.POTENTIAL,
        proof_url=poc.url,
        rendered_payload=payload.text,
        marker=marker,
        poc=poc,
    )


def test_packaged_config_loads_from_any_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("XSSAM_CONFIG", raising=False)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        settings = load_config()
    assert settings.crawler.max_urls > 0
    assert settings.reporting.json_report is True
    assert not any("shadows an attribute" in str(item.message) for item in caught)


def test_custom_config_file_and_environment_variable(tmp_path, monkeypatch):
    config_path = tmp_path / "custom.yaml"
    config_path.write_text("crawler:\n  max_depth: 7\n", encoding="utf-8")
    assert load_config(config_path).crawler.max_depth == 7

    monkeypatch.setenv("XSSAM_CONFIG", str(config_path))
    assert load_config(cwd_fallback=False).crawler.max_depth == 7


def test_payload_corpus_tolerates_empty_and_invalid_yaml(tmp_path):
    (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
    (tmp_path / "invalid.yaml").write_text("- not\n- a mapping\n", encoding="utf-8")
    (tmp_path / "good.yaml").write_text(
        'context: "html"\n'
        "payloads:\n"
        '  - payload_id: "custom_01"\n'
        '    text: "<b>__XSSAM_TOKEN__</b>"\n',
        encoding="utf-8",
    )

    corpus = PayloadCorpus(directory=tmp_path)
    assert corpus.errors
    assert any(
        payload.payload_id == "custom_01"
        for payload in corpus.payloads_by_context["html"]
    )
    rendered = corpus.get_payloads("html", "TOKEN123")
    assert "<b>TOKEN123</b>" in [payload.text for payload in rendered]
    assert all("__XSSAM_TOKEN__" not in payload.text for payload in rendered)
    assert all(payload.context for payload in rendered)


def test_scope_defaults_to_target_origin_and_blocks_lookalikes():
    settings = XSSAMSettings()
    validator = ScopeValidator("https://example.com/app", settings)
    assert validator.is_in_scope("https://example.com/other")
    assert validator.is_in_scope("https://example.com:443/other")
    assert not validator.is_in_scope("https://example.com:8443/other")
    assert not validator.is_in_scope("https://evil-example.com/")
    assert not validator.is_in_scope("https://api.example.com/")
    assert not validator.is_in_scope("javascript:alert(1)")

    settings.scope.subdomain_scope = True
    subdomain_validator = ScopeValidator("https://example.com/app", settings)
    assert subdomain_validator.is_in_scope("https://api.example.com/")


def test_http_client_blocks_out_of_scope_redirects(vulnerable_server):
    settings = _scanner_settings()
    client = AsyncHttpClient(settings, logger=ScanLogger(quiet=True))
    client.scope_validator = ScopeValidator(vulnerable_server + "/", settings)

    async def run():
        try:
            blocked = await client.request("GET", vulnerable_server + "/redirect")
            allowed = await client.request("GET", vulnerable_server + "/safe-redirect")
            return blocked, allowed
        finally:
            await client.close()

    blocked, allowed = asyncio.run(run())
    assert blocked is None
    assert allowed is not None
    assert allowed.status_code == 200


def test_parameter_extractor_handles_query_forms_and_dynamic_paths():
    extractor = ParameterExtractor()
    url_params = extractor.extract_from_url(
        "https://example.com/item/42?q=hello&flag"
    )
    assert any(p.name == "q" and p.location == ParameterLocation.QUERY for p in url_params)
    assert any(p.name == "flag" and p.value == "" for p in url_params)
    assert any(p.name == "path_segment_2" for p in url_params)
    assert not any(p.name == "path_segment_1" for p in url_params)

    form_params = extractor.extract_from_html(
        '<form action="/post" method="post"><input name="msg" value="hi"></form>',
        "https://example.com/page",
    )
    form_param = next(p for p in form_params if p.name == "msg")
    assert form_param.location == ParameterLocation.FORM
    assert form_param.method == "POST"
    assert form_param.action_url == "https://example.com/post"


def test_context_analyzer_classifies_canary_contexts():
    analyzer = ContextAnalyzer("xssam_canary_123")
    assert analyzer.analyze("<script>var x='xssam_canary_123';</script>") == "javascript"
    assert analyzer.analyze("<input value='xssam_canary_123'>") == "attribute"
    assert analyzer.analyze("<h1>xssam_canary_123</h1>") == "html"
    assert analyzer.analyze("<h1>no canary here</h1>") == "unknown"


def test_crawler_respects_scope_and_depth(vulnerable_server):
    settings = _scanner_settings()
    settings.crawler.max_depth = 1
    settings.crawler.max_urls = 20
    client = AsyncHttpClient(settings, logger=ScanLogger(quiet=True))
    validator = ScopeValidator(vulnerable_server + "/", settings)
    seen: list[str] = []

    async def on_page(url: str, _response) -> None:
        seen.append(url)

    crawler = AsyncCrawler(
        vulnerable_server + "/",
        client,
        validator,
        settings,
        on_page=on_page,
        logger=ScanLogger(quiet=True),
    )

    async def run():
        try:
            return await crawler.crawl()
        finally:
            await client.close()

    discovered = asyncio.run(run())
    assert any("/search" in url for url in discovered)
    assert any("/deep" in url for url in discovered)
    assert not any("example.invalid" in url for url in discovered)
    assert not any("/too-deep" in url for url in discovered)
    assert len(seen) >= 1


def test_scanner_ignores_html_escaped_reflection(vulnerable_server):
    settings = _scanner_settings()
    client = AsyncHttpClient(settings, logger=ScanLogger(quiet=True))
    scanner = XSSScanner(client, settings, ScanLogger(quiet=True))
    parameter = Parameter(
        name="q",
        value="hello",
        location=ParameterLocation.QUERY,
        discovery_source="test",
    )

    async def run():
        try:
            return await scanner.scan_parameter(
                f"{vulnerable_server}/escaped?q=hello", parameter
            )
        finally:
            await client.close()

    assert asyncio.run(run()) == []


def test_scanner_detects_javascript_context(vulnerable_server):
    settings = _scanner_settings()
    client = AsyncHttpClient(settings, logger=ScanLogger(quiet=True))
    scanner = XSSScanner(client, settings, ScanLogger(quiet=True))
    parameter = Parameter(
        name="url",
        value="/",
        location=ParameterLocation.QUERY,
        discovery_source="test",
    )

    async def run():
        try:
            return await scanner.scan_parameter(
                f"{vulnerable_server}/callback?url=/", parameter
            )
        finally:
            await client.close()

    findings = asyncio.run(run())
    assert findings
    assert findings[0].context == "javascript"
    assert findings[0].status == FindingStatus.POTENTIAL
    assert findings[0].poc is not None


def test_reports_escape_payloads_and_write_all_formats(tmp_path):
    payload = Payload(
        payload_id="escape_01",
        text="<script>alert('XSSAM_TEST')</script>",
        context="html",
    )
    finding = Finding(
        finding_id="find_escape",
        target_url="https://example.com/search",
        parameter=Parameter(
            name="q",
            location=ParameterLocation.QUERY,
            discovery_source="test",
        ),
        payload=payload,
        status=FindingStatus.POTENTIAL,
        proof_url="https://example.com/search?q=test",
        rendered_payload=payload.text,
        marker="XSSAM_TEST",
        poc=ProofOfConcept(url="https://example.com/search?q=test"),
    )
    exporter = ReportGenerator(tmp_path / "reports", XSSAMSettings())
    paths = exporter.export_all([finding], target_url="https://example.com/")

    assert {path.name for path in paths} == {
        "report.json",
        "report.txt",
        "report.html",
    }
    report_html = (tmp_path / "reports" / "report.html").read_text(encoding="utf-8")
    assert "<script>alert('XSSAM_TEST')</script>" not in report_html
    assert "&lt;script&gt;" in report_html
    assert json.loads((tmp_path / "reports" / "report.json").read_text())[0][
        "finding_id"
    ] == "find_escape"


class FakeConsoleMessage:
    def __init__(self, text: str) -> None:
        self.text = text


class FakeDialog:
    def __init__(self, message: str) -> None:
        self.message = message

    async def dismiss(self) -> None:
        return None


class FakePage:
    def __init__(self, console_messages=(), dialog_messages=()) -> None:
        self.console_messages = list(console_messages)
        self.dialog_messages = list(dialog_messages)
        self.handlers: dict[str, object] = {}

    def on(self, event: str, handler) -> None:
        self.handlers[event] = handler

    async def goto(self, _url: str, **_kwargs) -> None:
        console_handler = self.handlers.get("console")
        for message in self.console_messages:
            if console_handler:
                await console_handler(FakeConsoleMessage(message))
        dialog_handler = self.handlers.get("dialog")
        for message in self.dialog_messages:
            if dialog_handler:
                await dialog_handler(FakeDialog(message))

    async def screenshot(self, path: str) -> None:
        Path(path).write_bytes(b"fake screenshot")


class FakeContext:
    def __init__(self, page: FakePage) -> None:
        self.page = page
        self.closed = False

    async def add_init_script(self, _script: str) -> None:
        return None

    async def add_cookies(self, _cookies) -> None:
        return None

    async def new_page(self) -> FakePage:
        return self.page

    async def close(self) -> None:
        self.closed = True


class FakeBrowser:
    def __init__(self, page: FakePage) -> None:
        self.page = page

    async def new_context(self, **_kwargs) -> FakeContext:
        return FakeContext(self.page)


def test_browser_validator_only_confirms_payload_marker(tmp_path):
    settings = XSSAMSettings()
    settings.browser.enabled = True
    settings.browser.settle_time = 0
    validator = BrowserValidator(settings, tmp_path, ScanLogger(quiet=True))
    validator.disabled = False
    first_finding = _make_finding("TOKEN123")
    second_finding = _make_finding("TOKEN123")

    quiet_page = FakePage(
        console_messages=["XSSAM_SINK_HOOK_LOADED"],
        dialog_messages=["unrelated alert"],
    )
    confirmed_page = FakePage(
        console_messages=[CONFIRM_PREFIX + "TOKEN123"],
    )

    async def run():
        validator.browser = FakeBrowser(quiet_page)
        first = await validator.validate(first_finding)
        validator.browser = FakeBrowser(confirmed_page)
        second = await validator.validate(second_finding)
        return first, second

    first_status, second_status = asyncio.run(run())
    assert first_status == FindingStatus.POTENTIAL
    assert second_status == FindingStatus.CONFIRMED
    assert Path(second_finding.evidence["screenshot"]).is_file()


def test_cli_end_to_end_from_outside_repository(tmp_path, vulnerable_server):
    output_dir = tmp_path / "scan-output"
    command = [
        sys.executable,
        "-m",
        "xssam",
        "-u",
        f"{vulnerable_server}/search?q=hello",
        "--authorized",
        "--no-crawl",
        "--no-browser",
        "--depth",
        "0",
        "--delay",
        "0",
        "--threads",
        "2",
        "--max-requests",
        "50",
        "--quiet",
        "-o",
        str(output_dir),
    ]
    result = subprocess.run(
        command,
        cwd=tmp_path,
        env=_subprocess_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    findings = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["status"] == "POTENTIAL"
    assert findings[0]["parameter"]["name"] == "q"
    assert findings[0]["marker"].startswith("XSSAM_")
    assert findings[0]["poc"]["method"] == "GET"

    report_html = (output_dir / "report.html").read_text(encoding="utf-8")
    assert "&lt;script&gt;" in report_html
    assert "<script>alert('" not in report_html
    assert "XSSAM SCAN REPORT" in (output_dir / "report.txt").read_text()


def test_cli_requires_authorization(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "xssam",
            "-u",
            "https://example.com/",
            "--quiet",
        ],
        cwd=tmp_path,
        env=_subprocess_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2
    assert "--authorized" in result.stdout + result.stderr


def test_cli_version_works_from_any_directory(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "xssam", "--version"],
        cwd=tmp_path,
        env=_subprocess_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert "XSSAM" in result.stdout
