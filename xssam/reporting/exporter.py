from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from pydantic import BaseModel

from xssam.config import ReportingConfig, XSSAMSettings, load_config
from xssam.core.models import Finding, FindingStatus
from xssam.logging import ScanLogger


def status_value(finding: Finding) -> str:
    status = finding.status
    if isinstance(status, FindingStatus):
        return status.value
    return str(status)


class ReportGenerator:
    def __init__(
        self,
        output_dir: str | Path,
        settings: XSSAMSettings | ReportingConfig | None = None,
        logger: ScanLogger | None = None,
    ) -> None:
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if settings is None:
            settings = load_config(cwd_fallback=False)
        self.settings = settings
        self.reporting = (
            settings.reporting
            if isinstance(settings, BaseModel) and hasattr(settings, "reporting")
            else settings
        )
        self.logger = logger or ScanLogger(quiet=True)
        self.env = Environment(
            loader=PackageLoader("xssam.reporting", "templates"),
            # Old reports rendered payloads and URLs without escaping, so a
            # finding could execute JavaScript when the report was opened.
            autoescape=select_autoescape(["html", "xml"]),
        )

    def export_all(
        self,
        findings: Sequence[Finding],
        *,
        target_url: str | None = None,
        scanned_urls: Iterable[str] | None = None,
    ) -> list[Path]:
        paths: list[Path] = []
        if self.reporting.json_report:
            paths.append(self.export_json(findings))
        if self.reporting.txt:
            paths.append(self.export_txt(findings, target_url, scanned_urls))
        if self.reporting.html:
            paths.append(self.export_html(findings, target_url, scanned_urls))
        return paths

    def export_json(self, findings: Sequence[Finding]) -> Path:
        path = self.output_dir / "report.json"
        data = [finding.model_dump(mode="json") for finding in findings]
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        return path

    def export_txt(
        self,
        findings: Sequence[Finding],
        target_url: str | None = None,
        scanned_urls: Iterable[str] | None = None,
    ) -> Path:
        path = self.output_dir / "report.txt"
        lines = [
            "XSSAM SCAN REPORT",
            "=================",
            f"Generated: {datetime.now(UTC).isoformat(timespec='seconds')}",
            f"Target: {target_url or 'n/a'}",
            f"URLs visited: {len(list(scanned_urls or []))}",
            f"Findings: {len(findings)}",
            "",
        ]
        if not findings:
            lines.append("No potential or confirmed findings.")
        for finding in findings:
            lines.extend(
                [
                    f"Finding ID: {finding.finding_id}",
                    f"Status: {status_value(finding)}",
                    f"Severity: {finding.severity} (confidence: {finding.confidence})",
                    f"URL: {finding.target_url}",
                    f"Parameter: {finding.parameter.name} [{finding.parameter.location.value}]",
                    f"Context: {finding.context}",
                    f"Payload: {finding.payload.text}",
                    f"Rendered payload: {finding.rendered_payload}",
                    f"Proof URL: {finding.proof_url or 'n/a'}",
                ]
            )
            if finding.poc:
                lines.append(
                    f"POC method: {finding.poc.method}"
                    + (f" data={finding.poc.data}" if finding.poc.data else "")
                )
            if finding.evidence.get("screenshot"):
                lines.append(f"Screenshot: {finding.evidence['screenshot']}")
            lines.append("-" * 60)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def export_html(
        self,
        findings: Sequence[Finding],
        target_url: str | None = None,
        scanned_urls: Iterable[str] | None = None,
    ) -> Path:
        path = self.output_dir / "report.html"
        template = self.env.get_template("report.html")
        statuses = Counter(status_value(finding).upper() for finding in findings)
        rendered_findings = [self._finding_dict(finding) for finding in findings]
        html_content = template.render(
            findings=rendered_findings,
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            target_url=target_url or "n/a",
            scanned_url_count=len(list(scanned_urls or [])),
            total_findings=len(findings),
            confirmed=statuses["CONFIRMED"],
            potential=statuses["POTENTIAL"] + statuses["REFLECTED"],
        )
        path.write_text(html_content, encoding="utf-8")
        return path

    @staticmethod
    def _finding_dict(finding: Finding) -> dict:
        data = finding.model_dump(mode="json")
        status = status_value(finding)
        severity = str(finding.severity).lower()
        data["status"] = status
        data["status_class"] = status.lower()
        data["severity_class"] = severity
        return data
