import json
from pathlib import Path
from typing import List
from jinja2 import Environment, FileSystemLoader
from xssam.core.models import Finding

class ReportGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(loader=FileSystemLoader("xssam/reporting/templates"))

    def export_json(self, findings: List[Finding]):
        path = self.output_dir / "report.json"
        data = [f.model_dump() for f in findings]
        with open(path, "w") as f:
            json.dump(data, f, indent=4, default=str)

    def export_txt(self, findings: List[Finding]):
        path = self.output_dir / "report.txt"
        with open(path, "w") as f:
            f.write("XSSAM SCAN REPORT\n")
            f.write("=================\n\n")
            for find in findings:
                f.write(f"Finding ID: {find.finding_id}\n")
                f.write(f"Status: {find.status}\n")
                f.write(f"URL: {find.proof_url}\n")
                f.write(f"Parameter: {find.parameter.name}\n")
                f.write(f"Payload: {find.payload.text}\n")
                f.write("-" * 20 + "\n")

    def export_html(self, findings: List[Finding]):
        template = self.env.get_template("report.html")

        confirmed = len([f for f in findings if f.status == "CONFIRMED"])
        potential = len([f for f in findings if f.status == "POTENTIAL"])

        html_content = template.render(
            findings=findings,
            total_findings=len(findings),
            confirmed=confirmed,
            potential=potential
        )

        with open(self.output_dir / "report.html", "w") as f:
            f.write(html_content)
