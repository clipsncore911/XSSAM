import yaml
from pathlib import Path
from typing import List, Dict
from xssam.core.models import Payload

class PayloadCorpus:
    def __init__(self):
        self.payloads_by_context: Dict[str, List[Payload]] = {}
        self._load_payloads()

    def _load_payloads(self):
        payloads_dir = Path("xssam/payloads/groups")
        for yaml_file in payloads_dir.glob("*.yaml"):
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
                context = data["context"]
                payload_list = [Payload(**p) for p in data["payloads"]]
                self.payloads_by_context[context] = payload_list

    def get_payloads(self, context: str) -> List[Payload]:
        return self.payloads_by_context.get(context, self.payloads_by_context.get("html", []))

class ContextAnalyzer:
    def __init__(self):
        self.canary = "xssam_canary_123"

    def analyze(self, response_text: str) -> str:
        if self.canary not in response_text:
            return "unknown"

        idx = response_text.find(self.canary)

        # Simple context heuristics
        before = response_text[max(0, idx-20):idx]
        after = response_text[idx+len(self.canary):idx+len(self.canary)+20]

        if "<script" in before.lower() or "javascript:" in before.lower():
            return "javascript"
        if '="' in before or "='" in before:
            return "attribute"
        if "<" in before and ">" in after:
            return "html"

        return "html" # Default
