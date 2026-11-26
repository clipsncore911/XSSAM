from __future__ import annotations

import re
import uuid
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from xssam.core.models import Payload

PAYLOAD_TOKEN = "__XSSAM_TOKEN__"

CONTEXT_GROUPS: dict[str, tuple[str, ...]] = {
    "html": ("html",),
    "attribute": ("attribute",),
    "javascript": ("javascript",),
    "dom": ("dom",),
    "svg": ("html",),
    "unknown": ("html",),
    "": ("html",),
}

DEFAULT_PAYLOADS: dict[str, list[dict[str, str]]] = {
    "html": [
        {
            "payload_id": "html_fallback_01",
            "text": "<script>alert('__XSSAM_TOKEN__')</script>",
            "purpose": "Basic script tag",
        },
        {
            "payload_id": "html_fallback_02",
            "text": "<img src=x onerror=\"alert('__XSSAM_TOKEN__')\">",
            "purpose": "Image error handler",
        },
        {
            "payload_id": "html_fallback_03",
            "text": "<svg onload=\"alert('__XSSAM_TOKEN__')\">",
            "purpose": "SVG load handler",
        },
    ],
    "attribute": [
        {
            "payload_id": "attribute_fallback_01",
            "text": "\" autofocus onfocus=\"alert('__XSSAM_TOKEN__')",
            "purpose": "Break a double-quoted attribute",
        }
    ],
    "javascript": [
        {
            "payload_id": "javascript_fallback_01",
            "text": "';alert('__XSSAM_TOKEN__');//",
            "purpose": "Break a single-quoted JavaScript string",
        }
    ],
    "dom": [
        {
            "payload_id": "dom_fallback_01",
            "text": "<img src=x onerror=\"alert('__XSSAM_TOKEN__')\">",
            "purpose": "DOM sink execution probe",
        }
    ],
}


class PayloadCorpus:
    """Load context-specific payloads from package data, tolerating bad files."""

    def __init__(self, directory: str | Path | None = None) -> None:
        self.directory = Path(directory) if directory else None
        self.payloads_by_context: dict[str, list[Payload]] = {}
        self.errors: list[str] = []
        self._load_payloads()
        self._ensure_defaults()

    def _iter_files(self) -> list[tuple[str, Any]]:
        if self.directory is not None:
            return [
                (path.name, path)
                for path in sorted(self.directory.glob("*"))
                if path.suffix.lower() in {".yaml", ".yml"}
            ]
        group_dir = resources.files("xssam.payloads").joinpath("groups")
        return [
            (entry.name, entry)
            for entry in sorted(group_dir.iterdir(), key=lambda item: item.name)
            if entry.name.lower().endswith((".yaml", ".yml"))
        ]

    def _load_payloads(self) -> None:
        for name, source in self._iter_files():
            try:
                with source.open("r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle) or {}
            except (OSError, yaml.YAMLError, UnicodeError) as exc:
                self.errors.append(f"{name}: {exc}")
                continue

            if not isinstance(data, dict):
                self.errors.append(f"{name}: top level must be a mapping")
                continue
            context = str(data.get("context") or "").strip().lower()
            payload_defs = data.get("payloads") or []
            if not context or not isinstance(payload_defs, list):
                # Empty placeholder files are valid and simply ignored.
                if data:
                    self.errors.append(f"{name}: missing context or payloads list")
                continue

            loaded: list[Payload] = []
            for index, item in enumerate(payload_defs):
                if not isinstance(item, dict):
                    self.errors.append(f"{name}: payload #{index + 1} is not a mapping")
                    continue
                normalized = dict(item)
                normalized.setdefault("context", context)
                normalized.setdefault("purpose", "")
                try:
                    loaded.append(Payload.model_validate(normalized))
                except Exception as exc:
                    self.errors.append(f"{name}: invalid payload #{index + 1}: {exc}")
            self.payloads_by_context.setdefault(context, []).extend(loaded)

    def _ensure_defaults(self) -> None:
        for context, definitions in DEFAULT_PAYLOADS.items():
            existing = self.payloads_by_context.get(context, [])
            existing_ids = {payload.payload_id for payload in existing}
            for definition in definitions:
                if definition["payload_id"] not in existing_ids:
                    existing.append(
                        Payload.model_validate({**definition, "context": context})
                    )
            self.payloads_by_context[context] = existing

    @staticmethod
    def render_payload(text: str, marker: str) -> str:
        return text.replace(PAYLOAD_TOKEN, marker)

    def get_payloads(self, context: str, marker: str | None = None) -> list[Payload]:
        groups = CONTEXT_GROUPS.get((context or "").lower(), CONTEXT_GROUPS["html"])
        payloads: list[Payload] = []
        for group in groups:
            payloads.extend(self.payloads_by_context.get(group, []))
        if not payloads:
            payloads = list(self.payloads_by_context["html"])

        result: list[Payload] = []
        for payload in payloads:
            text = self.render_payload(payload.text, marker) if marker else payload.text
            result.append(payload.model_copy(update={"text": text}))
        return result


class ContextAnalyzer:
    """Use a unique, alphanumeric canary to classify the reflection context."""

    def __init__(self, canary: str | None = None) -> None:
        self.canary = canary or f"xssam_canary_{uuid.uuid4().hex[:12]}"

    def is_reflected(self, response_text: str) -> bool:
        return self.canary in response_text

    def analyze(self, response_text: str) -> str:
        index = response_text.find(self.canary)
        if index < 0:
            return "unknown"

        before = response_text[:index]
        lower_before = before.lower()

        last_script_open = lower_before.rfind("<script")
        last_script_close = lower_before.rfind("</script")
        if last_script_open > last_script_close:
            return "javascript"

        tag_start = before.rfind("<")
        tag_end = before.rfind(">")
        if tag_start > tag_end:
            open_tag = before[tag_start:]
            # An equals sign followed by an optional quote means the canary is
            # likely inside an attribute value.
            if re.search(r"[\w:-]+\s*=\s*(['\"]?)[^'\"]*$", open_tag):
                return "attribute"

        return "html"
