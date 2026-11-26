from __future__ import annotations

import html
import re
import urllib.parse
from collections.abc import Iterable


class PayloadMutator:
    """Generate a small set of executable payload variants.

    URL encoding is intentionally left to the HTTP/URL layer: pre-encoding a
    query value caused double encoding and non-reproducible proof URLs.
    """

    @staticmethod
    def url_encode(text: str) -> str:
        return urllib.parse.quote(text)

    @staticmethod
    def double_url_encode(text: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(text))

    @staticmethod
    def html_encode(text: str) -> str:
        return html.escape(text)

    @staticmethod
    def js_escape(text: str) -> str:
        return (
            text.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace('"', '\\"')
        )

    @staticmethod
    def case_variant(text: str) -> str:
        text = re.sub(
            r"(<\s*)([A-Za-z]+)",
            lambda match: match.group(1) + match.group(2).swapcase(),
            text,
        )
        return re.sub(
            r"\bon(error|load|focus|toggle)\b",
            lambda match: match.group(0).upper(),
            text,
            flags=re.IGNORECASE,
        )

    @classmethod
    def mutate(cls, payload: str) -> list[str]:
        variants: Iterable[str] = (
            payload,
            cls.case_variant(payload),
            cls.js_escape(payload),
        )
        # dict preserves insertion order while removing exact duplicates.
        return [variant for variant in dict.fromkeys(variants) if variant]
