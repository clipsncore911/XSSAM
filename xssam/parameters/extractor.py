from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

from bs4 import BeautifulSoup

from xssam.core.models import Parameter, ParameterLocation

DYNAMIC_PATH_SEGMENT = re.compile(
    r"(?:^\d+$|^[0-9a-fA-F-]{8,}$|=|(?:^|[-_])(?:id|slug|token|key)(?:$|[-_]))",
    re.IGNORECASE,
)


class ParameterExtractor:
    def __init__(self) -> None:
        self.interesting_headers = [
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Forwarded-Host",
        ]

    @staticmethod
    def _dedupe(params: list[Parameter]) -> list[Parameter]:
        seen: set[tuple[str, str, str, str]] = set()
        unique: list[Parameter] = []
        for param in params:
            key = (
                param.name,
                param.location.value,
                param.method.upper(),
                param.action_url or "",
            )
            if key not in seen:
                seen.add(key)
                unique.append(param)
        return unique

    def extract_from_url(self, url: str) -> list[Parameter]:
        params: list[Parameter] = []
        parsed = urlsplit(url)

        for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
            params.append(
                Parameter(
                    name=name,
                    value=str(values[0]) if values else "",
                    location=ParameterLocation.QUERY,
                    discovery_source="URL query string",
                )
            )

        # Only path segments that look dynamic are probed. Treating every word
        # in a route as a parameter produced noisy requests to invalid paths.
        for index, segment in enumerate(parsed.path.split("/")):
            if segment and DYNAMIC_PATH_SEGMENT.search(segment) and "." not in segment:
                params.append(
                    Parameter(
                        name=f"path_segment_{index}",
                        value=segment,
                        location=ParameterLocation.PATH,
                        discovery_source="URL path",
                    )
                )

        if parsed.fragment:
            fragment_params = parse_qs(parsed.fragment, keep_blank_values=True)
            if fragment_params:
                for name, values in fragment_params.items():
                    params.append(
                        Parameter(
                            name=name,
                            value=str(values[0]) if values else "",
                            location=ParameterLocation.FRAGMENT,
                            discovery_source="URL fragment",
                        )
                    )
            else:
                params.append(
                    Parameter(
                        name="fragment",
                        value=parsed.fragment,
                        location=ParameterLocation.FRAGMENT,
                        discovery_source="URL fragment",
                    )
                )

        return self._dedupe(params)

    def extract_from_html(self, html: str, url: str) -> list[Parameter]:
        params: list[Parameter] = []
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            method = str(form.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                method = "GET"
            action_url = urljoin(url, str(form.get("action") or ""))
            location = ParameterLocation.FORM if method == "POST" else ParameterLocation.QUERY

            for tag in form.find_all(["input", "textarea", "select", "button"]):
                name = tag.get("name")
                if not name:
                    continue
                if tag.name == "input" and str(tag.get("type") or "").lower() in {
                    "submit",
                    "reset",
                    "button",
                    "image",
                }:
                    continue

                value: Any = tag.get("value", "")
                if not value and tag.name == "select":
                    option = tag.find("option", value=True)
                    value = option.get("value", "") if option else ""
                params.append(
                    Parameter(
                        name=str(name),
                        value=str(value or ""),
                        location=location,
                        discovery_source="HTML form",
                        method=method,
                        action_url=action_url,
                    )
                )

        return self._dedupe(params)

    def extract_from_headers(self, headers: dict[str, Any] | None = None) -> list[Parameter]:
        headers = headers or {}
        params: list[Parameter] = []
        for header in self.interesting_headers:
            if headers and header not in headers:
                continue
            params.append(
                Parameter(
                    name=header,
                    value=str(headers.get(header, "")),
                    location=ParameterLocation.HEADER,
                    discovery_source="HTTP header",
                )
            )
        return params
