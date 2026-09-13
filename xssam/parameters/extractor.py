import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from xssam.core.models import Parameter, ParameterLocation

class ParameterExtractor:
    def __init__(self):
        # Common header names to check for XSS
        self.interesting_headers = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"]

    def extract_from_url(self, url: str) -> List[Parameter]:
        params = []
        parsed = urlparse(url)

        # 1. Query Parameters
        query_params = parse_qs(parsed.query)
        for name, values in query_params.items():
            params.append(Parameter(
                name=name,
                value=values[0],
                location=ParameterLocation.QUERY,
                discovery_source="URL Query String"
            ))

        # 2. Path Parameters (Simplistic approach: check for segments that look like IDs/slugs)
        path_segments = parsed.path.split("/")
        for i, segment in enumerate(path_segments):
            if segment and not segment.isdigit() and len(segment) > 3:
                # This is a heuristic; in a real tool, we might compare with other URLs
                params.append(Parameter(
                    name=f"path_segment_{i}",
                    value=segment,
                    location=ParameterLocation.PATH,
                    discovery_source="URL Path"
                ))

        return params

    def extract_from_html(self, html: str, url: str) -> List[Parameter]:
        params = []
        soup = BeautifulSoup(html, "html.parser")

        # 3. Form Parameters
        for form in soup.find_all("form"):
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if name:
                    params.append(Parameter(
                        name=name,
                        value=input_tag.get("value", ""),
                        location=ParameterLocation.FORM,
                        discovery_source="HTML Form"
                    ))

        return params

    def extract_from_headers(self, headers: Dict[str, Any]) -> List[Parameter]:
        params = []
        for header in self.interesting_headers:
            if header in headers:
                params.append(Parameter(
                    name=header,
                    value=headers[header],
                    location=ParameterLocation.HEADER,
                    discovery_source="HTTP Header"
                ))
        return params
