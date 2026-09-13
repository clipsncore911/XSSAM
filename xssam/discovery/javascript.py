import re
from urllib.parse import urljoin
from typing import Set, List
import httpx
from bs4 import BeautifulSoup

class JSDiscoveryEngine:
    def __init__(self, client):
        self.client = client
        # Regex for finding URLs and API paths in JS files
        self.url_pattern = re.compile(r'["\'](https?://[^\s"\']+)["\']')
        self.path_pattern = re.compile(r'["\'](/[a-zA-Z0-9._/-]+)["\']')

    async def extract_endpoints(self, js_url: str) -> Set[str]:
        endpoints = set()
        response = await self.client.request("GET", js_url)
        if not response:
            return endpoints

        content = response.text

        # Find absolute URLs
        for match in self.url_pattern.finditer(content):
            endpoints.add(match.group(1))

        # Find relative paths
        for match in self.path_pattern.finditer(content):
            # Basic cleaning of paths
            path = match.group(1)
            if path.startswith("/"):
                # Convert to absolute URL (this is handled later by the crawler)
                endpoints.add(path)

        return endpoints

    def parse_html_for_js(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        js_files = []
        for script in soup.find_all("script", src=True):
            js_files.append(urljoin(base_url, script["src"]))
        return js_files
