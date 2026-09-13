import urllib.parse
import html
import base64
from typing import List

class PayloadMutator:
    @staticmethod
    def url_encode(text: str) -> str:
        return urllib.parse.quote(text)

    @staticmethod
    def html_encode(text: str) -> str:
        return html.escape(text)

    @staticmethod
    def double_url_encode(text: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(text))

    @staticmethod
    def js_escape(text: str) -> str:
        # Basic JS string escaping
        return text.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')

    @classmethod
    def mutate(cls, payload: str) -> List[str]:
        """Returns a list of mutated versions of the payload."""
        return [
            payload, # Raw
            cls.url_encode(payload),
            cls.html_encode(payload),
            cls.double_url_encode(payload),
            cls.js_escape(payload)
        ]
