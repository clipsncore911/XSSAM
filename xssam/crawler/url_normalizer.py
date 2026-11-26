from __future__ import annotations

from urllib.parse import SplitResult, urlsplit, urlunsplit

HTTP_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}


def default_port(scheme: str) -> int | None:
    return DEFAULT_PORTS.get(scheme.lower())


def normalize_url(url: str, *, strip_fragment: bool = True) -> str | None:
    """Return a canonical, deduplication-friendly absolute HTTP(S) URL.

    Returns ``None`` for non-HTTP schemes, URLs containing credentials, or
    malformed ports. Fragments are stripped by default because they are not
    sent to the server and otherwise create duplicate crawl items.
    """
    try:
        parts = urlsplit(str(url).strip())
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in HTTP_SCHEMES or parts.username or parts.password:
        return None

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not hostname:
        return None

    hostname = hostname.rstrip(".").lower()
    host_for_netloc = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_for_netloc
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc = f"{host_for_netloc}:{port}"

    path = parts.path or "/"
    fragment = "" if strip_fragment else parts.fragment
    return urlunsplit((scheme, netloc, path, parts.query, fragment))


def is_http_url(url: str) -> bool:
    return normalize_url(url) is not None


def effective_port(parts: SplitResult) -> int | None:
    """Return the effective port of a normalized URL split result."""
    try:
        return parts.port or default_port(parts.scheme.lower())
    except ValueError:
        return None
