"""
Web crawler / spider for DAST target discovery.

Crawls a web application from a seed URL to discover:
  - Pages and URLs
  - HTML forms (with fields, action URLs, methods)
  - API endpoints (from JavaScript, OpenAPI, links)
  - Static resources (for completeness)

The crawler respects the ScopePolicy, rate limits, and max depth.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .config import RequestLimitExceeded, ScopeViolation
from .http_client import DastHTTPClient

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Data structures
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class FormField:
    """An input field within an HTML form."""

    name: str
    field_type: str = "text"      # text, password, hidden, email, etc.
    value: str = ""               # Default value (for hidden fields)


@dataclass
class FormInfo:
    """Metadata about an HTML form discovered during crawling."""

    url: str                       # Page URL where form was found
    action: str                    # Form action URL (resolved)
    method: str = "GET"            # GET or POST
    fields: list[FormField] = field(default_factory=list)
    has_file_upload: bool = False   # True if form has <input type="file">

    @property
    def field_names(self) -> list[str]:
        return [f.name for f in self.fields if f.name]


@dataclass
class APIEndpoint:
    """An API endpoint discovered from JavaScript or OpenAPI."""

    url: str
    method: str = "GET"
    source: str = ""               # Where it was discovered (JS file, OpenAPI, etc.)


@dataclass
class SiteMap:
    """Aggregated crawl results."""

    urls: set[str] = field(default_factory=set)
    forms: list[FormInfo] = field(default_factory=list)
    api_endpoints: list[APIEndpoint] = field(default_factory=list)
    static_resources: set[str] = field(default_factory=set)

    @property
    def total_discovered(self) -> int:
        return len(self.urls) + len(self.forms) + len(self.api_endpoints)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTML link & form parser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class _LinkFormParser(HTMLParser):
    """Extract links and forms from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[FormInfo] = []
        self.scripts: list[str] = []

        # Form parsing state
        self._in_form = False
        self._current_form: FormInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower == "a":
            href = attr_dict.get("href")
            if href:
                resolved = urljoin(self.base_url, href)
                self.links.append(resolved)

        elif tag_lower == "form":
            action = attr_dict.get("action", "")
            resolved_action = urljoin(self.base_url, action) if action else self.base_url
            method = (attr_dict.get("method") or "GET").upper()
            self._current_form = FormInfo(
                url=self.base_url,
                action=resolved_action,
                method=method,
            )
            self._in_form = True

        elif tag_lower == "input" and self._in_form and self._current_form:
            name = attr_dict.get("name", "")
            input_type = (attr_dict.get("type") or "text").lower()
            value = attr_dict.get("value", "")
            if input_type == "file":
                self._current_form.has_file_upload = True
            if name:
                self._current_form.fields.append(
                    FormField(name=name, field_type=input_type, value=value)
                )

        elif tag_lower == "textarea" and self._in_form and self._current_form:
            name = attr_dict.get("name", "")
            if name:
                self._current_form.fields.append(
                    FormField(name=name, field_type="textarea")
                )

        elif tag_lower == "select" and self._in_form and self._current_form:
            name = attr_dict.get("name", "")
            if name:
                self._current_form.fields.append(
                    FormField(name=name, field_type="select")
                )

        elif tag_lower == "script":
            src = attr_dict.get("src")
            if src:
                self.scripts.append(urljoin(self.base_url, src))

        elif tag_lower in ("link", "img", "iframe"):
            src = attr_dict.get("href") or attr_dict.get("src")
            if src:
                resolved = urljoin(self.base_url, src)
                self.links.append(resolved)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None
            self._in_form = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# API endpoint extraction from JavaScript
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Patterns to find URL-like strings in JavaScript
_JS_URL_PATTERNS = [
    # fetch("/api/users") or fetch('/api/users')
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["']([/][^"']+)["']"""),
    # url: "/api/endpoint"
    re.compile(r"""url\s*:\s*["']([/][^"']+)["']"""),
    # XMLHttpRequest.open("GET", "/api/...")
    re.compile(r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([/][^"']+)["']"""),
    # "/api/v1/..." string literals that look like API paths
    re.compile(r"""["'](/api/[^"']{3,})["']"""),
]


def _extract_js_endpoints(js_content: str, base_url: str) -> list[APIEndpoint]:
    """Extract API endpoint paths from JavaScript source code."""
    endpoints = []
    seen = set()

    for pattern in _JS_URL_PATTERNS:
        for match in pattern.finditer(js_content):
            path = match.group(1)
            if path not in seen:
                seen.add(path)
                full_url = urljoin(base_url, path)
                endpoints.append(APIEndpoint(url=full_url, source="javascript"))

    return endpoints


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Web Crawler
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class WebCrawler:
    """Breadth-first web crawler with scope enforcement.

    Args:
        client: The DastHTTPClient to use for requests.
        max_depth: Maximum crawl depth (overrides config.scope.max_depth
            if provided).
        max_pages: Maximum pages to crawl before stopping.
        verbose: Enable verbose logging.
    """

    # Extensions that indicate non-HTML content
    STATIC_EXTENSIONS = frozenset({
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".webp", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
        ".gz", ".tar", ".mp4", ".mp3", ".avi", ".mov", ".map",
    })

    def __init__(
        self,
        client: DastHTTPClient,
        max_depth: int | None = None,
        max_pages: int = 500,
        verbose: bool = False,
    ):
        self.client = client
        self.max_depth = max_depth or client.config.scope.max_depth
        self.max_pages = max_pages
        self.verbose = verbose

    def crawl(self, seed_url: str) -> SiteMap:
        """Crawl starting from seed_url and return the discovered site map.

        Uses breadth-first search with depth tracking.
        """
        sitemap = SiteMap()
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(seed_url, 0)]  # (url, depth)

        while queue:
            url, depth = queue.pop(0)

            # Skip if already visited, too deep, or page limit reached
            normalized = self._normalize_url(url)
            if normalized in visited:
                continue
            if depth > self.max_depth:
                continue
            if len(visited) >= self.max_pages:
                logger.info("Crawl page limit (%d) reached", self.max_pages)
                break

            visited.add(normalized)

            # Check if this is a static resource
            if self._is_static(url):
                sitemap.static_resources.add(url)
                continue

            # Check scope
            if not self.client.config.scope.is_url_in_scope(url):
                continue

            # Fetch the page
            try:
                resp = self.client.get(url, capture_evidence=False)
            except (ScopeViolation, RequestLimitExceeded):
                break
            except Exception as e:
                logger.debug("Crawl fetch failed for %s: %s", url, e)
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                # Not HTML — might be an API endpoint
                if "application/json" in content_type:
                    sitemap.api_endpoints.append(
                        APIEndpoint(url=url, source="crawl")
                    )
                continue

            sitemap.urls.add(url)

            if self.verbose:
                logger.debug("Crawled [%d]: %s (%d bytes)", depth, url, len(resp.text))

            # Parse the HTML
            try:
                parser = _LinkFormParser(url)
                parser.feed(resp.text)
            except Exception:
                continue

            # Collect forms
            for form in parser.forms:
                sitemap.forms.append(form)

            # Queue discovered links
            for link in parser.links:
                link_normalized = self._normalize_url(link)
                if link_normalized not in visited:
                    queue.append((link, depth + 1))

            # Fetch and parse JavaScript files for API endpoints
            for script_url in parser.scripts:
                if script_url not in visited:
                    visited.add(self._normalize_url(script_url))
                    sitemap.static_resources.add(script_url)
                    try:
                        js_resp = self.client.get(
                            script_url, capture_evidence=False,
                        )
                        if js_resp.status_code == 200:
                            endpoints = _extract_js_endpoints(
                                js_resp.text, seed_url,
                            )
                            sitemap.api_endpoints.extend(endpoints)
                    except (ScopeViolation, RequestLimitExceeded):
                        break
                    except Exception:
                        continue

        return sitemap

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication (strip fragment, trailing slash)."""
        parsed = urlparse(url)
        # Remove fragment
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"
        # Intentionally ignore query string for dedup — different params
        # are different pages for DAST purposes

    def _is_static(self, url: str) -> bool:
        """Check if URL points to a static resource."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in self.STATIC_EXTENSIONS)
