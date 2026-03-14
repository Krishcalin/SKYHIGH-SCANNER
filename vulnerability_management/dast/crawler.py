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
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from .config import RequestLimitExceeded, ScopeViolation
from .http_client import DastHTTPClient

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Data structures
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class RedirectRecord:
    """A redirect chain recorded during crawling."""

    original_url: str
    final_url: str
    chain: list[tuple[int, str]] = field(default_factory=list)  # [(status, url)]
    total_hops: int = 0


@dataclass
class TechFingerprint:
    """Technology fingerprint detected from HTTP responses."""

    server: str = ""                 # e.g. "nginx/1.24.0"
    powered_by: str = ""             # e.g. "PHP/8.2"
    framework: str = ""              # e.g. "Django", "Laravel"
    cms: str = ""                    # e.g. "WordPress 6.4"
    language: str = ""               # e.g. "PHP", "Python"
    js_frameworks: list[str] = field(default_factory=list)
    cookies_hints: list[str] = field(default_factory=list)
    raw_evidence: dict[str, str] = field(default_factory=dict)

    def summary_line(self) -> str:
        """One-line summary for logging."""
        parts = []
        if self.server:
            parts.append(self.server)
        if self.framework:
            parts.append(self.framework)
        elif self.cms:
            parts.append(self.cms)
        if self.language:
            parts.append(self.language)
        return " | ".join(parts) if parts else "(unknown)"


@dataclass
class CrawlStats:
    """Statistics collected during a crawl."""

    start_time: float = 0.0
    end_time: float = 0.0
    pages_crawled: int = 0
    requests_sent: int = 0
    status_codes: dict[int, int] = field(default_factory=dict)
    content_types: dict[str, int] = field(default_factory=dict)
    redirect_count: int = 0
    forms_discovered: int = 0
    api_endpoints_discovered: int = 0
    sitemap_urls_added: int = 0
    robots_paths_added: int = 0

    @property
    def duration_seconds(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

    def record_response(self, status_code: int, content_type: str) -> None:
        """Record a response for statistics."""
        self.requests_sent += 1
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
        ct = content_type.split(";")[0].strip() if content_type else "unknown"
        self.content_types[ct] = self.content_types.get(ct, 0) + 1


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
    # Phase 5 — advanced crawling
    redirects: list[RedirectRecord] = field(default_factory=list)
    tech_fingerprint: TechFingerprint | None = None
    robots_disallowed: list[str] = field(default_factory=list)
    crawl_stats: CrawlStats = field(default_factory=CrawlStats)
    # Phase 8 — WAF detection
    waf_info: object | None = None

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
# Smart URL pattern tracker
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class _URLPatternTracker:
    """Groups URLs by path+param-name pattern to limit redundant crawling.

    For example ``/product?id=1&color=red`` and ``/product?id=2&color=blue``
    produce the same pattern key ``example.com:/product?color=&id=`` and only
    ``max_per_pattern`` unique value combinations are crawled.
    """

    def __init__(self, max_per_pattern: int = 3):
        self.max_per_pattern = max_per_pattern
        self._pattern_counts: dict[str, int] = {}

    def should_crawl(self, url: str) -> bool:
        """Return True if this URL's pattern hasn't exceeded the limit."""
        key = self._pattern_key(url)
        count = self._pattern_counts.get(key, 0)
        if count >= self.max_per_pattern:
            return False
        self._pattern_counts[key] = count + 1
        return True

    @staticmethod
    def _pattern_key(url: str) -> str:
        """Generate a pattern key: ``netloc:path?sorted_param_names``."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        if parsed.query:
            params = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
            param_sig = "&".join(f"{p}=" for p in params)
            return f"{parsed.netloc}:{path}?{param_sig}"
        return f"{parsed.netloc}:{path}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Web Crawler
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Safe values for form auto-submission discovery
_SAFE_FORM_VALUES: dict[str, str] = {
    "q": "test", "search": "test", "query": "test", "keyword": "test",
    "filter": "test", "s": "test", "term": "test",
    "category": "1", "page": "1", "sort": "name", "order": "asc",
    "limit": "10", "offset": "0", "type": "all", "lang": "en",
}

# Field names that indicate a search/filter form (safe to submit)
_SEARCH_FIELD_NAMES = frozenset({
    "q", "query", "search", "keyword", "term", "s", "filter",
    "category", "sort", "order", "page", "limit", "type",
})


class WebCrawler:
    """Breadth-first web crawler with scope enforcement.

    Phase 5 enhancements:
      - Pre-crawl discovery via sitemap.xml and robots.txt
      - Smart URL deduplication (pattern-based)
      - Redirect chain tracking
      - Form auto-submission for discovery
      - Technology fingerprinting
      - Enhanced crawl statistics

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

    MAX_FORM_SUBMISSIONS = 20  # Cap on discovery form submissions

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

        Flow:
          1. Pre-crawl discovery (robots.txt, sitemap.xml)
          2. BFS loop with pattern tracking + redirect following
          3. Post-crawl form auto-submission
        """
        import time as _time

        from .discovery import RobotsTxtParser, SitemapParser, TechFingerprinter

        sitemap = SiteMap()
        stats = sitemap.crawl_stats
        stats.start_time = _time.monotonic()

        visited: set[str] = set()
        pattern_tracker = _URLPatternTracker()
        queue: list[tuple[str, int]] = [(seed_url, 0)]

        # ── Pre-crawl discovery ──────────────────────────────────
        try:
            robots = RobotsTxtParser(self.client).discover(seed_url)
            sitemap.robots_disallowed = robots.disallowed_paths
            stats.robots_paths_added = len(robots.disallowed_paths)

            # Seed queue with robots.txt Disallow paths (security-interesting)
            parsed_seed = urlparse(seed_url)
            base = f"{parsed_seed.scheme}://{parsed_seed.netloc}"
            for path in robots.disallowed_paths:
                full_url = base + path
                if self.client.config.scope.is_url_in_scope(full_url):
                    queue.append((full_url, 1))

            # Parse sitemaps (from robots.txt Sitemap: + standard paths)
            sm_parser = SitemapParser(self.client)
            sitemap_urls: list[str] = []
            if robots.sitemap_urls:
                sitemap_urls.extend(sm_parser.discover_urls(robots.sitemap_urls))
            sitemap_urls.extend(sm_parser.discover(seed_url))

            # Deduplicate and add to queue
            seen_sm: set[str] = set()
            for sm_url in sitemap_urls:
                if sm_url not in seen_sm:
                    seen_sm.add(sm_url)
                    queue.append((sm_url, 1))
            stats.sitemap_urls_added = len(seen_sm)

            if self.verbose and seen_sm:
                logger.debug(
                    "Pre-crawl: %d URLs from sitemaps, %d paths from robots.txt",
                    len(seen_sm), len(robots.disallowed_paths),
                )
        except (ScopeViolation, RequestLimitExceeded):
            pass
        except Exception as exc:
            logger.debug("Pre-crawl discovery error: %s", exc)

        # ── BFS crawl loop ───────────────────────────────────────
        fingerprinted = False
        fingerprinter = None

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

            # Smart pattern dedup
            if not pattern_tracker.should_crawl(url):
                continue

            visited.add(normalized)

            # Check if this is a static resource
            if self._is_static(url):
                sitemap.static_resources.add(url)
                continue

            # Check scope
            if not self.client.config.scope.is_url_in_scope(url):
                continue

            # Fetch the page (with redirect tracking)
            try:
                resp, redirect_rec = self._follow_redirects(url, sitemap)
            except (ScopeViolation, RequestLimitExceeded):
                break
            except Exception as e:
                logger.debug("Crawl fetch failed for %s: %s", url, e)
                continue

            # Record stats
            content_type = resp.headers.get("Content-Type", "")
            stats.record_response(resp.status_code, content_type)

            if "text/html" not in content_type and "application/xhtml" not in content_type:
                # Not HTML — might be an API endpoint
                if "application/json" in content_type:
                    sitemap.api_endpoints.append(
                        APIEndpoint(url=url, source="crawl"),
                    )
                    stats.api_endpoints_discovered += 1
                continue

            sitemap.urls.add(url)
            stats.pages_crawled += 1

            if self.verbose:
                logger.debug("Crawled [%d]: %s (%d bytes)", depth, url, len(resp.text))

            # Technology fingerprinting (once on first HTML response)
            if not fingerprinted:
                fingerprinted = True
                try:
                    fingerprinter = TechFingerprinter(self.client)
                    cookies = {
                        c.name: c.value
                        for c in self.client._session.cookies  # noqa: SLF001
                    }
                    sitemap.tech_fingerprint = fingerprinter.fingerprint(
                        seed_url, dict(resp.headers), resp.text, cookies,
                    )
                except Exception as exc:
                    logger.debug("Fingerprinting error: %s", exc)

            # Parse the HTML
            try:
                parser = _LinkFormParser(url)
                parser.feed(resp.text)
            except Exception:
                continue

            # Collect forms
            for form in parser.forms:
                sitemap.forms.append(form)
                stats.forms_discovered += 1

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
                        stats.record_response(
                            js_resp.status_code,
                            js_resp.headers.get("Content-Type", ""),
                        )
                        if js_resp.status_code == 200:
                            endpoints = _extract_js_endpoints(
                                js_resp.text, seed_url,
                            )
                            sitemap.api_endpoints.extend(endpoints)
                            stats.api_endpoints_discovered += len(endpoints)
                    except (ScopeViolation, RequestLimitExceeded):
                        break
                    except Exception:
                        continue

        # ── Post-crawl: form auto-submission ─────────────────────
        self._submit_discovery_forms(sitemap, visited, queue, seed_url)

        stats.end_time = _time.monotonic()
        return sitemap

    # ─── Redirect chain tracking ─────────────────────────────────

    def _follow_redirects(
        self,
        url: str,
        sitemap: SiteMap,
        max_hops: int = 10,
    ) -> tuple:
        """Follow redirects manually, recording the chain.

        Returns:
            (final_response, RedirectRecord | None)
        """
        chain: list[tuple[int, str]] = []
        current_url = url
        hop_visited: set[str] = set()

        for _ in range(max_hops):
            if current_url in hop_visited:
                break  # Redirect loop
            hop_visited.add(current_url)

            resp = self.client.request(
                "GET", current_url,
                capture_evidence=False,
                allow_redirects=False,
            )

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                resolved = urljoin(current_url, location)
                chain.append((resp.status_code, current_url))

                # Scope-check the redirect target
                if not self.client.config.scope.is_url_in_scope(resolved):
                    # Record truncated chain and return current response
                    record = RedirectRecord(
                        original_url=url,
                        final_url=resolved,
                        chain=chain,
                        total_hops=len(chain),
                    )
                    sitemap.redirects.append(record)
                    sitemap.crawl_stats.redirect_count += 1
                    return resp, record

                current_url = resolved
            else:
                # Final destination reached
                if chain:
                    chain.append((resp.status_code, current_url))
                    record = RedirectRecord(
                        original_url=url,
                        final_url=current_url,
                        chain=chain,
                        total_hops=len(chain) - 1,
                    )
                    sitemap.redirects.append(record)
                    sitemap.crawl_stats.redirect_count += 1
                    return resp, record
                return resp, None

        # Max hops or loop — return last response
        if chain:
            record = RedirectRecord(
                original_url=url,
                final_url=current_url,
                chain=chain,
                total_hops=len(chain),
            )
            sitemap.redirects.append(record)
            sitemap.crawl_stats.redirect_count += 1
            return resp, record
        return resp, None

    # ─── Form auto-submission for discovery ──────────────────────

    def _submit_discovery_forms(
        self,
        sitemap: SiteMap,
        visited: set[str],
        queue: list[tuple[str, int]],
        seed_url: str,
    ) -> None:
        """Submit safe discovery forms (search, filter) to find new pages."""
        submitted = 0

        for form in sitemap.forms:
            if submitted >= self.MAX_FORM_SUBMISSIONS:
                break

            # Skip login forms (have password fields)
            if any(f.field_type == "password" for f in form.fields):
                continue
            # Skip file upload forms
            if form.has_file_upload:
                continue

            # Only submit GET forms or forms with search-like fields
            field_names = {f.name.lower() for f in form.fields if f.name}
            is_search = bool(field_names & _SEARCH_FIELD_NAMES)
            if form.method != "GET" and not is_search:
                continue

            # Build form data with safe values
            form_data: dict[str, str] = {}
            for f in form.fields:
                if not f.name:
                    continue
                name_lower = f.name.lower()
                if f.field_type == "hidden" and f.value:
                    form_data[f.name] = f.value
                elif name_lower in _SAFE_FORM_VALUES:
                    form_data[f.name] = _SAFE_FORM_VALUES[name_lower]
                else:
                    form_data[f.name] = "test"

            # Submit the form
            try:
                if form.method == "GET":
                    qs = urlencode(form_data)
                    submit_url = f"{form.action}?{qs}" if qs else form.action
                    resp = self.client.get(submit_url, capture_evidence=False)
                else:
                    resp = self.client.post_form(
                        form.action, form_data, capture_evidence=False,
                    )
                submitted += 1
            except (ScopeViolation, RequestLimitExceeded):
                break
            except Exception:
                continue

            # Parse response for new links
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            try:
                parser = _LinkFormParser(form.action)
                parser.feed(resp.text)
            except Exception:
                continue

            for link in parser.links:
                link_normalized = self._normalize_url(link)
                if link_normalized not in visited:
                    visited.add(link_normalized)
                    if self.client.config.scope.is_url_in_scope(link):
                        sitemap.urls.add(link)

    # ─── URL normalization ───────────────────────────────────────

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication.

        Strips fragment, normalizes trailing slash, preserves and sorts
        query parameters for consistent deduplication.
        """
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            params = sorted(
                parse_qs(parsed.query, keep_blank_values=True).items(),
            )
            normalized += "?" + urlencode(params, doseq=True)
        return normalized

    def _is_static(self, url: str) -> bool:
        """Check if URL points to a static resource."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in self.STATIC_EXTENSIONS)
