"""
Pre-crawl discovery helpers for DAST scanning.

Provides three discovery mechanisms that run before the main BFS crawl:
  - SitemapParser — parses sitemap.xml / sitemap_index.xml
  - RobotsTxtParser — parses robots.txt for paths and sitemap refs
  - TechFingerprinter — detects server technology from HTTP signals
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from .crawler import TechFingerprint
from .http_client import DastHTTPClient

logger = logging.getLogger(__name__)

# Sitemap XML namespace
_SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Sitemap Parser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# Common sitemap paths to probe
_SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap.xml.gz",
]


class SitemapParser:
    """Parse XML sitemaps to discover URLs for crawling.

    Handles both ``<urlset>`` (direct URLs) and ``<sitemapindex>``
    (nested sitemaps) with a recursion depth limit.

    Args:
        client: HTTP client for fetching sitemaps.
        max_urls: Hard cap on total URLs returned.
    """

    def __init__(self, client: DastHTTPClient, max_urls: int = 2000):
        self.client = client
        self.max_urls = max_urls

    def discover(self, base_url: str) -> list[str]:
        """Probe common sitemap paths and return in-scope URLs."""
        all_urls: list[str] = []
        seen: set[str] = set()

        for path in _SITEMAP_PATHS:
            if len(all_urls) >= self.max_urls:
                break
            sitemap_url = urljoin(base_url, path)
            urls = self._parse_sitemap(sitemap_url, depth=0, seen=seen)
            all_urls.extend(urls)

        return all_urls[: self.max_urls]

    def discover_urls(self, sitemap_urls: list[str]) -> list[str]:
        """Parse explicit sitemap URLs (e.g. from robots.txt Sitemap: directives)."""
        all_urls: list[str] = []
        seen: set[str] = set()

        for url in sitemap_urls:
            if len(all_urls) >= self.max_urls:
                break
            urls = self._parse_sitemap(url, depth=0, seen=seen)
            all_urls.extend(urls)

        return all_urls[: self.max_urls]

    def _parse_sitemap(
        self, url: str, depth: int, seen: set[str],
    ) -> list[str]:
        """Recursively parse a sitemap URL."""
        if depth > 3:
            return []
        if url in seen:
            return []
        seen.add(url)

        try:
            resp = self.client.get(url, capture_evidence=False)
        except Exception:
            return []

        if resp.status_code != 200:
            return []

        content_type = resp.headers.get("Content-Type", "")
        if "xml" not in content_type and "text" not in content_type:
            return []

        return self._parse_xml(resp.text, depth, seen)

    def _parse_xml(
        self, xml_text: str, depth: int, seen: set[str],
    ) -> list[str]:
        """Parse XML and return in-scope page URLs."""
        urls: list[str] = []

        try:
            root = ET.fromstring(xml_text)  # noqa: S314
        except ET.ParseError:
            logger.debug("Failed to parse sitemap XML")
            return []

        # <sitemapindex> — nested sitemaps
        for sitemap_el in root.findall(f"{_SITEMAP_NS}sitemap"):
            loc_el = sitemap_el.find(f"{_SITEMAP_NS}loc")
            if loc_el is not None and loc_el.text:
                nested = self._parse_sitemap(
                    loc_el.text.strip(), depth + 1, seen,
                )
                urls.extend(nested)
                if len(urls) >= self.max_urls:
                    break

        # Also try without namespace (some sitemaps omit it)
        if not urls:
            for sitemap_el in root.findall("sitemap"):
                loc_el = sitemap_el.find("loc")
                if loc_el is not None and loc_el.text:
                    nested = self._parse_sitemap(
                        loc_el.text.strip(), depth + 1, seen,
                    )
                    urls.extend(nested)
                    if len(urls) >= self.max_urls:
                        break

        # <urlset> — direct URLs
        for url_el in root.findall(f"{_SITEMAP_NS}url"):
            loc_el = url_el.find(f"{_SITEMAP_NS}loc")
            if loc_el is not None and loc_el.text:
                page_url = loc_el.text.strip()
                if self.client.config.scope.is_url_in_scope(page_url):
                    urls.append(page_url)
                    if len(urls) >= self.max_urls:
                        break

        # Without namespace fallback
        if not any(f"{_SITEMAP_NS}" in (el.tag or "") for el in root):
            for url_el in root.findall("url"):
                loc_el = url_el.find("loc")
                if loc_el is not None and loc_el.text:
                    page_url = loc_el.text.strip()
                    if self.client.config.scope.is_url_in_scope(page_url):
                        urls.append(page_url)
                        if len(urls) >= self.max_urls:
                            break

        return urls


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Robots.txt Parser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@dataclass
class RobotsTxtResult:
    """Structured result from parsing robots.txt."""

    disallowed_paths: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    crawl_delay: float | None = None


class RobotsTxtParser:
    """Parse robots.txt to extract paths and sitemap references.

    Args:
        client: HTTP client for fetching robots.txt.
    """

    def __init__(self, client: DastHTTPClient):
        self.client = client

    def discover(self, base_url: str) -> RobotsTxtResult:
        """Fetch and parse /robots.txt."""
        result = RobotsTxtResult()
        robots_url = urljoin(base_url, "/robots.txt")

        try:
            resp = self.client.get(robots_url, capture_evidence=False)
        except Exception:
            return result

        if resp.status_code != 200:
            return result

        current_agent = ""
        for raw_line in resp.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            directive, _, value = line.partition(":")
            directive = directive.strip().lower()
            value = value.strip()

            if not value:
                continue

            if directive == "user-agent":
                current_agent = value.lower()

            elif directive == "disallow":
                # Collect from all user-agents (security interest)
                path = value.split("?")[0].split("#")[0]
                if path and path not in result.disallowed_paths:
                    result.disallowed_paths.append(path)

            elif directive == "allow":
                path = value.split("?")[0].split("#")[0]
                if path and path not in result.allowed_paths:
                    result.allowed_paths.append(path)

            elif directive == "sitemap":
                if value not in result.sitemap_urls:
                    result.sitemap_urls.append(value)

            elif directive == "crawl-delay":
                try:
                    # Only respect crawl-delay from * or our agent
                    if current_agent in ("*", ""):
                        result.crawl_delay = float(value)
                except ValueError:
                    pass

        return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Technology Fingerprinter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# Header → (regex, technology_name)
_SERVER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # (pattern, field_name_on_TechFingerprint, value_to_set)
    (re.compile(r"nginx", re.I), "server", "nginx"),
    (re.compile(r"apache", re.I), "server", "Apache"),
    (re.compile(r"Microsoft-IIS", re.I), "server", "IIS"),
    (re.compile(r"LiteSpeed", re.I), "server", "LiteSpeed"),
    (re.compile(r"Caddy", re.I), "server", "Caddy"),
    (re.compile(r"gunicorn", re.I), "server", "Gunicorn"),
    (re.compile(r"uvicorn", re.I), "server", "Uvicorn"),
]

_POWERED_BY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"PHP", re.I), "language", "PHP"),
    (re.compile(r"ASP\.NET", re.I), "language", "ASP.NET"),
    (re.compile(r"Express", re.I), "framework", "Express"),
    (re.compile(r"Servlet", re.I), "language", "Java"),
]

# Cookie name → (field, value)
_COOKIE_SIGNATURES: dict[str, tuple[str, str]] = {
    "PHPSESSID": ("language", "PHP"),
    "JSESSIONID": ("language", "Java"),
    "csrftoken": ("framework", "Django"),
    "django_language": ("framework", "Django"),
    "laravel_session": ("framework", "Laravel"),
    "connect.sid": ("framework", "Express"),
    "ASP.NET_SessionId": ("language", "ASP.NET"),
    "_rails_session": ("framework", "Rails"),
    "rack.session": ("framework", "Ruby/Rack"),
    "PLAY_SESSION": ("framework", "Play Framework"),
    "__cfduid": ("powered_by", "Cloudflare"),
}

# HTML body patterns → (field, value)
_BODY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"wp-content/", re.I), "cms", "WordPress"),
    (re.compile(r"wp-includes/", re.I), "cms", "WordPress"),
    (re.compile(r"/sites/default/files", re.I), "cms", "Drupal"),
    (re.compile(r"Drupal\.settings", re.I), "cms", "Drupal"),
    (re.compile(r"/media/jui/", re.I), "cms", "Joomla"),
    (re.compile(r"/static/admin/", re.I), "framework", "Django"),
    (re.compile(r"__NEXT_DATA__", re.I), "framework", "Next.js"),
    (re.compile(r"/_next/static/", re.I), "framework", "Next.js"),
    (re.compile(r"__NUXT__", re.I), "framework", "Nuxt.js"),
    (re.compile(r"data-reactroot", re.I), "framework", "React"),
    (re.compile(r"ng-app=", re.I), "framework", "Angular"),
    (re.compile(r"data-v-[a-f0-9]", re.I), "framework", "Vue.js"),
    (re.compile(r"ember-view", re.I), "framework", "Ember.js"),
]

# Meta generator patterns
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)

# Known paths to probe (path, field, value)
_PATH_PROBES: list[tuple[str, str, str]] = [
    ("/wp-login.php", "cms", "WordPress"),
    ("/wp-admin/", "cms", "WordPress"),
    ("/administrator/", "cms", "Joomla"),
    ("/user/login", "cms", "Drupal"),
    ("/admin/login/", "framework", "Django"),
    ("/elmah.axd", "language", "ASP.NET"),
    ("/web.config", "language", "ASP.NET"),
    ("/server-info", "server", "Apache"),
]


class TechFingerprinter:
    """Detect web technologies from HTTP response signals.

    Runs once during the crawl on the first HTML response to build
    a ``TechFingerprint``.  Does NOT create findings — the result is
    informational, stored on ``SiteMap.tech_fingerprint``.

    Args:
        client: HTTP client for optional HEAD probes.
    """

    def __init__(self, client: DastHTTPClient):
        self.client = client

    def fingerprint(
        self,
        target_url: str,
        headers: dict[str, str],
        body: str,
        cookies: dict[str, str] | None = None,
    ) -> TechFingerprint:
        """Build a fingerprint from response headers, body, and cookies."""
        fp = TechFingerprint()

        # --- Server header ---
        server_val = headers.get("Server", "")
        if server_val:
            fp.server = server_val
            fp.raw_evidence["Server"] = server_val
            for pat, fld, _val in _SERVER_PATTERNS:
                if pat.search(server_val):
                    setattr(fp, fld, server_val)
                    break

        # --- X-Powered-By ---
        powered = headers.get("X-Powered-By", "")
        if powered:
            fp.powered_by = powered
            fp.raw_evidence["X-Powered-By"] = powered
            for pat, fld, val in _POWERED_BY_PATTERNS:
                if pat.search(powered):
                    if not getattr(fp, fld):
                        setattr(fp, fld, val)
                    break

        # --- Cookies ---
        if cookies:
            for cookie_name, (fld, val) in _COOKIE_SIGNATURES.items():
                if cookie_name in cookies:
                    fp.cookies_hints.append(cookie_name)
                    if not getattr(fp, fld):
                        setattr(fp, fld, val)
                    fp.raw_evidence[f"cookie:{cookie_name}"] = val

        # --- Meta generator tag ---
        gen_match = _META_GENERATOR_RE.search(body[:10000])
        if gen_match:
            generator = gen_match.group(1).strip()
            fp.raw_evidence["meta:generator"] = generator
            gen_lower = generator.lower()
            if (
                any(kw in gen_lower for kw in ("wordpress", "drupal", "joomla"))
                or not fp.cms
            ):
                fp.cms = generator

        # --- Body patterns ---
        body_sample = body[:50000]
        js_fw_seen: set[str] = set()
        for pat, fld, val in _BODY_PATTERNS:
            if pat.search(body_sample):
                if fld == "framework" and val in (
                    "React", "Angular", "Vue.js", "Ember.js",
                    "Next.js", "Nuxt.js",
                ):
                    if val not in js_fw_seen:
                        js_fw_seen.add(val)
                        fp.js_frameworks.append(val)
                elif not getattr(fp, fld):
                    setattr(fp, fld, val)
                fp.raw_evidence[f"body:{val}"] = "pattern match"

        # --- Known path probes (HEAD, max 8) ---
        self._probe_paths(target_url, fp)

        # --- Infer language from framework/CMS if still unknown ---
        if not fp.language:
            fp.language = self._infer_language(fp)

        return fp

    def _probe_paths(self, target_url: str, fp: TechFingerprint) -> None:
        """HEAD-probe known paths to detect technology."""
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path, fld, val in _PATH_PROBES:
            probe_url = base + path
            try:
                resp = self.client.head(probe_url, capture_evidence=False)
            except Exception:
                continue
            if resp.status_code in (200, 301, 302, 403):
                if not getattr(fp, fld):
                    setattr(fp, fld, val)
                fp.raw_evidence[f"path:{path}"] = f"status={resp.status_code}"

    @staticmethod
    def _infer_language(fp: TechFingerprint) -> str:
        """Infer programming language from framework/CMS hints."""
        fw = (fp.framework or "").lower()
        cms = (fp.cms or "").lower()

        if "django" in fw or "flask" in fw:
            return "Python"
        if "laravel" in fw or "symfony" in fw:
            return "PHP"
        if "rails" in fw:
            return "Ruby"
        if "express" in fw or "next.js" in fw or "nuxt.js" in fw:
            return "Node.js"
        if "spring" in fw or "play" in fw:
            return "Java"
        if "wordpress" in cms or "drupal" in cms or "joomla" in cms:
            return "PHP"
        return ""
