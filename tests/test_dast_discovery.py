"""
Tests for Phase 5 — DAST discovery module.

Verifies:
  - SitemapParser: XML parsing, nested sitemaps, scope filtering, limits
  - RobotsTxtParser: directive parsing, sitemap extraction, crawl-delay
  - TechFingerprinter: header, cookie, body, meta generator detection
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vulnerability_management.dast.config import DastConfig, ScopePolicy
from vulnerability_management.dast.crawler import TechFingerprint
from vulnerability_management.dast.discovery import (
    RobotsTxtParser,
    SitemapParser,
    TechFingerprinter,
)
from vulnerability_management.dast.http_client import DastHTTPClient

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _make_client(hosts=None):
    config = DastConfig(
        scope=ScopePolicy(allowed_hosts=hosts or ["example.com"]),
        rate_limit_rps=1000.0,
        max_requests=5000,
    )
    return DastHTTPClient(config=config)


def _mock_resp(text, status=200, content_type="text/xml"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = {"Content-Type": content_type}
    resp.request = MagicMock()
    resp.request.headers = {}
    return resp


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SitemapParser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSitemapParser:
    """XML sitemap parsing tests."""

    def test_parse_urlset(self):
        """Parse a standard <urlset> sitemap."""
        client = _make_client()
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/page1</loc></url>
          <url><loc>https://example.com/page2</loc></url>
          <url><loc>https://example.com/page3</loc></url>
        </urlset>"""

        def side_effect(method, url, **kwargs):
            if "sitemap.xml" in url:
                return _mock_resp(xml)
            return _mock_resp("", status=404)

        with patch.object(client._session, "request", side_effect=side_effect):
            parser = SitemapParser(client)
            urls = parser.discover("https://example.com")

        assert len(urls) == 3
        assert "https://example.com/page1" in urls
        assert "https://example.com/page2" in urls

    def test_parse_sitemapindex(self):
        """Parse a <sitemapindex> with nested sitemaps."""
        client = _make_client()
        index_xml = """<?xml version="1.0"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>
        </sitemapindex>"""

        posts_xml = """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/post/1</loc></url>
          <url><loc>https://example.com/post/2</loc></url>
        </urlset>"""

        def side_effect(method, url, **kwargs):
            if "sitemap-posts" in url:
                return _mock_resp(posts_xml)
            if "sitemap.xml" in url:
                return _mock_resp(index_xml)
            return _mock_resp("", status=404)

        with patch.object(client._session, "request", side_effect=side_effect):
            parser = SitemapParser(client)
            urls = parser.discover("https://example.com")

        assert len(urls) == 2
        assert "https://example.com/post/1" in urls

    def test_scope_filtering(self):
        """Out-of-scope URLs are excluded."""
        client = _make_client(hosts=["example.com"])
        xml = """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/ok</loc></url>
          <url><loc>https://evil.com/bad</loc></url>
        </urlset>"""

        def side_effect(method, url, **kwargs):
            if "sitemap.xml" in url:
                return _mock_resp(xml)
            return _mock_resp("", status=404)

        with patch.object(client._session, "request", side_effect=side_effect):
            parser = SitemapParser(client)
            urls = parser.discover("https://example.com")

        assert len(urls) == 1
        assert "https://example.com/ok" in urls

    def test_max_urls_limit(self):
        """Hard cap on discovered URLs."""
        client = _make_client()
        entries = "\n".join(
            f"<url><loc>https://example.com/p/{i}</loc></url>"
            for i in range(100)
        )
        xml = f"""<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          {entries}
        </urlset>"""

        def side_effect(method, url, **kwargs):
            if "sitemap.xml" in url:
                return _mock_resp(xml)
            return _mock_resp("", status=404)

        with patch.object(client._session, "request", side_effect=side_effect):
            parser = SitemapParser(client, max_urls=10)
            urls = parser.discover("https://example.com")

        assert len(urls) <= 10

    def test_malformed_xml(self):
        """Malformed XML returns empty list, no crash."""
        client = _make_client()

        def side_effect(method, url, **kwargs):
            if "sitemap.xml" in url:
                return _mock_resp("<not valid xml>>><<<")
            return _mock_resp("", status=404)

        with patch.object(client._session, "request", side_effect=side_effect):
            parser = SitemapParser(client)
            urls = parser.discover("https://example.com")

        assert urls == []

    def test_404_returns_empty(self):
        """Missing sitemap returns empty list."""
        client = _make_client()

        def side_effect(method, url, **kwargs):
            return _mock_resp("", status=404)

        with patch.object(client._session, "request", side_effect=side_effect):
            parser = SitemapParser(client)
            urls = parser.discover("https://example.com")

        assert urls == []

    def test_discover_urls_explicit(self):
        """discover_urls() parses explicit sitemap URLs."""
        client = _make_client()
        xml = """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/explicit</loc></url>
        </urlset>"""

        def side_effect(method, url, **kwargs):
            return _mock_resp(xml)

        with patch.object(client._session, "request", side_effect=side_effect):
            parser = SitemapParser(client)
            urls = parser.discover_urls(["https://example.com/custom-sitemap.xml"])

        assert "https://example.com/explicit" in urls


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RobotsTxtParser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRobotsTxtParser:
    """robots.txt parsing tests."""

    def test_parse_disallow_allow(self):
        """Parse Disallow and Allow directives."""
        client = _make_client()
        robots = """User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /admin/public/
"""

        with patch.object(
            client._session, "request",
            return_value=_mock_resp(robots, content_type="text/plain"),
        ):
            parser = RobotsTxtParser(client)
            result = parser.discover("https://example.com")

        assert "/admin/" in result.disallowed_paths
        assert "/private/" in result.disallowed_paths
        assert "/admin/public/" in result.allowed_paths

    def test_parse_sitemap_directives(self):
        """Extract Sitemap: URLs."""
        client = _make_client()
        robots = """User-agent: *
Disallow: /tmp/
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap-news.xml
"""

        with patch.object(
            client._session, "request",
            return_value=_mock_resp(robots, content_type="text/plain"),
        ):
            parser = RobotsTxtParser(client)
            result = parser.discover("https://example.com")

        assert len(result.sitemap_urls) == 2
        assert "https://example.com/sitemap.xml" in result.sitemap_urls

    def test_parse_crawl_delay(self):
        """Parse Crawl-Delay directive."""
        client = _make_client()
        robots = """User-agent: *
Crawl-Delay: 2.5
Disallow: /slow/
"""

        with patch.object(
            client._session, "request",
            return_value=_mock_resp(robots, content_type="text/plain"),
        ):
            parser = RobotsTxtParser(client)
            result = parser.discover("https://example.com")

        assert result.crawl_delay == 2.5

    def test_missing_robots_txt(self):
        """404 robots.txt returns empty result."""
        client = _make_client()

        with patch.object(
            client._session, "request",
            return_value=_mock_resp("", status=404),
        ):
            parser = RobotsTxtParser(client)
            result = parser.discover("https://example.com")

        assert result.disallowed_paths == []
        assert result.sitemap_urls == []

    def test_empty_robots_txt(self):
        """Empty robots.txt returns empty result."""
        client = _make_client()

        with patch.object(
            client._session, "request",
            return_value=_mock_resp("", content_type="text/plain"),
        ):
            parser = RobotsTxtParser(client)
            result = parser.discover("https://example.com")

        assert result.disallowed_paths == []

    def test_comments_and_blank_lines(self):
        """Comments and blank lines are ignored."""
        client = _make_client()
        robots = """# This is a comment
User-agent: *

# Another comment
Disallow: /secret/

"""

        with patch.object(
            client._session, "request",
            return_value=_mock_resp(robots, content_type="text/plain"),
        ):
            parser = RobotsTxtParser(client)
            result = parser.discover("https://example.com")

        assert result.disallowed_paths == ["/secret/"]

    def test_no_duplicate_paths(self):
        """Duplicate paths are deduplicated."""
        client = _make_client()
        robots = """User-agent: *
Disallow: /admin/
User-agent: Googlebot
Disallow: /admin/
"""

        with patch.object(
            client._session, "request",
            return_value=_mock_resp(robots, content_type="text/plain"),
        ):
            parser = RobotsTxtParser(client)
            result = parser.discover("https://example.com")

        assert result.disallowed_paths.count("/admin/") == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TechFingerprinter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestTechFingerprinter:
    """Technology fingerprinting tests."""

    @pytest.fixture
    def client(self):
        c = _make_client()
        # Mock path probes to avoid actual requests
        with patch.object(c._session, "request",
                          return_value=_mock_resp("", status=404)):
            yield c

    def test_detect_nginx_from_server_header(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={"Server": "nginx/1.24.0"},
            body="<html><body>Hello</body></html>",
        )
        assert "nginx" in result.server

    def test_detect_php_from_powered_by(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={"X-Powered-By": "PHP/8.2.3"},
            body="<html></html>",
        )
        assert result.powered_by == "PHP/8.2.3"
        assert result.language == "PHP"

    def test_detect_django_from_cookie(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={},
            body="<html></html>",
            cookies={"csrftoken": "abc123", "sessionid": "xyz"},
        )
        assert result.framework == "Django"
        assert "csrftoken" in result.cookies_hints
        assert result.language == "Python"

    def test_detect_laravel_from_cookie(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={},
            body="<html></html>",
            cookies={"laravel_session": "abc"},
        )
        assert result.framework == "Laravel"
        assert result.language == "PHP"

    def test_detect_wordpress_from_generator(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={},
            body='<html><head><meta name="generator" content="WordPress 6.4" /></head></html>',
        )
        assert "WordPress" in result.cms
        assert result.language == "PHP"

    def test_detect_react_from_body(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={},
            body='<html><body><div data-reactroot="">app</div></body></html>',
        )
        assert "React" in result.js_frameworks

    def test_detect_nextjs_from_body(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={},
            body='<html><script src="/_next/static/chunks/main.js"></script></html>',
        )
        assert "Next.js" in result.js_frameworks

    def test_multiple_signals_combined(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2"},
            body='<html><head><meta name="generator" content="WordPress 6.4" /></head>'
                 '<body><link rel="stylesheet" href="/wp-content/themes/style.css" /></body></html>',
            cookies={"PHPSESSID": "abc123"},
        )
        assert "nginx" in result.server
        assert "WordPress" in result.cms
        assert result.language == "PHP"
        assert "PHPSESSID" in result.cookies_hints

    def test_no_signals_returns_empty_fingerprint(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={},
            body="<html><body>plain page</body></html>",
        )
        assert result.server == ""
        assert result.framework == ""
        assert result.cms == ""

    def test_summary_line(self):
        fp = TechFingerprint(
            server="nginx/1.24",
            framework="Django",
            language="Python",
        )
        line = fp.summary_line()
        assert "nginx" in line
        assert "Django" in line
        assert "Python" in line

    def test_summary_line_unknown(self):
        fp = TechFingerprint()
        assert fp.summary_line() == "(unknown)"

    def test_detect_express_from_cookie(self, client):
        fp = TechFingerprinter(client)
        result = fp.fingerprint(
            "https://example.com",
            headers={},
            body="<html></html>",
            cookies={"connect.sid": "s%3A123"},
        )
        assert result.framework == "Express"
        assert result.language == "Node.js"
