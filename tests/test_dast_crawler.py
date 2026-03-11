"""Tests for the DAST web crawler."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from skyhigh_scanner.dast.config import DastConfig, ScopePolicy
from skyhigh_scanner.dast.crawler import (
    APIEndpoint,
    FormField,
    FormInfo,
    SiteMap,
    WebCrawler,
    _extract_js_endpoints,
    _LinkFormParser,
)
from skyhigh_scanner.dast.http_client import DastHTTPClient

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SiteMap
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSiteMap:
    def test_empty_sitemap(self):
        sm = SiteMap()
        assert sm.total_discovered == 0
        assert len(sm.urls) == 0
        assert len(sm.forms) == 0
        assert len(sm.api_endpoints) == 0

    def test_total_discovered(self):
        sm = SiteMap()
        sm.urls.add("https://example.com")
        sm.forms.append(FormInfo(url="https://example.com", action="/submit"))
        sm.api_endpoints.append(APIEndpoint(url="/api/v1/users"))
        assert sm.total_discovered == 3


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FormInfo
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestFormInfo:
    def test_field_names(self):
        form = FormInfo(
            url="https://example.com/page",
            action="/submit",
            method="POST",
            fields=[
                FormField(name="username", field_type="text"),
                FormField(name="password", field_type="password"),
                FormField(name="", field_type="hidden"),  # No name — should be skipped
            ],
        )
        assert form.field_names == ["username", "password"]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTML parser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLinkFormParser:
    def test_extract_links(self):
        html = """
        <html>
        <body>
            <a href="/about">About</a>
            <a href="https://example.com/contact">Contact</a>
            <a href="/logout">Logout</a>
        </body>
        </html>
        """
        parser = _LinkFormParser("https://example.com")
        parser.feed(html)
        assert len(parser.links) == 3
        assert "https://example.com/about" in parser.links
        assert "https://example.com/contact" in parser.links

    def test_extract_form_simple(self):
        html = """
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
        """
        parser = _LinkFormParser("https://example.com")
        parser.feed(html)
        assert len(parser.forms) == 1
        form = parser.forms[0]
        assert form.action == "https://example.com/login"
        assert form.method == "POST"
        # submit input has no name attr, so only 2 named fields
        assert len(form.fields) == 2
        assert form.fields[0].name == "username"
        assert form.fields[1].name == "password"

    def test_extract_form_with_file_upload(self):
        html = """
        <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="document" />
            <input type="submit" value="Upload" />
        </form>
        """
        parser = _LinkFormParser("https://example.com")
        parser.feed(html)
        assert parser.forms[0].has_file_upload is True

    def test_extract_form_hidden_fields(self):
        html = """
        <form action="/transfer" method="POST">
            <input type="hidden" name="csrf_token" value="abc123" />
            <input type="text" name="amount" />
        </form>
        """
        parser = _LinkFormParser("https://example.com")
        parser.feed(html)
        form = parser.forms[0]
        csrf = [f for f in form.fields if f.name == "csrf_token"][0]
        assert csrf.field_type == "hidden"
        assert csrf.value == "abc123"

    def test_extract_scripts(self):
        html = """
        <html>
        <head>
            <script src="/js/app.js"></script>
            <script src="https://cdn.example.com/lib.js"></script>
        </head>
        </html>
        """
        parser = _LinkFormParser("https://example.com")
        parser.feed(html)
        assert len(parser.scripts) == 2
        assert "https://example.com/js/app.js" in parser.scripts

    def test_form_default_method_is_get(self):
        html = '<form action="/search"><input name="q" /></form>'
        parser = _LinkFormParser("https://example.com")
        parser.feed(html)
        assert parser.forms[0].method == "GET"

    def test_textarea_and_select(self):
        html = """
        <form action="/feedback" method="POST">
            <textarea name="message"></textarea>
            <select name="rating"><option>1</option></select>
        </form>
        """
        parser = _LinkFormParser("https://example.com")
        parser.feed(html)
        form = parser.forms[0]
        names = [f.name for f in form.fields]
        assert "message" in names
        assert "rating" in names

    def test_relative_action(self):
        html = '<form action="submit"></form>'
        parser = _LinkFormParser("https://example.com/app/")
        parser.feed(html)
        assert parser.forms[0].action == "https://example.com/app/submit"

    def test_no_action(self):
        html = '<form method="POST"><input name="x" /></form>'
        parser = _LinkFormParser("https://example.com/page")
        parser.feed(html)
        assert parser.forms[0].action == "https://example.com/page"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JavaScript endpoint extraction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestJSEndpointExtraction:
    def test_fetch_pattern(self):
        js = 'fetch("/api/users")'
        endpoints = _extract_js_endpoints(js, "https://example.com")
        assert len(endpoints) == 1
        assert endpoints[0].url == "https://example.com/api/users"

    def test_axios_pattern(self):
        js = 'axios.get("/api/v1/products")'
        endpoints = _extract_js_endpoints(js, "https://example.com")
        assert len(endpoints) == 1

    def test_xhr_pattern(self):
        js = '.open("GET", "/api/data")'
        endpoints = _extract_js_endpoints(js, "https://example.com")
        assert len(endpoints) == 1

    def test_api_string_literal(self):
        js = 'const url = "/api/v1/admin/settings"'
        endpoints = _extract_js_endpoints(js, "https://example.com")
        assert any("/api/v1/admin/settings" in ep.url for ep in endpoints)

    def test_deduplication(self):
        js = """
        fetch("/api/users")
        fetch("/api/users")
        """
        endpoints = _extract_js_endpoints(js, "https://example.com")
        assert len(endpoints) == 1

    def test_no_matches(self):
        js = "var x = 42; console.log(x);"
        endpoints = _extract_js_endpoints(js, "https://example.com")
        assert len(endpoints) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WebCrawler
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWebCrawler:
    @pytest.fixture
    def crawler_client(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            rate_limit_rps=1000.0,
            max_requests=500,
        )
        return DastHTTPClient(config=config)

    def _make_response(self, text, content_type="text/html", status=200):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = {"Content-Type": content_type}
        resp.request = MagicMock()
        resp.request.headers = {}
        return resp

    def test_crawl_single_page(self, crawler_client):
        page_html = """
        <html>
        <body><h1>Home</h1></body>
        </html>
        """
        with patch.object(
            crawler_client._session, "request",
            return_value=self._make_response(page_html),
        ):
            crawler = WebCrawler(client=crawler_client, max_depth=1)
            sitemap = crawler.crawl("https://example.com")

        assert "https://example.com" in sitemap.urls

    def test_crawl_discovers_links(self, crawler_client):
        page_html = """
        <html><body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </body></html>
        """
        about_html = "<html><body>About page</body></html>"
        contact_html = "<html><body>Contact page</body></html>"

        call_count = 0

        def side_effect(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/about" in url:
                return self._make_response(about_html)
            if "/contact" in url:
                return self._make_response(contact_html)
            return self._make_response(page_html)

        with patch.object(crawler_client._session, "request", side_effect=side_effect):
            crawler = WebCrawler(client=crawler_client, max_depth=2)
            sitemap = crawler.crawl("https://example.com")

        assert len(sitemap.urls) >= 2

    def test_crawl_respects_max_depth(self, crawler_client):
        # Each page links to the next depth level
        def side_effect(method, url, **kwargs):
            depth = url.count("/level")
            return self._make_response(
                f'<html><body><a href="/level{depth + 1}">Next</a></body></html>'
            )

        with patch.object(crawler_client._session, "request", side_effect=side_effect):
            crawler = WebCrawler(client=crawler_client, max_depth=2, max_pages=50)
            sitemap = crawler.crawl("https://example.com")

        # Should not go beyond depth 2
        assert len(sitemap.urls) <= 4

    def test_crawl_respects_max_pages(self, crawler_client):
        def side_effect(method, url, **kwargs):
            return self._make_response(
                '<html><body><a href="/page1">1</a><a href="/page2">2</a>'
                '<a href="/page3">3</a><a href="/page4">4</a></body></html>'
            )

        with patch.object(crawler_client._session, "request", side_effect=side_effect):
            crawler = WebCrawler(client=crawler_client, max_pages=2)
            sitemap = crawler.crawl("https://example.com")

        assert len(sitemap.urls) <= 2

    def test_crawl_skips_static_resources(self, crawler_client):
        page_html = """
        <html><body>
            <a href="/style.css">CSS</a>
            <a href="/image.png">Image</a>
            <a href="/app.js">JS</a>
            <a href="/page2">Page2</a>
        </body></html>
        """
        page2_html = "<html><body>Page 2</body></html>"

        def side_effect(method, url, **kwargs):
            if "/page2" in url:
                return self._make_response(page2_html)
            return self._make_response(page_html)

        with patch.object(crawler_client._session, "request", side_effect=side_effect):
            crawler = WebCrawler(client=crawler_client)
            sitemap = crawler.crawl("https://example.com")

        # Static files should be in static_resources, not urls
        assert any("style.css" in s for s in sitemap.static_resources)

    def test_crawl_discovers_forms(self, crawler_client):
        page_html = """
        <html><body>
            <form action="/search" method="GET">
                <input type="text" name="q" />
            </form>
        </body></html>
        """

        with patch.object(
            crawler_client._session, "request",
            return_value=self._make_response(page_html),
        ):
            crawler = WebCrawler(client=crawler_client)
            sitemap = crawler.crawl("https://example.com")

        assert len(sitemap.forms) == 1
        assert sitemap.forms[0].field_names == ["q"]

    def test_crawl_discovers_json_api(self, crawler_client):
        def side_effect(method, url, **kwargs):
            if "/api" in url:
                return self._make_response(
                    '{"data": []}', content_type="application/json",
                )
            return self._make_response(
                '<html><body><a href="/api/data">API</a></body></html>'
            )

        with patch.object(crawler_client._session, "request", side_effect=side_effect):
            crawler = WebCrawler(client=crawler_client, max_depth=2)
            sitemap = crawler.crawl("https://example.com")

        assert any("api" in ep.url for ep in sitemap.api_endpoints)

    def test_crawl_out_of_scope_links_skipped(self, crawler_client):
        page_html = """
        <html><body>
            <a href="https://evil.com/phish">External</a>
            <a href="/internal">Internal</a>
        </body></html>
        """
        internal_html = "<html><body>Internal</body></html>"

        def side_effect(method, url, **kwargs):
            if "/internal" in url:
                return self._make_response(internal_html)
            return self._make_response(page_html)

        with patch.object(crawler_client._session, "request", side_effect=side_effect):
            crawler = WebCrawler(client=crawler_client, max_depth=2)
            sitemap = crawler.crawl("https://example.com")

        assert not any("evil.com" in u for u in sitemap.urls)
