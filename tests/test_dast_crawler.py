"""Tests for the DAST web crawler."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vulnerability_management.dast.config import DastConfig, ScopePolicy
from vulnerability_management.dast.crawler import (
    APIEndpoint,
    CrawlStats,
    FormField,
    FormInfo,
    RedirectRecord,
    SiteMap,
    TechFingerprint,
    WebCrawler,
    _extract_js_endpoints,
    _LinkFormParser,
    _URLPatternTracker,
)
from vulnerability_management.dast.http_client import DastHTTPClient

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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 5 — New dataclasses
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNewDataclasses:
    """Tests for Phase 5 dataclasses."""

    def test_redirect_record(self):
        rr = RedirectRecord(
            original_url="https://example.com/old",
            final_url="https://example.com/new",
            chain=[(301, "https://example.com/old"), (200, "https://example.com/new")],
            total_hops=1,
        )
        assert rr.total_hops == 1
        assert rr.chain[0][0] == 301

    def test_tech_fingerprint_summary(self):
        fp = TechFingerprint(server="Apache/2.4", framework="Django", language="Python")
        assert "Apache" in fp.summary_line()
        assert "Django" in fp.summary_line()

    def test_tech_fingerprint_empty_summary(self):
        fp = TechFingerprint()
        assert fp.summary_line() == "(unknown)"

    def test_crawl_stats_record_response(self):
        cs = CrawlStats()
        cs.record_response(200, "text/html; charset=utf-8")
        cs.record_response(200, "text/html; charset=utf-8")
        cs.record_response(404, "text/html")
        assert cs.requests_sent == 3
        assert cs.status_codes[200] == 2
        assert cs.status_codes[404] == 1
        assert cs.content_types["text/html"] == 3

    def test_crawl_stats_duration(self):
        cs = CrawlStats(start_time=100.0, end_time=105.5)
        assert cs.duration_seconds == 5.5

    def test_crawl_stats_zero_duration(self):
        cs = CrawlStats()
        assert cs.duration_seconds == 0.0

    def test_sitemap_new_fields(self):
        sm = SiteMap()
        assert sm.redirects == []
        assert sm.tech_fingerprint is None
        assert sm.robots_disallowed == []
        assert sm.crawl_stats.requests_sent == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# URL Pattern Tracker
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestURLPatternTracker:
    """Smart URL deduplication tests."""

    def test_same_pattern_different_values(self):
        tracker = _URLPatternTracker(max_per_pattern=2)
        assert tracker.should_crawl("https://example.com/product?id=1") is True
        assert tracker.should_crawl("https://example.com/product?id=2") is True
        assert tracker.should_crawl("https://example.com/product?id=3") is False

    def test_different_paths_independent(self):
        tracker = _URLPatternTracker(max_per_pattern=1)
        assert tracker.should_crawl("https://example.com/a?id=1") is True
        assert tracker.should_crawl("https://example.com/b?id=1") is True

    def test_different_param_names_different_patterns(self):
        tracker = _URLPatternTracker(max_per_pattern=1)
        assert tracker.should_crawl("https://example.com/page?id=1") is True
        assert tracker.should_crawl("https://example.com/page?name=x") is True

    def test_no_query_string_path_only(self):
        tracker = _URLPatternTracker(max_per_pattern=1)
        assert tracker.should_crawl("https://example.com/page") is True
        assert tracker.should_crawl("https://example.com/page") is False

    def test_pattern_key_sorts_params(self):
        key1 = _URLPatternTracker._pattern_key("https://x.com/p?b=2&a=1")
        key2 = _URLPatternTracker._pattern_key("https://x.com/p?a=9&b=8")
        assert key1 == key2

    def test_default_limit_is_three(self):
        tracker = _URLPatternTracker()
        for i in range(3):
            assert tracker.should_crawl(f"https://x.com/p?id={i}") is True
        assert tracker.should_crawl("https://x.com/p?id=99") is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Normalize URL (updated)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNormalizeURL:
    """_normalize_url now preserves and sorts query params."""

    @pytest.fixture
    def crawler(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            rate_limit_rps=1000.0,
        )
        client = DastHTTPClient(config=config)
        return WebCrawler(client=client)

    def test_preserves_query_params(self, crawler):
        n = crawler._normalize_url("https://example.com/page?q=test")
        assert "q=test" in n

    def test_sorts_query_params(self, crawler):
        n = crawler._normalize_url("https://example.com/page?b=2&a=1")
        assert n == "https://example.com/page?a=1&b=2"

    def test_strips_fragment(self, crawler):
        n = crawler._normalize_url("https://example.com/page#section")
        assert "#" not in n

    def test_strips_trailing_slash(self, crawler):
        n = crawler._normalize_url("https://example.com/page/")
        assert n.endswith("/page") or n.endswith("/page?")
        assert not n.endswith("/page/")

    def test_root_path(self, crawler):
        n = crawler._normalize_url("https://example.com/")
        assert n == "https://example.com/"

    def test_no_query_string(self, crawler):
        n = crawler._normalize_url("https://example.com/about")
        assert n == "https://example.com/about"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Redirect tracking
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRedirectTracking:
    """Redirect chain tracking tests."""

    def _make_response(self, status=200, location=None, text="", content_type="text/html"):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = {"Content-Type": content_type}
        if location:
            resp.headers["Location"] = location
        resp.request = MagicMock()
        resp.request.headers = {}
        resp.request.body = None
        return resp

    @pytest.fixture
    def crawler_with_client(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            rate_limit_rps=1000.0,
            max_requests=500,
        )
        client = DastHTTPClient(config=config)
        crawler = WebCrawler(client=client)
        return crawler, client

    def test_no_redirect(self, crawler_with_client):
        crawler, client = crawler_with_client
        sitemap = SiteMap()

        with patch.object(
            client._session, "request",
            return_value=self._make_response(200, text="<html>ok</html>"),
        ):
            resp, record = crawler._follow_redirects(
                "https://example.com/page", sitemap,
            )

        assert resp.status_code == 200
        assert record is None
        assert len(sitemap.redirects) == 0

    def test_single_redirect(self, crawler_with_client):
        crawler, client = crawler_with_client
        sitemap = SiteMap()

        call_count = 0

        def side_effect(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._make_response(301, location="/new-page")
            return self._make_response(200, text="<html>new</html>")

        with patch.object(client._session, "request", side_effect=side_effect):
            resp, record = crawler._follow_redirects(
                "https://example.com/old", sitemap,
            )

        assert resp.status_code == 200
        assert record is not None
        assert record.total_hops == 1
        assert record.original_url == "https://example.com/old"
        assert len(sitemap.redirects) == 1

    def test_multi_hop_redirect(self, crawler_with_client):
        crawler, client = crawler_with_client
        sitemap = SiteMap()

        call_count = 0

        def side_effect(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._make_response(301, location="/step2")
            if call_count == 2:
                return self._make_response(302, location="/step3")
            return self._make_response(200, text="<html>final</html>")

        with patch.object(client._session, "request", side_effect=side_effect):
            resp, record = crawler._follow_redirects(
                "https://example.com/start", sitemap,
            )

        assert record is not None
        assert record.total_hops == 2
        assert len(record.chain) == 3  # 2 redirects + final

    def test_out_of_scope_redirect_truncates(self, crawler_with_client):
        crawler, client = crawler_with_client
        sitemap = SiteMap()

        with patch.object(
            client._session, "request",
            return_value=self._make_response(301, location="https://evil.com/phish"),
        ):
            resp, record = crawler._follow_redirects(
                "https://example.com/link", sitemap,
            )

        assert record is not None
        assert "evil.com" in record.final_url
        assert sitemap.crawl_stats.redirect_count == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Form auto-submission
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestFormAutoSubmission:
    """Form auto-submission for discovery tests."""

    def _make_response(self, text="", content_type="text/html", status=200):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = {"Content-Type": content_type}
        resp.request = MagicMock()
        resp.request.headers = {}
        resp.request.body = None
        return resp

    @pytest.fixture
    def crawler_with_client(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            rate_limit_rps=1000.0,
            max_requests=500,
        )
        client = DastHTTPClient(config=config)
        crawler = WebCrawler(client=client)
        return crawler, client

    def test_submits_search_form(self, crawler_with_client):
        crawler, client = crawler_with_client
        sitemap = SiteMap()
        sitemap.forms.append(FormInfo(
            url="https://example.com",
            action="https://example.com/search",
            method="GET",
            fields=[FormField(name="q", field_type="text")],
        ))
        visited: set[str] = set()

        result_html = '<html><body><a href="/results/1">Result</a></body></html>'
        with patch.object(
            client._session, "request",
            return_value=self._make_response(result_html),
        ):
            crawler._submit_discovery_forms(
                sitemap, visited, [], "https://example.com",
            )

        assert any("results" in u for u in sitemap.urls)

    def test_skips_login_form(self, crawler_with_client):
        crawler, client = crawler_with_client
        sitemap = SiteMap()
        sitemap.forms.append(FormInfo(
            url="https://example.com",
            action="https://example.com/login",
            method="POST",
            fields=[
                FormField(name="username", field_type="text"),
                FormField(name="password", field_type="password"),
            ],
        ))
        visited: set[str] = set()

        with patch.object(client._session, "request") as mock_req:
            crawler._submit_discovery_forms(
                sitemap, visited, [], "https://example.com",
            )
            mock_req.assert_not_called()

    def test_skips_file_upload_form(self, crawler_with_client):
        crawler, client = crawler_with_client
        sitemap = SiteMap()
        sitemap.forms.append(FormInfo(
            url="https://example.com",
            action="https://example.com/upload",
            method="POST",
            fields=[FormField(name="file", field_type="file")],
            has_file_upload=True,
        ))
        visited: set[str] = set()

        with patch.object(client._session, "request") as mock_req:
            crawler._submit_discovery_forms(
                sitemap, visited, [], "https://example.com",
            )
            mock_req.assert_not_called()

    def test_respects_submission_limit(self, crawler_with_client):
        crawler, client = crawler_with_client
        crawler.MAX_FORM_SUBMISSIONS = 2
        sitemap = SiteMap()
        for i in range(5):
            sitemap.forms.append(FormInfo(
                url="https://example.com",
                action=f"https://example.com/search{i}",
                method="GET",
                fields=[FormField(name="q", field_type="text")],
            ))
        visited: set[str] = set()

        call_count = 0

        def side_effect(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html><body>results</body></html>"
            resp.headers = {"Content-Type": "text/html"}
            resp.request = MagicMock()
            resp.request.headers = {}
            resp.request.body = None
            return resp

        with patch.object(client._session, "request", side_effect=side_effect):
            crawler._submit_discovery_forms(
                sitemap, visited, [], "https://example.com",
            )

        assert call_count <= 2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Crawl stats integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCrawlStatsIntegration:
    """CrawlStats populated during crawl."""

    def _make_response(self, text="", content_type="text/html", status=200):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = {"Content-Type": content_type}
        resp.request = MagicMock()
        resp.request.headers = {}
        resp.request.body = None
        return resp

    def test_stats_populated_after_crawl(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            rate_limit_rps=1000.0,
            max_requests=500,
        )
        client = DastHTTPClient(config=config)

        page_html = "<html><body><h1>Home</h1></body></html>"

        with patch.object(
            client._session, "request",
            return_value=self._make_response(page_html),
        ):
            crawler = WebCrawler(client=client, max_depth=1)
            sitemap = crawler.crawl("https://example.com")

        cs = sitemap.crawl_stats
        assert cs.pages_crawled >= 1
        assert cs.duration_seconds >= 0
        assert 200 in cs.status_codes
