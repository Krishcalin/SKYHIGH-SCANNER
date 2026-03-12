"""Tests for DAST xss check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from skyhigh_scanner.dast.checks.xss import CANARY, run_checks
from skyhigh_scanner.dast.crawler import FormField, FormInfo, SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(get_text: str = "", post_text: str = "") -> MagicMock:
    client = MagicMock()

    get_resp = MagicMock()
    get_resp.text = get_text
    get_resp.status_code = 200
    get_resp.headers = {}
    client.get.return_value = get_resp

    post_resp = MagicMock()
    post_resp.text = post_text
    post_resp.status_code = 200
    post_resp.headers = {}
    client.post.return_value = post_resp

    return client


def _url_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.urls = set(urls)
    return sm


def _empty_sitemap() -> SiteMap:
    return SiteMap()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestReflectedXSSParams:
    """DAST-XSS-001: Reflected XSS via URL parameters."""

    def test_xss_reflected(self):
        client = _mock_client(get_text=f"<html>Search: <{CANARY}xss></html>")
        sm = _url_sitemap("https://example.com/search?q=test")
        findings = run_checks(client, "https://example.com", sm)
        xss_001 = [f for f in findings if f.rule_id == "DAST-XSS-001"]
        assert len(xss_001) == 1
        assert xss_001[0].severity == "HIGH"

    def test_xss_encoded_no_finding(self):
        client = _mock_client(get_text="<html>Search: &lt;test&gt;</html>")
        sm = _url_sitemap("https://example.com/search?q=test")
        findings = run_checks(client, "https://example.com", sm)
        xss_001 = [f for f in findings if f.rule_id == "DAST-XSS-001"]
        assert len(xss_001) == 0

    def test_no_params_no_test(self):
        client = _mock_client()
        sm = _url_sitemap("https://example.com/page")
        findings = run_checks(client, "https://example.com", sm)
        xss_001 = [f for f in findings if f.rule_id == "DAST-XSS-001"]
        assert len(xss_001) == 0


class TestReflectedXSSForms:
    """DAST-XSS-002: Reflected XSS via form inputs."""

    def test_form_xss(self):
        client = _mock_client(post_text=f"<html>Result: <{CANARY}xss></html>")
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/search",
            action="https://example.com/search",
            method="POST",
            fields=[FormField(name="q", field_type="text")],
        )]
        findings = run_checks(client, "https://example.com", sm)
        xss_002 = [f for f in findings if f.rule_id == "DAST-XSS-002"]
        assert len(xss_002) == 1

    def test_form_no_xss(self):
        client = _mock_client(post_text="<html>Safe output</html>")
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/search",
            action="https://example.com/search",
            method="POST",
            fields=[FormField(name="q", field_type="text")],
        )]
        findings = run_checks(client, "https://example.com", sm)
        xss_002 = [f for f in findings if f.rule_id == "DAST-XSS-002"]
        assert len(xss_002) == 0


class TestDOMXSS:
    """DAST-XSS-003: DOM-based XSS indicators."""

    def test_dom_xss_source_and_sink(self):
        js_code = """
        <script>
            var input = document.URL;
            document.write(input);
        </script>
        """
        client = _mock_client(get_text=js_code)
        sm = _url_sitemap("https://example.com/page")
        findings = run_checks(client, "https://example.com", sm)
        xss_003 = [f for f in findings if f.rule_id == "DAST-XSS-003"]
        assert len(xss_003) == 1

    def test_no_dom_xss(self):
        client = _mock_client(get_text="<html>Safe page</html>")
        sm = _url_sitemap("https://example.com/page")
        findings = run_checks(client, "https://example.com", sm)
        xss_003 = [f for f in findings if f.rule_id == "DAST-XSS-003"]
        assert len(xss_003) == 0

    def test_sink_without_source_no_finding(self):
        js_code = "<script>document.write('hello');</script>"
        client = _mock_client(get_text=js_code)
        sm = _url_sitemap("https://example.com/page")
        findings = run_checks(client, "https://example.com", sm)
        xss_003 = [f for f in findings if f.rule_id == "DAST-XSS-003"]
        assert len(xss_003) == 0


class TestXSSInHeaders:
    """DAST-XSS-004: XSS via HTTP headers."""

    def test_referer_reflected(self):
        payload = f"<{CANARY}header>"
        client = _mock_client(get_text=f"<html>Referer: {payload}</html>")
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        xss_004 = [f for f in findings if f.rule_id == "DAST-XSS-004"]
        assert len(xss_004) >= 1

    def test_no_header_reflection(self):
        client = _mock_client(get_text="<html>Normal page</html>")
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        xss_004 = [f for f in findings if f.rule_id == "DAST-XSS-004"]
        assert len(xss_004) == 0


class TestXSSErrorPages:
    """DAST-XSS-005: XSS in error pages."""

    def test_path_reflected_in_404(self):
        payload = f"<{CANARY}err>"
        client = _mock_client(get_text=f"<html>404: {payload} not found</html>")
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        xss_005 = [f for f in findings if f.rule_id == "DAST-XSS-005"]
        assert len(xss_005) == 1

    def test_path_not_reflected(self):
        client = _mock_client(get_text="<html>404: Page not found</html>")
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        xss_005 = [f for f in findings if f.rule_id == "DAST-XSS-005"]
        assert len(xss_005) == 0


class TestRunChecks:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        client = _mock_client(get_text=f"<{CANARY}xss>")
        sm = _url_sitemap("https://example.com/search?q=test")
        findings = run_checks(client, "https://example.com", sm)
        for f in findings:
            assert f.category == "xss"
            assert f.target_type == "dast"

    def test_empty_sitemap(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        assert isinstance(findings, list)
