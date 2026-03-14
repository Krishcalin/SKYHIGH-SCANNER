"""Tests for DAST xss check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from vulnerability_management.dast.checks.xss import (
    CANARY,
    STORED_XSS_CANARY_PREFIX,
    _check_stored_xss,
    run_checks,
)
from vulnerability_management.dast.crawler import FormField, FormInfo, SiteMap

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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Stored XSS (DAST-XSS-006 / DAST-XSS-007)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestStoredXSS:
    """DAST-XSS-006/007: Stored XSS via form submission."""

    def test_stored_xss_detected(self):
        """Detect when canary appears unescaped in subsequent GET."""
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/comments",
            action="https://example.com/comments",
            method="POST",
            fields=[FormField(name="comment", field_type="text")],
        )]
        sm.urls = {"https://example.com/comments"}

        client = MagicMock()
        # POST succeeds
        client.post.return_value = MagicMock(text="OK", status_code=200, headers={})

        # GET returns the canary unescaped
        def fake_get(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}
            # Include any SKYHIGH_STORED_ canary unescaped with onerror
            resp.text = f"<html>Comment: <img src=x onerror={STORED_XSS_CANARY_PREFIX}abcd1234></html>"
            return resp

        client.get.return_value = fake_get()
        # Need to make client.get match the canary that _generate_canary produces
        # Instead, mock to reflect whatever was posted
        call_count = [0]

        def smart_get(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}
            # After post, get should return any canary that was submitted
            post_calls = client.post.call_args_list
            if post_calls:
                # Extract canary from posted data
                data = post_calls[0].kwargs.get("data", {}) if post_calls[0].kwargs else {}
                if not data and len(post_calls[0].args) > 1:
                    data = post_calls[0].args[1] if len(post_calls[0].args) > 1 else {}
                for v in data.values():
                    if STORED_XSS_CANARY_PREFIX in str(v):
                        resp.text = f"<html>{v}</html>"
                        return resp
            resp.text = "<html>Normal</html>"
            return resp

        client.get.side_effect = smart_get

        findings = []
        _check_stored_xss(client, sm, findings)
        xss_006 = [f for f in findings if f.rule_id == "DAST-XSS-006"]
        assert len(xss_006) >= 1
        assert xss_006[0].severity == "CRITICAL"

    def test_stored_xss_no_forms(self):
        """No finding when no eligible forms."""
        client = _mock_client()
        sm = _empty_sitemap()
        findings = []
        _check_stored_xss(client, sm, findings)
        assert len(findings) == 0

    def test_stored_xss_encoded(self):
        """Canary appears encoded — DAST-XSS-007."""
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/feedback",
            action="https://example.com/feedback",
            method="POST",
            fields=[FormField(name="message", field_type="textarea")],
        )]
        sm.urls = {"https://example.com/feedback"}

        client = MagicMock()
        client.post.return_value = MagicMock(text="OK", status_code=200, headers={})

        def smart_get(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}
            post_calls = client.post.call_args_list
            if post_calls:
                data = post_calls[0].kwargs.get("data", {}) if post_calls[0].kwargs else {}
                for v in data.values():
                    if STORED_XSS_CANARY_PREFIX in str(v):
                        # Return canary text but WITHOUT the onerror= unescaped
                        import re as _re
                        canary = _re.search(r"SKYHIGH_STORED_\w+", str(v))
                        if canary:
                            resp.text = f"<html>Comment: {canary.group()}</html>"
                            return resp
            resp.text = "<html>Normal</html>"
            return resp

        client.get.side_effect = smart_get

        findings = []
        _check_stored_xss(client, sm, findings)
        xss_007 = [f for f in findings if f.rule_id == "DAST-XSS-007"]
        assert len(xss_007) >= 1
        assert xss_007[0].severity == "HIGH"

    def test_stored_xss_skip_search_form(self):
        """Search forms are skipped."""
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/search",
            action="https://example.com/search",
            method="POST",
            fields=[FormField(name="q", field_type="text")],
        )]
        client = _mock_client()
        findings = []
        _check_stored_xss(client, sm, findings)
        assert len(findings) == 0

    def test_stored_xss_skip_file_upload(self):
        """File upload forms are skipped."""
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/upload",
            action="https://example.com/upload",
            method="POST",
            fields=[FormField(name="file", field_type="file")],
            has_file_upload=True,
        )]
        client = _mock_client()
        findings = []
        _check_stored_xss(client, sm, findings)
        assert len(findings) == 0

    def test_canary_prefix_defined(self):
        """Verify the canary prefix constant."""
        assert STORED_XSS_CANARY_PREFIX == "SKYHIGH_STORED_"
