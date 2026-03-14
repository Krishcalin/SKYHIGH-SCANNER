"""Tests for DAST config_misconfig check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from vulnerability_management.dast.checks.config_misconfig import run_checks
from vulnerability_management.dast.crawler import SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(
    headers: dict | None = None,
    get_headers: dict | None = None,
    get_text: str = "",
    get_status: int = 200,
    options_headers: dict | None = None,
) -> MagicMock:
    client = MagicMock()
    client.get_headers.return_value = headers or {}

    resp = MagicMock()
    resp.text = get_text
    resp.headers = get_headers or {}
    resp.status_code = get_status
    client.get.return_value = resp

    options_resp = MagicMock()
    options_resp.headers = options_headers or {}
    client.options.return_value = options_resp

    return client


def _empty_sitemap() -> SiteMap:
    return SiteMap()


def _https_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.urls = set(urls)
    return sm


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSecurityHeaders:
    """DAST-CFG-001: Missing security headers."""

    def test_all_headers_missing(self):
        # Must include at least one header so get_headers() returns truthy dict
        client = _mock_client(headers={"Content-Type": "text/html"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_001 = [f for f in findings if f.rule_id == "DAST-CFG-001"]
        # Should flag at least CSP, X-Frame-Options, X-Content-Type-Options
        assert len(cfg_001) >= 3

    def test_all_headers_present(self):
        client = _mock_client(headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_001 = [f for f in findings if f.rule_id == "DAST-CFG-001"]
        assert len(cfg_001) == 0

    def test_partial_headers(self):
        client = _mock_client(headers={
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_001 = [f for f in findings if f.rule_id == "DAST-CFG-001"]
        # Missing: CSP, Referrer-Policy, Permissions-Policy
        assert len(cfg_001) == 3


class TestHSTS:
    """DAST-CFG-002: HSTS."""

    def test_hsts_missing(self):
        client = _mock_client(headers={})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_002 = [f for f in findings if f.rule_id == "DAST-CFG-002"]
        assert len(cfg_002) == 1

    def test_hsts_present_strong(self):
        client = _mock_client(headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_002 = [f for f in findings if f.rule_id == "DAST-CFG-002"]
        assert len(cfg_002) == 0

    def test_hsts_weak_max_age(self):
        client = _mock_client(headers={
            "Strict-Transport-Security": "max-age=86400",  # 1 day
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_002 = [f for f in findings if f.rule_id == "DAST-CFG-002"]
        assert len(cfg_002) == 1
        assert "86400" in cfg_002[0].description


class TestCookieSecurity:
    """DAST-CFG-003: Insecure cookies."""

    def test_insecure_cookie(self):
        resp = MagicMock()
        resp.headers = {"Set-Cookie": "session=abc123; Path=/"}
        resp.text = ""
        client = MagicMock()
        client.get_headers.return_value = {}
        client.get.return_value = resp
        client.options.return_value = MagicMock(headers={})

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_003 = [f for f in findings if f.rule_id == "DAST-CFG-003"]
        # Missing: HttpOnly, Secure, SameSite
        assert len(cfg_003) == 3

    def test_secure_cookie(self):
        resp = MagicMock()
        resp.headers = {
            "Set-Cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict",
        }
        resp.text = ""
        client = MagicMock()
        client.get_headers.return_value = {}
        client.get.return_value = resp
        client.options.return_value = MagicMock(headers={})

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_003 = [f for f in findings if f.rule_id == "DAST-CFG-003"]
        assert len(cfg_003) == 0


class TestCORS:
    """DAST-CFG-004: CORS misconfiguration."""

    def test_cors_wildcard(self):
        resp = MagicMock()
        resp.headers = {"Access-Control-Allow-Origin": "*"}
        resp.text = ""
        client = MagicMock()
        client.get_headers.return_value = {}
        client.get.return_value = resp
        client.options.return_value = MagicMock(headers={})

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_004 = [f for f in findings if f.rule_id == "DAST-CFG-004"]
        assert len(cfg_004) == 1

    def test_cors_reflects_origin(self):
        resp = MagicMock()
        resp.headers = {"Access-Control-Allow-Origin": "https://evil.attacker.com"}
        resp.text = ""
        client = MagicMock()
        client.get_headers.return_value = {}
        client.get.return_value = resp
        client.options.return_value = MagicMock(headers={})

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_004 = [f for f in findings if f.rule_id == "DAST-CFG-004"]
        assert len(cfg_004) == 1
        assert cfg_004[0].severity == "HIGH"


class TestHTTPMethods:
    """DAST-CFG-005: Dangerous HTTP methods."""

    def test_trace_enabled(self):
        client = _mock_client(
            options_headers={"Allow": "GET, POST, TRACE, DELETE"},
        )
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_005 = [f for f in findings if f.rule_id == "DAST-CFG-005"]
        assert len(cfg_005) == 2  # TRACE + DELETE

    def test_safe_methods_only(self):
        client = _mock_client(
            options_headers={"Allow": "GET, POST, HEAD"},
        )
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_005 = [f for f in findings if f.rule_id == "DAST-CFG-005"]
        assert len(cfg_005) == 0


class TestCSPQuality:
    """DAST-CFG-006: Weak CSP."""

    def test_unsafe_inline(self):
        client = _mock_client(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_006 = [f for f in findings if f.rule_id == "DAST-CFG-006"]
        assert len(cfg_006) == 1
        assert "unsafe-inline" in cfg_006[0].name

    def test_strong_csp(self):
        client = _mock_client(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc123'",
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_006 = [f for f in findings if f.rule_id == "DAST-CFG-006"]
        assert len(cfg_006) == 0


class TestMixedContent:
    """DAST-CFG-007: Mixed content."""

    def test_mixed_content_detected(self):
        html = '<img src="http://cdn.example.com/image.png">'
        resp = MagicMock()
        resp.text = html
        client = MagicMock()
        client.get_headers.return_value = {}
        client.get.return_value = resp
        client.options.return_value = MagicMock(headers={})

        sitemap = _https_sitemap("https://example.com/page")
        findings = run_checks(client, "https://example.com", sitemap)
        cfg_007 = [f for f in findings if f.rule_id == "DAST-CFG-007"]
        assert len(cfg_007) == 1


class TestCacheControl:
    """DAST-CFG-008: Missing cache-control."""

    def test_no_cache_control(self):
        client = _mock_client(headers={})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_008 = [f for f in findings if f.rule_id == "DAST-CFG-008"]
        assert len(cfg_008) == 1

    def test_no_store_present(self):
        client = _mock_client(headers={"Cache-Control": "no-store"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_008 = [f for f in findings if f.rule_id == "DAST-CFG-008"]
        assert len(cfg_008) == 0


class TestClickjacking:
    """DAST-CFG-009: Invalid X-Frame-Options."""

    def test_invalid_xfo(self):
        client = _mock_client(headers={"X-Frame-Options": "INVALID"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_009 = [f for f in findings if f.rule_id == "DAST-CFG-009"]
        assert len(cfg_009) == 1

    def test_valid_deny(self):
        client = _mock_client(headers={"X-Frame-Options": "DENY"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_009 = [f for f in findings if f.rule_id == "DAST-CFG-009"]
        assert len(cfg_009) == 0


class TestXContentTypeOptions:
    """DAST-CFG-010: X-Content-Type-Options."""

    def test_wrong_value(self):
        client = _mock_client(headers={"X-Content-Type-Options": "wrong"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_010 = [f for f in findings if f.rule_id == "DAST-CFG-010"]
        assert len(cfg_010) == 1

    def test_nosniff_correct(self):
        client = _mock_client(headers={"X-Content-Type-Options": "nosniff"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        cfg_010 = [f for f in findings if f.rule_id == "DAST-CFG-010"]
        assert len(cfg_010) == 0


class TestRunChecks:
    """Integration tests."""

    def test_all_findings_have_correct_category(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        for f in findings:
            assert f.category == "config_misconfig"
            assert f.target_type == "dast"
