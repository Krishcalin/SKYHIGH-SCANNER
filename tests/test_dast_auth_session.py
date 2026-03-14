"""Tests for DAST auth_session check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from vulnerability_management.dast.checks.auth_session import run_checks
from vulnerability_management.dast.crawler import FormField, FormInfo, SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(get_text: str = "", get_headers: dict | None = None) -> MagicMock:
    client = MagicMock()
    resp = MagicMock()
    resp.text = get_text
    resp.headers = get_headers or {}
    resp.status_code = 200
    resp.url = "https://example.com/dashboard"
    client.get.return_value = resp
    client.post.return_value = resp
    client.get_headers.return_value = {}
    return client


def _login_form(
    action: str = "https://example.com/login",
    method: str = "POST",
    has_csrf: bool = False,
) -> FormInfo:
    fields = [
        FormField(name="username", field_type="text"),
        FormField(name="password", field_type="password"),
    ]
    if has_csrf:
        fields.append(FormField(name="csrf_token", field_type="hidden", value="abc123"))
    return FormInfo(
        url="https://example.com/login",
        action=action,
        method=method,
        fields=fields,
    )


def _empty_sitemap() -> SiteMap:
    return SiteMap()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCSRFTokens:
    """DAST-AUTH-001: Missing CSRF tokens."""

    def test_missing_csrf_token(self):
        sm = SiteMap()
        sm.forms = [_login_form(has_csrf=False)]
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_001 = [f for f in findings if f.rule_id == "DAST-AUTH-001"]
        assert len(auth_001) == 1

    def test_csrf_token_present(self):
        sm = SiteMap()
        sm.forms = [_login_form(has_csrf=True)]
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_001 = [f for f in findings if f.rule_id == "DAST-AUTH-001"]
        assert len(auth_001) == 0

    def test_get_form_not_checked(self):
        sm = SiteMap()
        form = _login_form(method="GET", has_csrf=False)
        sm.forms = [form]
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_001 = [f for f in findings if f.rule_id == "DAST-AUTH-001"]
        assert len(auth_001) == 0  # GET forms don't need CSRF


class TestSessionInURL:
    """DAST-AUTH-002: Session tokens in URL."""

    def test_session_in_url(self):
        sm = SiteMap()
        sm.urls = {"https://example.com/page?jsessionid=abc123"}
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_002 = [f for f in findings if f.rule_id == "DAST-AUTH-002"]
        assert len(auth_002) == 1

    def test_no_session_in_url(self):
        sm = SiteMap()
        sm.urls = {"https://example.com/page?id=123"}
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_002 = [f for f in findings if f.rule_id == "DAST-AUTH-002"]
        assert len(auth_002) == 0


class TestLoginOverHTTP:
    """DAST-AUTH-003: Login forms over HTTP."""

    def test_http_login(self):
        sm = SiteMap()
        sm.forms = [_login_form(action="http://example.com/login")]
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_003 = [f for f in findings if f.rule_id == "DAST-AUTH-003"]
        assert len(auth_003) == 1

    def test_https_login_ok(self):
        sm = SiteMap()
        sm.forms = [_login_form(action="https://example.com/login")]
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_003 = [f for f in findings if f.rule_id == "DAST-AUTH-003"]
        assert len(auth_003) == 0


class TestPasswordAutocomplete:
    """DAST-AUTH-004: Password autocomplete."""

    def test_autocomplete_enabled(self):
        html = '<input type="password" name="pwd">'
        client = _mock_client(get_text=html)
        sm = SiteMap()
        sm.urls = {"https://example.com/login"}
        findings = run_checks(client, "https://example.com", sm)
        auth_004 = [f for f in findings if f.rule_id == "DAST-AUTH-004"]
        assert len(auth_004) == 1

    def test_autocomplete_off(self):
        html = '<input type="password" name="pwd" autocomplete="off">'
        client = _mock_client(get_text=html)
        sm = SiteMap()
        sm.urls = {"https://example.com/login"}
        findings = run_checks(client, "https://example.com", sm)
        auth_004 = [f for f in findings if f.rule_id == "DAST-AUTH-004"]
        assert len(auth_004) == 0


class TestSessionCookieSecurity:
    """DAST-AUTH-005: Session cookie security."""

    def test_session_cookie_no_httponly(self):
        resp = MagicMock()
        resp.text = ""
        resp.headers = {"Set-Cookie": "JSESSIONID=abc; Path=/"}
        resp.status_code = 200
        client = MagicMock()
        client.get.return_value = resp
        client.get_headers.return_value = {}

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        auth_005 = [f for f in findings if f.rule_id == "DAST-AUTH-005"]
        # Should flag HttpOnly and Secure
        assert len(auth_005) >= 1

    def test_non_session_cookie_ignored(self):
        resp = MagicMock()
        resp.text = ""
        resp.headers = {"Set-Cookie": "preference=dark; Path=/"}
        resp.status_code = 200
        client = MagicMock()
        client.get.return_value = resp
        client.get_headers.return_value = {}

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        auth_005 = [f for f in findings if f.rule_id == "DAST-AUTH-005"]
        assert len(auth_005) == 0


class TestLoginFormSecurity:
    """DAST-AUTH-006: Login form method."""

    def test_get_login_flagged(self):
        sm = SiteMap()
        sm.forms = [_login_form(method="GET")]
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_006 = [f for f in findings if f.rule_id == "DAST-AUTH-006"]
        assert len(auth_006) == 1

    def test_post_login_ok(self):
        sm = SiteMap()
        sm.forms = [_login_form(method="POST")]
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_006 = [f for f in findings if f.rule_id == "DAST-AUTH-006"]
        assert len(auth_006) == 0


class TestDefaultCredentials:
    """DAST-AUTH-007: Default credentials."""

    def test_default_creds_accepted(self):
        # Simulate successful login (redirect to dashboard)
        resp = MagicMock()
        resp.status_code = 302
        resp.url = "https://example.com/dashboard"
        resp.text = ""

        client = MagicMock()
        client.get.return_value = MagicMock(text="", headers={}, status_code=200)
        client.post.return_value = resp
        client.get_headers.return_value = {}

        sm = SiteMap()
        sm.forms = [_login_form()]
        findings = run_checks(client, "https://example.com", sm)
        auth_007 = [f for f in findings if f.rule_id == "DAST-AUTH-007"]
        assert len(auth_007) == 1
        assert auth_007[0].severity == "CRITICAL"


class TestLogoutMechanism:
    """DAST-AUTH-009: GET-based logout."""

    def test_get_logout(self):
        sm = SiteMap()
        sm.urls = {"https://example.com/logout"}
        client = _mock_client()
        findings = run_checks(client, "https://example.com", sm)
        auth_009 = [f for f in findings if f.rule_id == "DAST-AUTH-009"]
        assert len(auth_009) == 1


class TestRunChecks:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        for f in findings:
            assert f.category == "auth_session"
            assert f.target_type == "dast"
