"""Tests for DAST access_control check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from vulnerability_management.dast.checks.access_control import run_checks
from vulnerability_management.dast.crawler import SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(
    probe_results: dict | None = None,
    get_text: str = "",
    get_status: int = 200,
) -> MagicMock:
    client = MagicMock()

    if probe_results:
        def _probe(base, path):
            return probe_results.get(path, (404, ""))
        client.probe_path.side_effect = _probe
    else:
        client.probe_path.return_value = (404, "")

    resp = MagicMock()
    resp.text = get_text
    resp.status_code = get_status
    resp.headers = {}
    resp.url = ""
    client.get.return_value = resp
    client.request.return_value = resp

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

class TestForcedBrowsing:
    """DAST-AC-001: Forced browsing to admin paths."""

    def test_admin_panel_found(self):
        admin_body = "<html><head><title>Admin Dashboard</title></head><body><h1>Admin Dashboard</h1><p>Manage users and settings</p><nav>Configuration</nav></body></html>"
        client = _mock_client(probe_results={
            "admin": (200, admin_body),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        ac_001 = [f for f in findings if f.rule_id == "DAST-AC-001"]
        assert len(ac_001) >= 1
        assert ac_001[0].severity == "HIGH"

    def test_admin_returns_404(self):
        client = _mock_client()  # all probes return 404
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        ac_001 = [f for f in findings if f.rule_id == "DAST-AC-001"]
        assert len(ac_001) == 0

    def test_actuator_found(self):
        actuator_body = '{"_links":{"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"},"metrics":{"href":"/actuator/metrics"},"configuration":{"href":"/actuator/config"}}}'
        client = _mock_client(probe_results={
            "actuator": (200, actuator_body),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        ac_001 = [f for f in findings if f.rule_id == "DAST-AC-001"]
        assert len(ac_001) >= 1


class TestVerbTampering:
    """DAST-AC-002: HTTP verb tampering."""

    def test_verb_bypass(self):
        # GET returns 403, POST returns 200
        def _mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Forbidden"
            resp.headers = {}
            return resp

        def _mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200 if method == "POST" else 403
            resp.text = "OK"
            resp.headers = {}
            return resp

        client = MagicMock()
        client.get.side_effect = _mock_get
        client.request.side_effect = _mock_request
        client.probe_path.return_value = (404, "")

        sm = _url_sitemap("https://example.com/admin/delete")
        findings = run_checks(client, "https://example.com", sm)
        ac_002 = [f for f in findings if f.rule_id == "DAST-AC-002"]
        assert len(ac_002) == 1

    def test_no_forbidden_pages(self):
        client = _mock_client(get_status=200)
        sm = _url_sitemap("https://example.com/page")
        findings = run_checks(client, "https://example.com", sm)
        ac_002 = [f for f in findings if f.rule_id == "DAST-AC-002"]
        assert len(ac_002) == 0


class TestIDOR:
    """DAST-AC-003: IDOR indicators."""

    def test_sequential_id_accessible(self):
        profile_body = "<html><head><title>User Profile</title></head><body><h1>User Profile</h1><p>Name: John Doe</p><p>Email: john@example.com</p></body></html>"
        client = _mock_client(
            get_text=profile_body,
        )
        sm = _url_sitemap("https://example.com/user?user_id=100")
        findings = run_checks(client, "https://example.com", sm)
        ac_003 = [f for f in findings if f.rule_id == "DAST-AC-003"]
        assert len(ac_003) == 1

    def test_non_numeric_id(self):
        client = _mock_client()
        sm = _url_sitemap("https://example.com/user?user_id=abc-uuid")
        findings = run_checks(client, "https://example.com", sm)
        ac_003 = [f for f in findings if f.rule_id == "DAST-AC-003"]
        assert len(ac_003) == 0

    def test_non_idor_param(self):
        client = _mock_client()
        sm = _url_sitemap("https://example.com/page?color=123")
        findings = run_checks(client, "https://example.com", sm)
        ac_003 = [f for f in findings if f.rule_id == "DAST-AC-003"]
        assert len(ac_003) == 0


class TestRobotsTxtPaths:
    """DAST-AC-004: robots.txt disallowed paths accessible."""

    def test_disallowed_path_accessible(self):
        secret_body = "<html><head><title>Secret Area</title></head><body><h1>Secret Page Content</h1><p>Confidential data and internal resources are listed here for authorized users.</p></body></html>"
        def _probe(base, path):
            if path == "robots.txt":
                return (200, "User-agent: *\nDisallow: /secret/\nDisallow: /backup/")
            if path == "secret/":
                return (200, secret_body)
            return (404, "")

        client = MagicMock()
        client.probe_path.side_effect = _probe
        client.get.return_value = MagicMock(text="", status_code=200, headers={}, url="")
        client.request.return_value = MagicMock(text="", status_code=404, headers={})

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        ac_004 = [f for f in findings if f.rule_id == "DAST-AC-004"]
        assert len(ac_004) >= 1

    def test_no_robots_txt(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        ac_004 = [f for f in findings if f.rule_id == "DAST-AC-004"]
        assert len(ac_004) == 0


class TestMissingAuthSensitive:
    """DAST-AC-005: Sensitive pages without auth."""

    def test_profile_without_auth(self):
        profile_body = (
            "<html><head><title>My Profile</title></head><body>"
            "<h1>My Profile</h1><p>Name: John Doe</p>"
            "<p>Email: john@example.com</p>"
            "<p>Phone: +1-555-0100</p>"
            "<p>Address: 123 Main St, Anytown, USA</p>"
            "<p>Account created: 2024-01-15</p>"
            "</body></html>"
        )
        client = _mock_client(get_text=profile_body)
        sm = _url_sitemap("https://example.com/profile")
        findings = run_checks(client, "https://example.com", sm)
        ac_005 = [f for f in findings if f.rule_id == "DAST-AC-005"]
        assert len(ac_005) == 1

    def test_login_page_not_flagged(self):
        client = _mock_client(
            get_text="<html><h1>Login</h1><form>Sign in to your account</form></html>",
        )
        sm = _url_sitemap("https://example.com/account/login")
        findings = run_checks(client, "https://example.com", sm)
        ac_005 = [f for f in findings if f.rule_id == "DAST-AC-005"]
        assert len(ac_005) == 0


class TestPrivilegeEscalation:
    """DAST-AC-006: Privilege escalation via params."""

    def test_admin_param_accepted(self):
        client = _mock_client(get_text="<html>Admin panel</html>")
        sm = _url_sitemap("https://example.com/page?role=user")
        findings = run_checks(client, "https://example.com", sm)
        ac_006 = [f for f in findings if f.rule_id == "DAST-AC-006"]
        assert len(ac_006) == 1

    def test_no_priv_param(self):
        client = _mock_client()
        sm = _url_sitemap("https://example.com/page?color=blue")
        findings = run_checks(client, "https://example.com", sm)
        ac_006 = [f for f in findings if f.rule_id == "DAST-AC-006"]
        assert len(ac_006) == 0


class TestRunChecks:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        client = _mock_client(probe_results={
            "admin": (200, "<html>Admin Dashboard with settings and configuration</html>"),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        for f in findings:
            assert f.category == "access_control"
            assert f.target_type == "dast"

    def test_empty_sitemap(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        assert isinstance(findings, list)
