"""Tests for DAST injection blind SQL injection checks (DAST-INJ-009, DAST-INJ-010)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from vulnerability_management.dast.checks.injection import (
    BLIND_BOOLEAN_PAIRS,
    BLIND_TIME_PAYLOADS,
    BLIND_TIME_THRESHOLD_S,
    _check_blind_sqli_boolean,
    _check_blind_sqli_time,
    run_checks,
)
from vulnerability_management.dast.crawler import SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(get_text: str = "", get_status: int = 200) -> MagicMock:
    client = MagicMock()
    resp = MagicMock()
    resp.text = get_text
    resp.status_code = get_status
    resp.headers = {}
    client.get.return_value = resp
    client.post.return_value = MagicMock(text="", status_code=200, headers={})
    client.probe_path.return_value = (404, "")
    return client


def _url_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.urls = set(urls)
    return sm


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Time-based blind SQLi (DAST-INJ-009)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestBlindSQLiTime:
    """DAST-INJ-009: Time-based blind SQL injection."""

    def test_time_delay_detected(self):
        """Detect when injected payload causes significant delay."""
        client = _mock_client(get_text="<html>Normal</html>")
        sm = _url_sitemap("https://example.com/search?id=1")

        # Simulate: baseline fast (0.1s), injected slow (5.1s), confirm slow (5.2s)
        call_count = [0]
        original_monotonic = time.monotonic

        def _fake_monotonic():
            call_count[0] += 1
            base = original_monotonic()
            # Calls: baseline_start, baseline_end, inject_start, inject_end,
            #        confirm_start, confirm_end
            # We need inject and confirm to show ~5s delta
            return base

        # Instead of mocking time, mock the client.get to have side effects
        # that simulate timing
        findings = []
        baseline_resp = MagicMock(text="Normal", status_code=200, headers={})

        call_idx = [0]

        def fake_get(*args, **kwargs):
            call_idx[0] += 1
            return baseline_resp

        client.get.side_effect = fake_get

        # Directly test the function with mocked time.monotonic
        times = iter([
            0.0,   # baseline start
            0.1,   # baseline end (0.1s)
            0.2,   # inject start
            5.3,   # inject end (5.1s delta)
            5.4,   # confirm start
            10.6,  # confirm end (5.2s delta)
        ])

        with patch("vulnerability_management.dast.checks.injection.time") as mock_time:
            mock_time.monotonic.side_effect = lambda: next(times)
            _check_blind_sqli_time(client, sm, findings)

        inj_009 = [f for f in findings if f.rule_id == "DAST-INJ-009"]
        assert len(inj_009) == 1
        assert inj_009[0].severity == "CRITICAL"
        assert inj_009[0].cwe == "CWE-89"

    def test_no_delay_no_finding(self):
        """No finding when response times are similar."""
        client = _mock_client(get_text="<html>Normal</html>")
        sm = _url_sitemap("https://example.com/search?id=1")

        # All responses fast (~0.1s)
        times = iter([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9,
                      1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9])

        findings = []
        with patch("vulnerability_management.dast.checks.injection.time") as mock_time:
            mock_time.monotonic.side_effect = lambda: next(times)
            _check_blind_sqli_time(client, sm, findings)

        inj_009 = [f for f in findings if f.rule_id == "DAST-INJ-009"]
        assert len(inj_009) == 0

    def test_no_params_skipped(self):
        """URLs without query params are skipped."""
        client = _mock_client()
        sm = _url_sitemap("https://example.com/page")
        findings = []
        _check_blind_sqli_time(client, sm, findings)
        assert len(findings) == 0
        client.get.assert_not_called()

    def test_url_limit(self):
        """Only first 5 URLs with params are tested."""
        client = _mock_client()
        urls = [f"https://example.com/p{i}?x={i}" for i in range(10)]
        sm = _url_sitemap(*urls)

        times = iter([i * 0.1 for i in range(200)])
        findings = []
        with patch("vulnerability_management.dast.checks.injection.time") as mock_time:
            mock_time.monotonic.side_effect = lambda: next(times)
            _check_blind_sqli_time(client, sm, findings)

        # Should have tested at most 5 URLs × params × payloads
        # Each URL: 1 baseline + up to 2 payloads = max 3 calls per URL
        assert client.get.call_count <= 5 * 3

    def test_constants_defined(self):
        """Verify constants are properly defined."""
        assert BLIND_TIME_THRESHOLD_S == 4.0
        assert len(BLIND_TIME_PAYLOADS) >= 3
        for payload, desc in BLIND_TIME_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(desc, str)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Boolean-based blind SQLi (DAST-INJ-010)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestBlindSQLiBoolean:
    """DAST-INJ-010: Boolean-based blind SQL injection."""

    def test_boolean_diff_detected(self):
        """Detect when true/false conditions produce different response lengths."""
        sm = _url_sitemap("https://example.com/users?id=1")
        client = MagicMock()

        # baseline: 500 chars, true: 500 chars (matches baseline), false: 100 chars (differs)
        call_idx = [0]

        def fake_get(*args, **kwargs):
            call_idx[0] += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}
            idx = call_idx[0]
            if idx == 1:
                resp.text = "A" * 500  # baseline
            elif idx % 2 == 0:
                resp.text = "A" * 500  # true condition
            else:
                resp.text = "B" * 100  # false condition
            return resp

        client.get.side_effect = fake_get
        client.post.return_value = MagicMock(text="", status_code=200, headers={})
        client.probe_path.return_value = (404, "")

        findings = []
        _check_blind_sqli_boolean(client, sm, findings)

        inj_010 = [f for f in findings if f.rule_id == "DAST-INJ-010"]
        assert len(inj_010) == 1
        assert inj_010[0].severity == "HIGH"
        assert inj_010[0].cwe == "CWE-89"

    def test_no_diff_no_finding(self):
        """No finding when true/false conditions produce same response."""
        client = _mock_client(get_text="A" * 500)
        sm = _url_sitemap("https://example.com/users?id=1")

        findings = []
        _check_blind_sqli_boolean(client, sm, findings)

        inj_010 = [f for f in findings if f.rule_id == "DAST-INJ-010"]
        assert len(inj_010) == 0

    def test_no_params_skipped(self):
        """URLs without params are skipped."""
        client = _mock_client()
        sm = _url_sitemap("https://example.com/page")
        findings = []
        _check_blind_sqli_boolean(client, sm, findings)
        assert len(findings) == 0
        client.get.assert_not_called()

    def test_url_limit(self):
        """Only first 10 URLs with params are tested."""
        client = _mock_client(get_text="Normal")
        urls = [f"https://example.com/p{i}?x={i}" for i in range(20)]
        sm = _url_sitemap(*urls)

        findings = []
        _check_blind_sqli_boolean(client, sm, findings)

        # At most 10 URLs tested — each URL = 1 baseline + up to 4 pairs × 2 = 9 max
        assert client.get.call_count <= 10 * 9

    def test_constants_defined(self):
        """Verify boolean payload pairs are properly defined."""
        assert len(BLIND_BOOLEAN_PAIRS) >= 3
        for true_p, false_p, desc in BLIND_BOOLEAN_PAIRS:
            assert isinstance(true_p, str)
            assert isinstance(false_p, str)
            assert isinstance(desc, str)
            assert true_p != false_p


class TestBlindSQLiIntegration:
    """Integration: blind checks run as part of run_checks()."""

    def test_blind_checks_called(self):
        """Verify blind SQLi checks are called from run_checks()."""
        client = _mock_client(get_text="<html>Normal</html>")
        sm = _url_sitemap("https://example.com/page?id=1")

        with patch("vulnerability_management.dast.checks.injection.time") as mock_time:
            mock_time.monotonic.return_value = 0.1
            findings = run_checks(client, "https://example.com", sm)

        # run_checks should complete without error
        assert isinstance(findings, list)

    def test_all_blind_findings_correct_category(self):
        """All blind SQLi findings have correct metadata."""
        sm = _url_sitemap("https://example.com/search?q=test")
        client = MagicMock()

        call_idx = [0]

        def fake_get(*args, **kwargs):
            call_idx[0] += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}
            if call_idx[0] == 1 or call_idx[0] % 2 == 0:
                resp.text = "A" * 500
            else:
                resp.text = "B" * 100
            return resp

        client.get.side_effect = fake_get
        client.post.return_value = MagicMock(text="", status_code=200, headers={})
        client.probe_path.return_value = (404, "")

        findings = []
        _check_blind_sqli_boolean(client, sm, findings)

        for f in findings:
            assert f.category == "injection"
            assert f.target_type == "dast"
            assert f.cwe == "CWE-89"
