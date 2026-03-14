"""Tests for DAST-specific HTML report sections."""

from __future__ import annotations

from vulnerability_management.core.finding import Finding
from vulnerability_management.core.reporting import (
    _build_dast_sections,
    generate_html_report,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _dast_summary(**overrides) -> dict:
    """Build a minimal DAST summary dict."""
    base = {
        "severity_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "targets_scanned": 1,
        "targets_failed": 0,
        "scan_duration_seconds": 42,
        "kev_findings": 0,
        "dast_metadata": {
            "requests_sent": 150,
            "crawl": {
                "pages": 25,
                "forms": 8,
                "api_endpoints": 12,
                "sitemap_urls_added": 5,
                "robots_paths_added": 3,
                "redirect_count": 7,
                "status_codes": {"200": 20, "301": 5, "404": 2},
                "content_types": {"text/html": 22, "application/json": 5},
                "duration_seconds": 3.5,
                "api_endpoints_list": [
                    {"url": "https://example.com/api/users", "method": "GET", "source": "link"},
                    {"url": "https://example.com/api/login", "method": "POST", "source": "form"},
                ],
                "tech_fingerprint": {
                    "server": "nginx/1.24",
                    "framework": "Express",
                    "cms": None,
                    "language": "Node.js",
                    "js_frameworks": ["React", "jQuery"],
                },
            },
            "auth_mode": "cookie",
            "passive_only": False,
            "rate_limit_rps": 10,
            "performance": {
                "avg_response_time_ms": 45.2,
                "p95_response_time_ms": 120.5,
            },
        },
    }
    base.update(overrides)
    return base


def _non_dast_summary() -> dict:
    """Build a summary without dast_metadata."""
    return {
        "severity_counts": {"CRITICAL": 0, "HIGH": 1},
        "targets_scanned": 1,
        "targets_failed": 0,
        "scan_duration_seconds": 10,
        "kev_findings": 0,
    }


def _sample_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="DAST-INJ-001",
        name="Test finding",
        category="injection",
        severity="CRITICAL",
        file_path="https://example.com/search",
        line_num=0,
        line_content="Payload: ' OR 1=1",
        description="Test description",
        recommendation="Fix it",
        target_type="dast",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests: _build_dast_sections()
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestBuildDastSections:
    """Test the _build_dast_sections() function."""

    def test_returns_empty_for_non_dast(self):
        result = _build_dast_sections(_non_dast_summary())
        assert result == ""

    def test_returns_empty_for_no_metadata(self):
        result = _build_dast_sections({})
        assert result == ""

    def test_crawl_summary_present(self):
        result = _build_dast_sections(_dast_summary())
        assert "Crawl Summary" in result
        assert "25" in result  # pages
        assert "8" in result   # forms
        assert "12" in result  # api endpoints

    def test_tech_fingerprint_present(self):
        result = _build_dast_sections(_dast_summary())
        assert "Technology Fingerprint" in result
        assert "nginx/1.24" in result
        assert "Express" in result
        assert "Node.js" in result

    def test_tech_fingerprint_absent_when_none(self):
        summary = _dast_summary()
        summary["dast_metadata"]["crawl"]["tech_fingerprint"] = None
        result = _build_dast_sections(summary)
        assert "Technology Fingerprint" not in result

    def test_response_analysis_present(self):
        result = _build_dast_sections(_dast_summary())
        assert "Response Analysis" in result
        assert "200" in result
        assert "text/html" in result

    def test_api_inventory_present(self):
        result = _build_dast_sections(_dast_summary())
        assert "API Endpoint Inventory" in result
        assert "/api/users" in result
        assert "/api/login" in result
        assert "POST" in result

    def test_api_inventory_absent_when_empty(self):
        summary = _dast_summary()
        summary["dast_metadata"]["crawl"]["api_endpoints_list"] = []
        result = _build_dast_sections(summary)
        assert "API Endpoint Inventory" not in result

    def test_attack_surface_present(self):
        result = _build_dast_sections(_dast_summary())
        assert "Attack Surface Summary" in result
        assert "150" in result   # requests sent
        assert "cookie" in result  # auth mode
        assert "10/s" in result  # rate limit

    def test_passive_only_shown(self):
        summary = _dast_summary()
        summary["dast_metadata"]["passive_only"] = True
        result = _build_dast_sections(summary)
        assert "Yes" in result

    def test_performance_metrics(self):
        result = _build_dast_sections(_dast_summary())
        assert "45ms" in result or "Avg Response" in result
        assert "121ms" in result or "P95 Response" in result

    def test_html_escaping(self):
        """Verify special characters are escaped."""
        summary = _dast_summary()
        summary["dast_metadata"]["auth_mode"] = "<script>alert(1)</script>"
        result = _build_dast_sections(summary)
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_empty_crawl_stats(self):
        """Handle empty crawl stats gracefully."""
        summary = _dast_summary()
        summary["dast_metadata"]["crawl"] = {}
        result = _build_dast_sections(summary)
        # Should still produce attack surface section
        assert "Attack Surface Summary" in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests: Full report integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDastReportIntegration:
    """Test DAST sections appear in full HTML reports."""

    def test_dast_sections_in_html_report(self):
        findings = [_sample_finding()]
        summary = _dast_summary()
        report = generate_html_report(
            scanner_name="VulnMgmt DAST Scanner",
            version="1.0.0",
            target_type="dast",
            findings=findings,
            summary=summary,
            targets_scanned=["https://example.com"],
        )
        assert "Crawl Summary" in report
        assert "Attack Surface Summary" in report
        assert "dast-section" in report
        assert "dast-grid" in report

    def test_non_dast_report_no_dast_sections(self):
        findings = [_sample_finding(rule_id="LINUX-AUTH-001", category="auth",
                                     target_type="linux")]
        summary = _non_dast_summary()
        report = generate_html_report(
            scanner_name="VulnMgmt Linux Scanner",
            version="1.0.0",
            target_type="linux",
            findings=findings,
            summary=summary,
        )
        assert "Crawl Summary" not in report
        assert "Attack Surface Summary" not in report

    def test_dast_css_present(self):
        findings = [_sample_finding()]
        summary = _dast_summary()
        report = generate_html_report(
            scanner_name="VulnMgmt DAST Scanner",
            version="1.0.0",
            target_type="dast",
            findings=findings,
            summary=summary,
        )
        assert ".dast-section" in report
        assert ".dast-grid" in report
        assert ".dast-stat" in report
        assert ".dast-table" in report

    def test_report_valid_html(self):
        findings = [_sample_finding()]
        summary = _dast_summary()
        report = generate_html_report(
            scanner_name="VulnMgmt DAST Scanner",
            version="1.0.0",
            target_type="dast",
            findings=findings,
            summary=summary,
        )
        assert report.startswith("<!DOCTYPE html>")
        assert "</html>" in report
