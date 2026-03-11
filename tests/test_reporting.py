"""Tests for skyhigh_scanner.core.reporting."""

import pytest

from skyhigh_scanner.core.reporting import generate_html_report, THEME_COLORS, SEVERITY_BADGE


class TestHtmlReport:
    def test_basic_generation(self, sample_findings):
        summary = {
            "scan_duration_seconds": 1.5,
            "targets_scanned": 5,
            "targets_failed": 1,
            "kev_findings": 0,
            "severity_counts": {
                "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1,
            },
        }
        html = generate_html_report(
            scanner_name="Test Scanner",
            version="1.0.0",
            target_type="generic",
            findings=sample_findings,
            summary=summary,
        )
        assert "<!DOCTYPE html>" in html
        assert "Test Scanner" in html
        assert "v1.0.0" in html

    def test_findings_present(self, sample_findings):
        summary = {
            "scan_duration_seconds": 0,
            "targets_scanned": 1,
            "targets_failed": 0,
            "kev_findings": 0,
            "severity_counts": {
                "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1,
            },
        }
        html = generate_html_report(
            scanner_name="S", version="1", target_type="generic",
            findings=sample_findings, summary=summary,
        )
        for f in sample_findings:
            assert f.rule_id in html

    def test_kev_badge(self, sample_finding):
        summary = {
            "scan_duration_seconds": 0,
            "targets_scanned": 1,
            "targets_failed": 0,
            "kev_findings": 1,
            "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        html = generate_html_report(
            scanner_name="S", version="1", target_type="generic",
            findings=[sample_finding], summary=summary,
        )
        assert "ACTIVELY EXPLOITED" in html

    def test_cve_and_cvss_tags(self, sample_finding):
        summary = {
            "scan_duration_seconds": 0, "targets_scanned": 1, "targets_failed": 0,
            "kev_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        html = generate_html_report(
            scanner_name="S", version="1", target_type="generic",
            findings=[sample_finding], summary=summary,
        )
        assert "CVE-2024-99999" in html
        assert "CVSS 7.5" in html

    def test_theme_colors(self):
        for tt in ("windows", "linux", "cisco", "webserver", "middleware", "database"):
            assert tt in THEME_COLORS
            primary, secondary = THEME_COLORS[tt]
            assert primary.startswith("#")
            assert secondary.startswith("#")

    def test_target_type_specific_theme(self, sample_findings):
        summary = {
            "scan_duration_seconds": 0, "targets_scanned": 0, "targets_failed": 0,
            "kev_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        for target_type in ("windows", "linux", "cisco"):
            html = generate_html_report(
                scanner_name="S", version="1", target_type=target_type,
                findings=[], summary=summary,
            )
            primary, _ = THEME_COLORS[target_type]
            assert primary in html

    def test_targets_table(self, sample_findings):
        summary = {
            "scan_duration_seconds": 0, "targets_scanned": 2, "targets_failed": 1,
            "kev_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        html = generate_html_report(
            scanner_name="S", version="1", target_type="generic",
            findings=[], summary=summary,
            targets_scanned=["10.0.0.1", "10.0.0.2"],
            targets_failed=["10.0.0.2"],
        )
        assert "10.0.0.1" in html
        assert "10.0.0.2" in html
        assert "Failed" in html

    def test_html_escaping(self):
        """Ensure XSS-prone content is escaped."""
        from skyhigh_scanner.core.finding import Finding

        f = Finding(
            rule_id="XSS-001",
            name="<script>alert(1)</script>",
            category="Test",
            severity="HIGH",
            file_path="<img onerror=alert(1)>",
            line_num=0,
            line_content='"; DROP TABLE users;--',
            description="Desc with <b>html</b>",
            recommendation="Fix & update",
        )
        summary = {
            "scan_duration_seconds": 0, "targets_scanned": 1, "targets_failed": 0,
            "kev_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        html = generate_html_report(
            scanner_name="S", version="1", target_type="generic",
            findings=[f], summary=summary,
        )
        # The finding name should be escaped, not raw script tags in finding cards
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "&amp;" in html
        # Raw <script>alert(1)</script> must NOT appear
        assert "<script>alert(1)</script>" not in html

    def test_empty_findings(self):
        summary = {
            "scan_duration_seconds": 0, "targets_scanned": 0, "targets_failed": 0,
            "kev_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        html = generate_html_report(
            scanner_name="S", version="1", target_type="generic",
            findings=[], summary=summary,
        )
        assert "<!DOCTYPE html>" in html
        assert "Total Findings" in html


class TestSeverityBadge:
    def test_all_severities_have_colors(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in SEVERITY_BADGE
            assert SEVERITY_BADGE[sev].startswith("#")
