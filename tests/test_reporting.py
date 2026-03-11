"""Tests for skyhigh_scanner.core.reporting."""

import pytest

from skyhigh_scanner.core.reporting import (
    HAS_WEASYPRINT,
    SEVERITY_BADGE,
    THEME_COLORS,
    _build_charts_data,
    _build_charts_section,
    _build_pdf_html,
    generate_html_report,
    generate_pdf_report,
)


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


# ── PDF HTML generation (always testable, no weasyprint needed) ──────

def _pdf_summary(**overrides):
    """Build a minimal summary dict for PDF tests."""
    defaults = {
        "scan_duration_seconds": 2.0,
        "targets_scanned": 3,
        "targets_failed": 0,
        "kev_findings": 0,
        "severity_counts": {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        },
    }
    defaults.update(overrides)
    return defaults


class TestBuildPdfHtml:
    """Tests for _build_pdf_html — the print-optimised HTML template."""

    def test_basic_structure(self, sample_findings):
        html_out = _build_pdf_html(
            "Test Scanner", "1.0.0", "generic",
            sample_findings, _pdf_summary(),
        )
        assert "<!DOCTYPE html>" in html_out
        assert "Test Scanner" in html_out
        assert "v1.0.0" in html_out

    def test_no_javascript(self, sample_findings):
        html_out = _build_pdf_html(
            "S", "1", "generic", sample_findings, _pdf_summary(),
        )
        assert "<script" not in html_out
        assert "filterFindings" not in html_out

    def test_white_background(self):
        html_out = _build_pdf_html(
            "S", "1", "generic", [], _pdf_summary(),
        )
        # PDF template should NOT have dark background
        assert "background:#1a1a2e" not in html_out

    def test_findings_expanded(self, sample_findings):
        html_out = _build_pdf_html(
            "S", "1", "generic", sample_findings, _pdf_summary(),
        )
        # All findings should have visible body (no display:none)
        assert "display:none" not in html_out

    def test_all_findings_present(self, sample_findings):
        html_out = _build_pdf_html(
            "S", "1", "generic", sample_findings, _pdf_summary(),
        )
        for f in sample_findings:
            assert f.rule_id in html_out

    def test_severity_badges(self, sample_findings):
        html_out = _build_pdf_html(
            "S", "1", "generic", sample_findings,
            _pdf_summary(severity_counts={
                "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1,
            }),
        )
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in html_out

    def test_kev_badge(self, sample_finding):
        html_out = _build_pdf_html(
            "S", "1", "generic", [sample_finding],
            _pdf_summary(kev_findings=1),
        )
        assert "ACTIVELY EXPLOITED" in html_out

    def test_cve_and_cvss(self, sample_finding):
        html_out = _build_pdf_html(
            "S", "1", "generic", [sample_finding], _pdf_summary(),
        )
        assert "CVE-2024-99999" in html_out
        assert "CVSS 7.5" in html_out

    def test_target_type_theme(self):
        for tt in ("windows", "linux", "cisco"):
            html_out = _build_pdf_html("S", "1", tt, [], _pdf_summary())
            primary, _ = THEME_COLORS[tt]
            assert primary in html_out

    def test_targets_table(self):
        html_out = _build_pdf_html(
            "S", "1", "generic", [],
            _pdf_summary(targets_scanned=2, targets_failed=1),
            targets_scanned=["10.0.0.1", "10.0.0.2"],
            targets_failed=["10.0.0.2"],
        )
        assert "10.0.0.1" in html_out
        assert "10.0.0.2" in html_out
        assert "Failed" in html_out

    def test_empty_findings(self):
        html_out = _build_pdf_html("S", "1", "generic", [], _pdf_summary())
        assert "<!DOCTYPE html>" in html_out
        assert "Total" in html_out

    def test_compliance_section(self):
        from skyhigh_scanner.core.compliance import enrich_finding
        from skyhigh_scanner.core.finding import Finding

        f = Finding(
            rule_id="PDF-001", name="SQL Injection", category="Injection",
            severity="CRITICAL", file_path="target", line_num=0,
            line_content="query(input)", description="desc",
            recommendation="fix", cwe="CWE-89",
        )
        enrich_finding(f)
        html_out = _build_pdf_html(
            "S", "1", "generic", [f],
            _pdf_summary(severity_counts={"CRITICAL": 1, "HIGH": 0,
                                          "MEDIUM": 0, "LOW": 0, "INFO": 0}),
        )
        assert "Compliance Framework Mapping" in html_out
        assert "NIST" in html_out

    def test_epss_badge(self):
        from skyhigh_scanner.core.finding import Finding

        f = Finding(
            rule_id="PDF-002", name="Test", category="Test",
            severity="HIGH", file_path="t", line_num=0,
            line_content="", description="d", recommendation="r",
            epss=0.85,
        )
        html_out = _build_pdf_html(
            "S", "1", "generic", [f],
            _pdf_summary(severity_counts={"CRITICAL": 0, "HIGH": 1,
                                          "MEDIUM": 0, "LOW": 0, "INFO": 0}),
        )
        assert "EPSS 85.0%" in html_out
        assert "epss-high" in html_out

    def test_html_escaping(self):
        from skyhigh_scanner.core.finding import Finding

        f = Finding(
            rule_id="XSS-001",
            name="<script>alert(1)</script>",
            category="Test", severity="HIGH",
            file_path="<img>", line_num=0,
            line_content='"; DROP TABLE;--',
            description="Desc <b>bold</b>",
            recommendation="Fix & update",
        )
        html_out = _build_pdf_html(
            "S", "1", "generic", [f],
            _pdf_summary(severity_counts={"CRITICAL": 0, "HIGH": 1,
                                          "MEDIUM": 0, "LOW": 0, "INFO": 0}),
        )
        assert "&lt;script&gt;" in html_out
        assert "<script>alert(1)</script>" not in html_out
        assert "&amp;" in html_out

    def test_page_size_directive(self):
        html_out = _build_pdf_html("S", "1", "generic", [], _pdf_summary())
        assert "@page" in html_out
        assert "A4" in html_out


class TestGeneratePdfReport:
    """Tests for generate_pdf_report — the full PDF pipeline."""

    def test_raises_without_weasyprint(self, monkeypatch):
        """When weasyprint is not installed, generate_pdf_report raises RuntimeError."""
        import skyhigh_scanner.core.reporting as rmod
        monkeypatch.setattr(rmod, "HAS_WEASYPRINT", False)
        with pytest.raises(RuntimeError, match="weasyprint"):
            generate_pdf_report(
                "S", "1", "generic", [], _pdf_summary(),
            )

    def _mock_weasyprint(self, monkeypatch):
        """Enable weasyprint mock so generate_pdf_report doesn't skip or fail."""
        from unittest.mock import MagicMock
        import skyhigh_scanner.core.reporting as rmod

        fake_pdf = b"%PDF-1.4 fake pdf content for testing"
        mock_html_cls = MagicMock()
        mock_html_cls.return_value.write_pdf.return_value = fake_pdf
        monkeypatch.setattr(rmod, "HAS_WEASYPRINT", True)
        monkeypatch.setattr(rmod, "weasyprint", MagicMock(HTML=mock_html_cls), raising=False)
        return fake_pdf

    def test_returns_bytes(self, sample_findings, monkeypatch):
        self._mock_weasyprint(monkeypatch)
        result = generate_pdf_report(
            "Test Scanner", "1.0.0", "generic",
            sample_findings, _pdf_summary(severity_counts={
                "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1,
            }),
        )
        assert isinstance(result, bytes)
        assert result[:5] == b"%PDF-"

    def test_pdf_with_compliance(self, monkeypatch):
        from skyhigh_scanner.core.compliance import enrich_finding
        from skyhigh_scanner.core.finding import Finding

        self._mock_weasyprint(monkeypatch)
        f = Finding(
            rule_id="PDF-C01", name="Test", category="Auth",
            severity="HIGH", file_path="t", line_num=0,
            line_content="", description="d", recommendation="r",
            cwe="CWE-287",
        )
        enrich_finding(f)
        result = generate_pdf_report(
            "S", "1", "generic", [f],
            _pdf_summary(severity_counts={"CRITICAL": 0, "HIGH": 1,
                                          "MEDIUM": 0, "LOW": 0, "INFO": 0}),
        )
        assert isinstance(result, bytes)
        assert result[:5] == b"%PDF-"

    def test_pdf_empty_findings(self, monkeypatch):
        self._mock_weasyprint(monkeypatch)
        result = generate_pdf_report("S", "1", "generic", [], _pdf_summary())
        assert isinstance(result, bytes)
        assert result[:5] == b"%PDF-"

    def test_pdf_write_to_file(self, tmp_path, monkeypatch):
        self._mock_weasyprint(monkeypatch)
        result = generate_pdf_report("S", "1", "generic", [], _pdf_summary())
        pdf_path = tmp_path / "report.pdf"
        pdf_path.write_bytes(result)
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0


class TestCliPdfFlag:
    """Test that the --pdf CLI argument is accepted."""

    def test_pdf_flag_parses(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24", "--pdf", "report.pdf"])
        assert args.pdf_file == "report.pdf"

    def test_pdf_default_none(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24"])
        assert args.pdf_file is None

    def test_pdf_with_other_outputs(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "linux", "-r", "10.0.0.0/24",
            "--pdf", "report.pdf",
            "--html", "report.html",
            "--json", "report.json",
            "--csv", "report.csv",
        ])
        assert args.pdf_file == "report.pdf"
        assert args.html_file == "report.html"
        assert args.json_file == "report.json"
        assert args.csv_file == "report.csv"


# ── Chart.js Dashboard ──────────────────────────────────────────────

def _chart_summary(**overrides):
    """Build a minimal summary dict for chart tests."""
    defaults = {
        "scan_duration_seconds": 1.0,
        "targets_scanned": 3,
        "targets_failed": 0,
        "kev_findings": 0,
        "severity_counts": {
            "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1,
        },
    }
    defaults.update(overrides)
    return defaults


class TestBuildChartsData:
    def test_severity_data(self, sample_findings):
        data = _build_charts_data(sample_findings, _chart_summary())
        assert data["severity"]["labels"] == ["Critical", "High", "Medium", "Low", "Info"]
        assert data["severity"]["data"] == [1, 1, 1, 1, 1]
        assert len(data["severity"]["colors"]) == 5

    def test_category_counts(self, sample_findings):
        data = _build_charts_data(sample_findings, _chart_summary())
        # All sample_findings have category="Test"
        assert data["categories"]["labels"] == ["Test"]
        assert data["categories"]["data"] == [5]

    def test_target_counts(self, sample_findings):
        data = _build_charts_data(sample_findings, _chart_summary())
        # sample_findings: file_path = 10.0.0.1 through 10.0.0.5
        assert len(data["targets"]["labels"]) == 5
        assert all(c == 1 for c in data["targets"]["data"])

    def test_epss_buckets_none(self, sample_findings):
        """sample_findings have no EPSS — all should be in 'none' bucket."""
        data = _build_charts_data(sample_findings, _chart_summary())
        assert data["epss"]["data"][3] == 5  # "No EPSS"
        assert data["epss"]["data"][0] == 0  # >=50%

    def test_epss_buckets_mixed(self):
        from skyhigh_scanner.core.finding import Finding
        findings = [
            Finding(rule_id="E-1", name="t", category="C", severity="HIGH",
                    file_path="x", line_num=0, line_content="", description="d",
                    recommendation="r", epss=0.9),
            Finding(rule_id="E-2", name="t", category="C", severity="HIGH",
                    file_path="x", line_num=0, line_content="", description="d",
                    recommendation="r", epss=0.25),
            Finding(rule_id="E-3", name="t", category="C", severity="HIGH",
                    file_path="x", line_num=0, line_content="", description="d",
                    recommendation="r", epss=0.05),
            Finding(rule_id="E-4", name="t", category="C", severity="HIGH",
                    file_path="x", line_num=0, line_content="", description="d",
                    recommendation="r"),
        ]
        data = _build_charts_data(findings, _chart_summary(
            severity_counts={"CRITICAL": 0, "HIGH": 4, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        ))
        assert data["epss"]["data"] == [1, 1, 1, 1]  # high, med, low, none

    def test_top_targets_limited_to_10(self):
        from skyhigh_scanner.core.finding import Finding
        findings = [
            Finding(rule_id=f"T-{i}", name="t", category="C", severity="HIGH",
                    file_path=f"10.0.0.{i}", line_num=0, line_content="",
                    description="d", recommendation="r")
            for i in range(15)
        ]
        data = _build_charts_data(findings, _chart_summary())
        assert len(data["targets"]["labels"]) == 10

    def test_top_categories_limited_to_12(self):
        from skyhigh_scanner.core.finding import Finding
        findings = [
            Finding(rule_id=f"C-{i}", name="t", category=f"Cat{i}", severity="HIGH",
                    file_path="x", line_num=0, line_content="",
                    description="d", recommendation="r")
            for i in range(15)
        ]
        data = _build_charts_data(findings, _chart_summary())
        assert len(data["categories"]["labels"]) == 12

    def test_empty_findings(self):
        data = _build_charts_data([], _chart_summary(
            severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        ))
        assert data["categories"]["labels"] == []
        assert data["targets"]["labels"] == []


class TestBuildChartsSection:
    def test_returns_empty_for_no_findings(self):
        result = _build_charts_section([], _chart_summary())
        assert result == ""

    def test_contains_chart_elements(self, sample_findings):
        result = _build_charts_section(sample_findings, _chart_summary())
        assert "chartSeverity" in result
        assert "chartEpss" in result
        assert "chartCategory" in result
        assert "chartTargets" in result

    def test_contains_chartjs_cdn(self, sample_findings):
        result = _build_charts_section(sample_findings, _chart_summary())
        assert "chart.js" in result
        assert "cdn.jsdelivr.net" in result

    def test_contains_data_json(self, sample_findings):
        result = _build_charts_section(sample_findings, _chart_summary())
        assert '"severity"' in result
        assert '"categories"' in result

    def test_dashboard_title(self, sample_findings):
        result = _build_charts_section(sample_findings, _chart_summary())
        assert "Dashboard" in result


class TestHtmlReportDashboard:
    def test_charts_present_with_findings(self, sample_findings):
        html_out = generate_html_report(
            "Test Scanner", "1.0.0", "generic",
            sample_findings, _chart_summary(),
        )
        assert "chartSeverity" in html_out
        assert "charts-section" in html_out

    def test_charts_absent_without_findings(self):
        html_out = generate_html_report(
            "S", "1", "generic", [],
            _chart_summary(severity_counts={
                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
            }),
        )
        assert "chartSeverity" not in html_out
        # The div element should not be present (CSS class name appears in stylesheet)
        assert '<div class="charts-section">' not in html_out

    def test_charts_css_present(self, sample_findings):
        html_out = generate_html_report(
            "S", "1", "generic", sample_findings, _chart_summary(),
        )
        assert ".charts-grid" in html_out
        assert ".chart-card" in html_out

    def test_category_filter_dropdown(self, sample_findings):
        html_out = generate_html_report(
            "S", "1", "generic", sample_findings, _chart_summary(),
        )
        assert "filterCategory" in html_out
        assert "All Categories" in html_out

    def test_charts_hidden_in_print(self, sample_findings):
        html_out = generate_html_report(
            "S", "1", "generic", sample_findings, _chart_summary(),
        )
        assert ".charts-section { display:none; }" in html_out
        # The double braces in the f-string become single in output
        # so let's check for the pattern correctly
        assert "charts-section" in html_out

    def test_info_in_severity_filter(self, sample_findings):
        html_out = generate_html_report(
            "S", "1", "generic", sample_findings, _chart_summary(),
        )
        assert '<option value="INFO">Info</option>' in html_out

    def test_no_charts_in_pdf(self, sample_findings):
        html_out = _build_pdf_html(
            "S", "1", "generic", sample_findings, _chart_summary(),
        )
        assert "chartSeverity" not in html_out
        assert "chart.js" not in html_out
