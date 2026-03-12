"""
Tests for Phase 4 — DAST Evidence Propagation.

Verifies that:
  - Finding evidence field works correctly
  - Evidence flows through to JSON serialisation
  - Evidence renders in HTML reports
  - Evidence renders in PDF reports
  - Evidence appears in SARIF properties
  - Evidence appears in console report
  - DastScanner summary includes DAST metadata
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from skyhigh_scanner.core.finding import Finding
from skyhigh_scanner.core.reporting import (
    _build_evidence_html,
    _build_pdf_evidence_html,
    generate_html_report,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test Finding evidence field
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestFindingEvidence:
    """Finding dataclass evidence field tests."""

    def _make_finding(self, evidence=None):
        return Finding(
            rule_id="DAST-INJ-001",
            name="SQL injection in URL parameter: q",
            category="injection",
            severity="CRITICAL",
            file_path="https://example.com/search",
            line_num=0,
            line_content="Payload: ' → SQL error detected",
            description="SQL injection detected.",
            recommendation="Use parameterized queries.",
            cwe="CWE-89",
            target_type="dast",
            evidence=evidence,
        )

    def test_evidence_default_none(self):
        f = self._make_finding()
        assert f.evidence is None

    def test_evidence_assigned(self):
        ev = [{"method": "GET", "url": "http://x.com", "status": 200,
               "payload": "'", "proof": "SQL error"}]
        f = self._make_finding(evidence=ev)
        assert f.evidence == ev
        assert len(f.evidence) == 1
        assert f.evidence[0]["method"] == "GET"

    def test_evidence_in_to_dict(self):
        ev = [{"method": "POST", "url": "http://x.com/form", "status": 500,
               "payload": "1 OR 1=1", "proof": "error near"}]
        f = self._make_finding(evidence=ev)
        d = f.to_dict()
        assert "evidence" in d
        assert d["evidence"][0]["status"] == 500

    def test_evidence_none_excluded_from_dict(self):
        f = self._make_finding(evidence=None)
        d = f.to_dict()
        assert "evidence" not in d

    def test_evidence_in_json(self):
        ev = [{"method": "GET", "url": "http://x.com", "status": 200,
               "payload": "'", "proof": "err"}]
        f = self._make_finding(evidence=ev)
        j = json.loads(f.to_json())
        assert "evidence" in j
        assert j["evidence"][0]["payload"] == "'"

    def test_multiple_evidence_items(self):
        ev = [
            {"method": "GET", "url": "http://x.com?q=1", "status": 200,
             "payload": "'", "proof": "err1"},
            {"method": "GET", "url": "http://x.com?q=2", "status": 500,
             "payload": "1 OR 1=1", "proof": "err2"},
        ]
        f = self._make_finding(evidence=ev)
        assert len(f.evidence) == 2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test HTML evidence rendering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestHTMLEvidence:
    """HTML report evidence rendering tests."""

    def test_evidence_html_empty(self):
        assert _build_evidence_html(None) == ""
        assert _build_evidence_html([]) == ""

    def test_evidence_html_renders(self):
        ev = [{"method": "GET", "url": "http://x.com?q='",
               "status": 200, "payload": "'", "proof": "SQL error"}]
        result = _build_evidence_html(ev)
        assert "evidence-section" in result
        assert "evidence-title" in result
        assert "GET" in result
        assert "SQL error" in result

    def test_evidence_html_escapes_xss(self):
        ev = [{"method": "GET", "url": "http://x.com",
               "status": 200, "payload": "<script>alert(1)</script>",
               "proof": "<img onerror=x>"}]
        result = _build_evidence_html(ev)
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_evidence_passive_check_hides_payload(self):
        ev = [{"method": "HEAD", "url": "http://x.com",
               "status": 200, "payload": "(none — passive check)",
               "proof": "Server: Apache/2.4"}]
        result = _build_evidence_html(ev)
        assert "Payload:" not in result
        assert "Server: Apache/2.4" in result

    def test_evidence_in_full_html_report(self):
        ev = [{"method": "GET", "url": "http://x.com?q='",
               "status": 200, "payload": "'", "proof": "SQL error"}]
        f = Finding(
            rule_id="DAST-INJ-001", name="SQLi", category="injection",
            severity="CRITICAL", file_path="http://x.com/search",
            line_num=0, line_content="test", description="desc",
            recommendation="fix", target_type="dast", evidence=ev,
        )
        summary = {
            "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0},
            "scan_duration_seconds": 5,
            "targets_scanned": 1,
            "targets_failed": 0,
            "kev_findings": 0,
        }
        html = generate_html_report(
            "Test Scanner", "1.0.0", "dast", [f], summary,
        )
        assert "evidence-section" in html
        assert "SQL error" in html


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test PDF evidence rendering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPDFEvidence:
    """PDF report evidence rendering tests."""

    def test_pdf_evidence_empty(self):
        assert _build_pdf_evidence_html(None) == ""
        assert _build_pdf_evidence_html([]) == ""

    def test_pdf_evidence_renders(self):
        ev = [{"method": "POST", "url": "http://x.com/api",
               "status": 500, "payload": "{'$gt': ''}",
               "proof": "NoSQL data returned"}]
        result = _build_pdf_evidence_html(ev)
        assert "ev-item" in result
        assert "POST" in result
        assert "NoSQL data returned" in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test SARIF evidence
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSARIFEvidence:
    """SARIF export evidence in properties bag."""

    def test_sarif_includes_evidence(self, tmp_path):
        from skyhigh_scanner.core.scanner_base import ScannerBase

        class TestScanner(ScannerBase):
            SCANNER_NAME = "Test"
            SCANNER_VERSION = "1.0.0"
            TARGET_TYPE = "dast"

            def scan(self):
                pass

        scanner = TestScanner()
        scanner._start_time = 1000.0
        scanner._end_time = 1010.0
        ev = [{"method": "GET", "url": "http://x.com", "status": 200,
               "payload": "'", "proof": "SQL error"}]
        scanner.findings.append(Finding(
            rule_id="DAST-INJ-001", name="SQLi", category="injection",
            severity="CRITICAL", file_path="http://x.com",
            line_num=0, line_content="test", description="desc",
            recommendation="fix", target_type="dast", evidence=ev,
        ))

        sarif_file = str(tmp_path / "test.sarif")
        scanner.save_sarif(sarif_file)

        with open(sarif_file) as fh:
            sarif = json.load(fh)

        result = sarif["runs"][0]["results"][0]
        assert "properties" in result
        assert "evidence" in result["properties"]
        assert result["properties"]["evidence"][0]["method"] == "GET"

    def test_sarif_no_evidence_when_none(self, tmp_path):
        from skyhigh_scanner.core.scanner_base import ScannerBase

        class TestScanner(ScannerBase):
            SCANNER_NAME = "Test"
            SCANNER_VERSION = "1.0.0"
            TARGET_TYPE = "dast"

            def scan(self):
                pass

        scanner = TestScanner()
        scanner._start_time = 1000.0
        scanner._end_time = 1010.0
        scanner.findings.append(Finding(
            rule_id="DAST-INJ-001", name="SQLi", category="injection",
            severity="CRITICAL", file_path="http://x.com",
            line_num=0, line_content="test", description="desc",
            recommendation="fix", target_type="dast",
        ))

        sarif_file = str(tmp_path / "test.sarif")
        scanner.save_sarif(sarif_file)

        with open(sarif_file) as fh:
            sarif = json.load(fh)

        result = sarif["runs"][0]["results"][0]
        props = result.get("properties", {})
        assert "evidence" not in props


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test DastScanner summary metadata
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDastScannerMetadata:
    """DastScanner summary includes DAST-specific metadata."""

    def test_summary_has_dast_metadata(self):
        from skyhigh_scanner.dast.config import DastConfig, ScopePolicy
        from skyhigh_scanner.scanners.dast_scanner import DastScanner

        scope = ScopePolicy(allowed_hosts={"example.com"})
        config = DastConfig(scope=scope)
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        # Simulate scan metadata
        scanner._request_count = 150
        scanner._crawl_stats = {"pages": 10, "forms": 3, "api_endpoints": 5}
        scanner._auth_mode = "form"

        s = scanner.summary()
        assert "dast_metadata" in s
        meta = s["dast_metadata"]
        assert meta["requests_sent"] == 150
        assert meta["crawl"]["pages"] == 10
        assert meta["auth_mode"] == "form"
        assert meta["passive_only"] is False
        assert meta["rate_limit_rps"] == config.rate_limit_rps


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test check module evidence integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCheckModuleEvidence:
    """Verify check modules produce findings with evidence."""

    def test_injection_sqli_has_evidence(self):
        """SQL injection findings should carry evidence."""
        from skyhigh_scanner.dast.checks.injection import _check_sql_injection_urls
        from skyhigh_scanner.dast.crawler import SiteMap

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "You have an error in your SQL syntax near 'test' at line 1" + " " * 200
        client.get.return_value = resp

        sitemap = SiteMap()
        sitemap.urls.add("https://example.com/search?q=test")

        findings = []
        _check_sql_injection_urls(client, sitemap, findings)
        assert len(findings) >= 1
        f = findings[0]
        assert f.evidence is not None
        assert len(f.evidence) >= 1
        assert f.evidence[0]["method"] == "GET"
        assert f.evidence[0]["payload"] == "'"
        assert "status" in f.evidence[0]

    def test_xss_reflected_has_evidence(self):
        """XSS findings should carry evidence."""
        from skyhigh_scanner.dast.checks.xss import CANARY, _check_reflected_xss_params
        from skyhigh_scanner.dast.crawler import SiteMap

        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = f"<html><body>Results: <{CANARY}xss> found</body></html>" + " " * 200
        client.get.return_value = resp

        sitemap = SiteMap()
        sitemap.urls.add("https://example.com/search?q=test")

        findings = []
        _check_reflected_xss_params(client, sitemap, findings)
        assert len(findings) >= 1
        f = findings[0]
        assert f.evidence is not None
        assert f.evidence[0]["method"] == "GET"
        assert "payload" in f.evidence[0]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test console evidence output
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestConsoleEvidence:
    """Console report prints evidence."""

    def test_console_prints_evidence(self, capsys):
        from skyhigh_scanner.core.scanner_base import ScannerBase

        class TestScanner(ScannerBase):
            SCANNER_NAME = "Test"
            SCANNER_VERSION = "1.0.0"
            TARGET_TYPE = "dast"

            def scan(self):
                pass

        scanner = TestScanner()
        ev = [{"method": "GET", "url": "http://x.com?q='",
               "status": 200, "payload": "'"}]
        scanner.findings.append(Finding(
            rule_id="DAST-INJ-001", name="SQLi", category="injection",
            severity="CRITICAL", file_path="http://x.com",
            line_num=0, line_content="test", description="desc",
            recommendation="fix", target_type="dast", evidence=ev,
        ))
        scanner.print_report()

        captured = capsys.readouterr()
        assert "Evidence" in captured.out
        assert "GET" in captured.out
        assert "Payload" in captured.out

    def test_console_skips_evidence_when_none(self, capsys):
        from skyhigh_scanner.core.scanner_base import ScannerBase

        class TestScanner(ScannerBase):
            SCANNER_NAME = "Test"
            SCANNER_VERSION = "1.0.0"
            TARGET_TYPE = "dast"

            def scan(self):
                pass

        scanner = TestScanner()
        scanner.findings.append(Finding(
            rule_id="DAST-INJ-001", name="SQLi", category="injection",
            severity="CRITICAL", file_path="http://x.com",
            line_num=0, line_content="test", description="desc",
            recommendation="fix", target_type="dast",
        ))
        scanner.print_report()

        captured = capsys.readouterr()
        assert "Evidence" not in captured.out
