"""Tests for compliance framework mapping engine."""

from skyhigh_scanner.core.compliance import (
    CATEGORY_MAP,
    CWE_MAP,
    FRAMEWORKS,
    _extract_cwe_id,
    _lookup_category,
    _lookup_cwe,
    compliance_summary,
    enrich_finding,
    enrich_findings,
    filter_by_framework,
    format_controls,
    map_finding,
)
from skyhigh_scanner.core.finding import Finding

# ── Helper ────────────────────────────────────────────────────────────

def _make_finding(**kwargs):
    """Create a Finding with sensible defaults."""
    defaults = dict(
        rule_id="TEST-001", name="Test Finding", category="Test",
        severity="HIGH", file_path="target", line_num=0,
        line_content="detail", description="desc", recommendation="fix",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ── CWE ID extraction ────────────────────────────────────────────────

class TestExtractCweId:
    def test_standard_format(self):
        assert _extract_cwe_id("CWE-89") == "CWE-89"

    def test_lowercase(self):
        assert _extract_cwe_id("cwe-79") == "CWE-79"

    def test_no_dash(self):
        assert _extract_cwe_id("CWE287") == "CWE-287"

    def test_numeric_only(self):
        assert _extract_cwe_id("89") == "CWE-89"

    def test_none(self):
        assert _extract_cwe_id(None) is None

    def test_empty(self):
        assert _extract_cwe_id("") is None

    def test_whitespace(self):
        assert _extract_cwe_id("  CWE-78  ") == "CWE-78"

    def test_invalid(self):
        assert _extract_cwe_id("not-a-cwe") is None


# ── CWE lookup ────────────────────────────────────────────────────────

class TestLookupCwe:
    def test_known_cwe(self):
        result = _lookup_cwe("CWE-89")
        assert "nist_800_53" in result
        assert "pci_dss" in result
        assert "SI-10" in result["nist_800_53"]

    def test_unknown_cwe(self):
        assert _lookup_cwe("CWE-99999") == {}

    def test_all_frameworks_present(self):
        for cwe_id, mapping in CWE_MAP.items():
            for fw in FRAMEWORKS:
                assert fw in mapping, f"{cwe_id} missing framework {fw}"


# ── Category lookup ───────────────────────────────────────────────────

class TestLookupCategory:
    def test_authentication_match(self):
        result = _lookup_category("Authentication Configuration")
        assert "nist_800_53" in result
        assert "IA-2" in result["nist_800_53"]

    def test_ssh_match(self):
        result = _lookup_category("SSH Hardening")
        assert "nist_800_53" in result

    def test_logging_match(self):
        result = _lookup_category("Audit Logging")
        assert "pci_dss" in result

    def test_no_match(self):
        assert _lookup_category("Completely Unknown Category XYZ") == {}

    def test_case_insensitive(self):
        result = _lookup_category("PASSWORD Policy")
        assert "nist_800_53" in result

    def test_all_categories_have_all_frameworks(self):
        for cat_key, mapping in CATEGORY_MAP.items():
            for fw in FRAMEWORKS:
                assert fw in mapping, f"Category '{cat_key}' missing framework {fw}"


# ── map_finding ───────────────────────────────────────────────────────

class TestMapFinding:
    def test_cwe_takes_priority(self):
        result = map_finding(cwe="CWE-89", category="Authentication")
        # CWE-89 is SQL injection, not authentication
        assert "SI-10" in result["nist_800_53"]

    def test_category_fallback(self):
        result = map_finding(cwe=None, category="SSH Hardening")
        assert "nist_800_53" in result

    def test_unknown_cwe_falls_to_category(self):
        result = map_finding(cwe="CWE-99999", category="Logging Configuration")
        assert "AU-2" in result["nist_800_53"]

    def test_no_match(self):
        result = map_finding(cwe=None, category="Totally Unknown")
        assert result == {}

    def test_cwe_without_category(self):
        result = map_finding(cwe="CWE-287")
        assert "IA-2" in result["nist_800_53"]


# ── enrich_finding ────────────────────────────────────────────────────

class TestEnrichFinding:
    def test_enriches_with_cwe(self):
        f = _make_finding(cwe="CWE-89")
        enrich_finding(f)
        assert f.compliance is not None
        assert "nist_800_53" in f.compliance

    def test_enriches_with_category(self):
        f = _make_finding(category="Authentication")
        enrich_finding(f)
        assert f.compliance is not None

    def test_no_match_leaves_none(self):
        f = _make_finding(cwe=None, category="Xyzzy Unknown")
        enrich_finding(f)
        assert f.compliance is None


# ── enrich_findings (batch) ───────────────────────────────────────────

class TestEnrichFindings:
    def test_batch_enrich(self):
        findings = [
            _make_finding(cwe="CWE-89"),
            _make_finding(cwe="CWE-287"),
            _make_finding(category="Unknown XYZ"),
        ]
        count = enrich_findings(findings)
        assert count == 2
        assert findings[0].compliance is not None
        assert findings[1].compliance is not None
        assert findings[2].compliance is None

    def test_empty_list(self):
        assert enrich_findings([]) == 0


# ── compliance_summary ────────────────────────────────────────────────

class TestComplianceSummary:
    def test_aggregates_controls(self):
        findings = [
            _make_finding(cwe="CWE-89"),
            _make_finding(cwe="CWE-79"),
            _make_finding(cwe="CWE-287"),
        ]
        enrich_findings(findings)
        stats = compliance_summary(findings)
        assert "nist_800_53" in stats
        # CWE-89 and CWE-79 both map to SI-10
        assert stats["nist_800_53"]["SI-10"] == 2

    def test_framework_filter(self):
        findings = [_make_finding(cwe="CWE-89")]
        enrich_findings(findings)
        stats = compliance_summary(findings, frameworks=["pci_dss"])
        assert "pci_dss" in stats
        assert "nist_800_53" not in stats

    def test_empty_findings(self):
        stats = compliance_summary([])
        for fw in FRAMEWORKS:
            assert stats[fw] == {}

    def test_sorted_by_count(self):
        findings = [
            _make_finding(cwe="CWE-89"),
            _make_finding(cwe="CWE-89"),
            _make_finding(cwe="CWE-287"),
        ]
        enrich_findings(findings)
        stats = compliance_summary(findings)
        nist = stats["nist_800_53"]
        # SI-10 appears in both CWE-89 findings
        counts = list(nist.values())
        assert counts == sorted(counts, reverse=True)


# ── filter_by_framework ──────────────────────────────────────────────

class TestFilterByFramework:
    def test_filter_pci(self):
        findings = [
            _make_finding(cwe="CWE-89"),
            _make_finding(category="Unknown XYZ"),
        ]
        enrich_findings(findings)
        result = filter_by_framework(findings, "pci_dss")
        assert len(result) == 1
        assert result[0].cwe == "CWE-89"

    def test_filter_specific_control(self):
        findings = [
            _make_finding(cwe="CWE-89"),   # maps to SI-10, SI-3
            _make_finding(cwe="CWE-287"),  # maps to IA-2, IA-5
        ]
        enrich_findings(findings)
        result = filter_by_framework(findings, "nist_800_53", controls=["IA-2"])
        assert len(result) == 1
        assert result[0].cwe == "CWE-287"

    def test_filter_no_compliance(self):
        findings = [_make_finding()]
        result = filter_by_framework(findings, "nist_800_53")
        assert len(result) == 0


# ── format_controls ──────────────────────────────────────────────────

class TestFormatControls:
    def test_all_frameworks(self):
        f = _make_finding(cwe="CWE-89")
        enrich_finding(f)
        text = format_controls(f.compliance)
        assert "NIST:" in text
        assert "ISO:" in text
        assert "PCI:" in text
        assert "CIS:" in text

    def test_single_framework(self):
        f = _make_finding(cwe="CWE-89")
        enrich_finding(f)
        text = format_controls(f.compliance, framework="pci_dss")
        assert "PCI:" in text
        assert "NIST:" not in text

    def test_none_compliance(self):
        assert format_controls(None) == ""

    def test_empty_compliance(self):
        assert format_controls({}) == ""


# ── Finding serialisation with compliance ─────────────────────────────

class TestFindingSerialization:
    def test_to_dict_includes_compliance(self):
        f = _make_finding(cwe="CWE-89")
        enrich_finding(f)
        d = f.to_dict()
        assert "compliance" in d
        assert "nist_800_53" in d["compliance"]

    def test_to_dict_excludes_none_compliance(self):
        f = _make_finding()
        d = f.to_dict()
        assert "compliance" not in d

    def test_to_json_roundtrip(self):
        import json
        f = _make_finding(cwe="CWE-89")
        enrich_finding(f)
        j = f.to_json()
        data = json.loads(j)
        assert data["compliance"]["nist_800_53"] == f.compliance["nist_800_53"]


# ── Integration with ScannerBase ──────────────────────────────────────

class TestScannerBaseCompliance:
    def test_enrich_compliance_method(self):
        from skyhigh_scanner.core.scanner_base import ScannerBase

        class DummyScanner(ScannerBase):
            def scan(self):
                self._add("T-001", "SQL Injection", "Injection", "CRITICAL",
                          "file.py", 10, "query(input)", "SQL injection found",
                          "Use parameterised queries", cwe="CWE-89")
                self._add("T-002", "Weak Password", "Authentication", "MEDIUM",
                          "config", 0, "min_length=4", "Weak password policy",
                          "Set min length to 12", cwe="CWE-521")

        scanner = DummyScanner(verbose=False)
        scanner.scan()
        count = scanner.enrich_compliance()
        assert count == 2
        assert scanner.findings[0].compliance is not None
        assert scanner.findings[1].compliance is not None

    def test_summary_includes_compliance(self):
        from skyhigh_scanner.core.scanner_base import ScannerBase

        class DummyScanner(ScannerBase):
            def scan(self):
                self._add("T-001", "Test", "Authentication", "HIGH",
                          "x", 0, "", "d", "r", cwe="CWE-287")

        scanner = DummyScanner(verbose=False)
        scanner.scan()
        scanner.enrich_compliance()
        s = scanner.summary()
        assert s["compliance_mapped"] == 1
        assert "nist_800_53" in s["compliance"]

    def test_csv_has_compliance_columns(self, tmp_path):
        import csv

        from skyhigh_scanner.core.scanner_base import ScannerBase

        class DummyScanner(ScannerBase):
            def scan(self):
                self._add("T-001", "Test", "Auth", "HIGH",
                          "x", 0, "", "d", "r", cwe="CWE-287")

        scanner = DummyScanner(verbose=False)
        scanner.scan()
        scanner.enrich_compliance()

        csv_path = str(tmp_path / "report.csv")
        scanner.save_csv(csv_path)

        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            row = next(reader)
            assert "nist_800_53" in row
            assert "pci_dss" in row
            assert "IA-2" in row["nist_800_53"]


# ── Integration with HTML report ──────────────────────────────────────

class TestHtmlCompliance:
    def test_compliance_in_html(self):
        from skyhigh_scanner.core.reporting import generate_html_report

        f = _make_finding(cwe="CWE-89")
        enrich_finding(f)
        summary = {"severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        html_out = generate_html_report("Test", "1", "generic", [f], summary)
        assert "Compliance:" in html_out
        assert "NIST:" in html_out
        assert "Compliance Framework Mapping" in html_out

    def test_no_compliance_section_without_enrichment(self):
        from skyhigh_scanner.core.reporting import generate_html_report

        f = _make_finding()
        summary = {"severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        html_out = generate_html_report("Test", "1", "generic", [f], summary)
        assert "Compliance Framework Mapping" not in html_out

    def test_compliance_dashboard_card(self):
        from skyhigh_scanner.core.reporting import generate_html_report

        f = _make_finding(cwe="CWE-89")
        enrich_finding(f)
        summary = {"severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
        html_out = generate_html_report("Test", "1", "generic", [f], summary)
        assert "Compliance Mapped" in html_out


# ── CLI flag ──────────────────────────────────────────────────────────

class TestCliComplianceFlag:
    def test_compliance_flag_parses(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24", "--compliance"])
        assert args.compliance is True

    def test_compliance_default_false(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24"])
        assert args.compliance is False


# ── Data integrity ────────────────────────────────────────────────────

class TestDataIntegrity:
    def test_all_cwe_mappings_have_all_frameworks(self):
        for cwe_id, mapping in CWE_MAP.items():
            for fw in FRAMEWORKS:
                assert fw in mapping, f"{cwe_id} missing {fw}"
                assert len(mapping[fw]) > 0, f"{cwe_id} has empty {fw}"

    def test_all_category_mappings_have_all_frameworks(self):
        for cat, mapping in CATEGORY_MAP.items():
            for fw in FRAMEWORKS:
                assert fw in mapping, f"Category '{cat}' missing {fw}"
                assert len(mapping[fw]) > 0, f"Category '{cat}' has empty {fw}"

    def test_framework_keys_consistent(self):
        expected = {"nist_800_53", "iso_27001", "pci_dss", "cis_controls"}
        assert set(FRAMEWORKS.keys()) == expected

    def test_cwe_map_coverage(self):
        # Ensure we cover the most critical CWEs from OWASP Top 10
        critical_cwes = [
            "CWE-79", "CWE-89", "CWE-78", "CWE-287", "CWE-502",
            "CWE-22", "CWE-352", "CWE-798", "CWE-327", "CWE-778",
        ]
        for cwe in critical_cwes:
            assert cwe in CWE_MAP, f"Critical {cwe} not in CWE_MAP"
