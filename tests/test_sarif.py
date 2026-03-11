"""Tests for SARIF v2.1.0 export."""

import json

import pytest

from skyhigh_scanner.core.finding import Finding

# ── Fixtures ──────────────────────────────────────────────────────────

class _StubScanner:
    """Minimal stub mimicking ScannerBase for save_sarif testing."""

    SCANNER_NAME = "Test Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "generic"

    def __init__(self, findings=None):
        self.findings = findings or []
        self.targets_scanned = ["10.0.0.1"]
        self.targets_failed = []
        self._start_time = 1700000000.0
        self._end_time = 1700000010.0
        self.verbose = False
        self._messages = []

    def _info(self, msg):
        self._messages.append(msg)


def _make_stub(findings=None):
    """Bind ScannerBase.save_sarif to the stub."""
    from skyhigh_scanner.core.scanner_base import ScannerBase
    stub = _StubScanner(findings)
    stub.save_sarif = ScannerBase.save_sarif.__get__(stub, _StubScanner)
    return stub


def _basic_finding(**overrides):
    defaults = dict(
        rule_id="TEST-001", name="Test Vuln", category="Test",
        severity="HIGH", file_path="10.0.0.1", line_num=0,
        line_content="setting=bad", description="A test finding.",
        recommendation="Fix it.", cwe="CWE-200",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ── SARIF structure tests ─────────────────────────────────────────────

class TestSarifStructure:
    def test_valid_sarif_envelope(self, tmp_path):
        stub = _make_stub([_basic_finding()])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]
        assert len(sarif["runs"]) == 1

    def test_tool_driver(self, tmp_path):
        stub = _make_stub([_basic_finding()])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Test Scanner"
        assert driver["version"] == "1.0.0"
        assert driver["semanticVersion"] == "1.0.0"
        assert "informationUri" in driver

    def test_rules_array(self, tmp_path):
        stub = _make_stub([_basic_finding()])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert rule["id"] == "TEST-001"
        assert rule["name"] == "Test Vuln"
        assert "shortDescription" in rule
        assert "fullDescription" in rule
        assert "help" in rule

    def test_results_array(self, tmp_path):
        stub = _make_stub([_basic_finding()])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        r = results[0]
        assert r["ruleId"] == "TEST-001"
        assert r["ruleIndex"] == 0
        assert r["level"] == "error"
        assert "message" in r
        assert "locations" in r

    def test_invocations(self, tmp_path):
        stub = _make_stub([])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
        assert invocations[0]["startTimeUtc"] is not None

    def test_empty_findings(self, tmp_path):
        stub = _make_stub([])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_info_message_printed(self, tmp_path):
        stub = _make_stub([])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        assert any("SARIF" in m for m in stub._messages)


# ── Severity mapping ──────────────────────────────────────────────────

class TestSarifSeverityMapping:
    @pytest.mark.parametrize("severity,expected_level", [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "note"),
    ])
    def test_severity_to_level(self, tmp_path, severity, expected_level):
        finding = _basic_finding(severity=severity, rule_id=f"SEV-{severity}")
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        result = sarif["runs"][0]["results"][0]
        assert result["level"] == expected_level

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == expected_level


# ── Rule properties ──────────────────────────────────────────────────

class TestSarifRuleProperties:
    def test_cwe_tag(self, tmp_path):
        finding = _basic_finding(cwe="CWE-89")
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "CWE-89" in rule["properties"]["tags"]

    def test_cvss_security_severity(self, tmp_path):
        finding = _basic_finding(cvss=9.8)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.8"

    def test_help_uri_from_cwe(self, tmp_path):
        finding = _basic_finding(cwe="CWE-79")
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "79.html" in rule["helpUri"]

    def test_no_cwe_no_help_uri(self, tmp_path):
        finding = _basic_finding(cwe=None)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" not in rule

    def test_no_cvss_no_security_severity(self, tmp_path):
        finding = _basic_finding(cvss=None, cwe=None)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "properties" not in rule


# ── Result properties ────────────────────────────────────────────────

class TestSarifResultProperties:
    def test_location(self, tmp_path):
        finding = _basic_finding(file_path="192.168.1.1", line_num=42)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "192.168.1.1"
        assert loc["physicalLocation"]["region"]["startLine"] == 42

    def test_line_num_zero_becomes_one(self, tmp_path):
        finding = _basic_finding(line_num=0)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 1

    def test_fingerprint(self, tmp_path):
        finding = _basic_finding(file_path="10.0.0.5", line_num=10)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        fp = sarif["runs"][0]["results"][0]["fingerprints"]
        assert fp["skyhigh/v1"] == "TEST-001:10.0.0.5:10"

    def test_fixes_from_recommendation(self, tmp_path):
        finding = _basic_finding(recommendation="Upgrade to v2.0")
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        fixes = sarif["runs"][0]["results"][0]["fixes"]
        assert len(fixes) == 1
        assert "Upgrade" in fixes[0]["description"]["text"]

    def test_cve_in_properties(self, tmp_path):
        finding = _basic_finding(cve="CVE-2024-12345")
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["cve"] == "CVE-2024-12345"

    def test_kev_in_properties(self, tmp_path):
        finding = _basic_finding(cisa_kev=True)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["cisa_kev"] is True

    def test_epss_in_properties(self, tmp_path):
        finding = _basic_finding(epss=0.92)
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["epss"] == 0.92

    def test_compliance_in_properties(self, tmp_path):
        finding = _basic_finding()
        finding.compliance = {"nist_800_53": ["SI-10"], "pci_dss": ["6.5.1"]}
        stub = _make_stub([finding])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["compliance"]["nist_800_53"] == ["SI-10"]
        assert props["compliance"]["pci_dss"] == ["6.5.1"]


# ── Deduplication & multiple findings ────────────────────────────────

class TestSarifDeduplication:
    def test_duplicate_rules_deduplicated(self, tmp_path):
        f1 = _basic_finding(file_path="10.0.0.1")
        f2 = _basic_finding(file_path="10.0.0.2")
        stub = _make_stub([f1, f2])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 1
        assert len(results) == 2
        assert results[0]["ruleIndex"] == 0
        assert results[1]["ruleIndex"] == 0

    def test_multiple_distinct_rules(self, tmp_path):
        f1 = _basic_finding(rule_id="A-001", name="Vuln A")
        f2 = _basic_finding(rule_id="B-002", name="Vuln B")
        f3 = _basic_finding(rule_id="C-003", name="Vuln C")
        stub = _make_stub([f1, f2, f3])
        path = str(tmp_path / "report.sarif")
        stub.save_sarif(path)

        with open(path) as f:
            sarif = json.load(f)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 3
        assert len(results) == 3
        assert results[0]["ruleIndex"] == 0
        assert results[1]["ruleIndex"] == 1
        assert results[2]["ruleIndex"] == 2


# ── CLI integration ──────────────────────────────────────────────────

class TestCliSarifFlag:
    def test_sarif_flag_parses(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24", "--sarif", "report.sarif"])
        assert args.sarif_file == "report.sarif"

    def test_sarif_default_none(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24"])
        assert args.sarif_file is None

    def test_sarif_with_other_outputs(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "linux", "-r", "10.0.0.0/24",
            "--sarif", "report.sarif",
            "--json", "report.json",
            "--html", "report.html",
            "--csv", "report.csv",
            "--pdf", "report.pdf",
        ])
        assert args.sarif_file == "report.sarif"
        assert args.json_file == "report.json"
        assert args.html_file == "report.html"
        assert args.csv_file == "report.csv"
        assert args.pdf_file == "report.pdf"
