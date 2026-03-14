"""Tests for vulnerability_management.core.scanner_base."""

import json
from pathlib import Path

import pytest

from vulnerability_management.core.finding import Finding
from vulnerability_management.core.scanner_base import ScannerBase


class ConcreteScanner(ScannerBase):
    """Minimal concrete implementation for testing."""
    SCANNER_NAME = "Test Scanner"
    SCANNER_VERSION = "0.1.0"
    TARGET_TYPE = "generic"

    def scan(self):
        pass  # no-op for testing


@pytest.fixture
def scanner():
    return ConcreteScanner(verbose=False)


@pytest.fixture
def scanner_verbose():
    return ConcreteScanner(verbose=True)


class TestScannerBaseInit:
    def test_defaults(self, scanner):
        assert scanner.findings == []
        assert scanner.targets_scanned == []
        assert scanner.targets_failed == []
        assert scanner.verbose is False

    def test_verbose(self, scanner_verbose):
        assert scanner_verbose.verbose is True


class TestAddFinding:
    def test_add_creates_finding(self, scanner):
        scanner._add(
            rule_id="T-001", name="Test", category="Cat",
            severity="HIGH", file_path="10.0.0.1", line_num=0,
            line_content="x=1", description="D", recommendation="R",
        )
        assert len(scanner.findings) == 1
        assert scanner.findings[0].rule_id == "T-001"
        assert scanner.findings[0].target_type == "generic"

    def test_add_finding_preserves_target_type(self, scanner):
        f = Finding(
            rule_id="T-002", name="Test", category="Cat",
            severity="LOW", file_path="x", line_num=0,
            line_content="", description="D", recommendation="R",
            target_type="windows",
        )
        scanner._add_finding(f)
        assert scanner.findings[0].target_type == "windows"

    def test_add_finding_sets_default_target_type(self, scanner):
        f = Finding(
            rule_id="T-003", name="Test", category="Cat",
            severity="LOW", file_path="x", line_num=0,
            line_content="", description="D", recommendation="R",
        )
        scanner._add_finding(f)
        assert scanner.findings[0].target_type == "generic"


class TestFilterSeverity:
    def test_filter_medium(self, scanner, sample_findings):
        scanner.findings = list(sample_findings)
        scanner.filter_severity("MEDIUM")
        severities = {f.severity for f in scanner.findings}
        assert "LOW" not in severities
        assert "INFO" not in severities
        assert "CRITICAL" in severities
        assert "HIGH" in severities
        assert "MEDIUM" in severities

    def test_filter_critical(self, scanner, sample_findings):
        scanner.findings = list(sample_findings)
        scanner.filter_severity("CRITICAL")
        assert len(scanner.findings) == 1
        assert scanner.findings[0].severity == "CRITICAL"

    def test_filter_info_keeps_all(self, scanner, sample_findings):
        scanner.findings = list(sample_findings)
        scanner.filter_severity("INFO")
        assert len(scanner.findings) == 5


class TestSummary:
    def test_summary_structure(self, scanner, sample_findings):
        scanner.findings = list(sample_findings)
        scanner.targets_scanned = ["10.0.0.1", "10.0.0.2"]
        scanner.targets_failed = ["10.0.0.2"]
        s = scanner.summary()

        assert s["scanner"] == "Test Scanner"
        assert s["version"] == "0.1.0"
        assert s["target_type"] == "generic"
        assert s["targets_scanned"] == 2
        assert s["targets_failed"] == 1
        assert s["total_findings"] == 5
        assert s["severity_counts"]["CRITICAL"] == 1
        assert s["severity_counts"]["HIGH"] == 1
        assert "generated" in s

    def test_kev_count(self, scanner, sample_finding):
        scanner.findings = [sample_finding]
        s = scanner.summary()
        assert s["kev_findings"] == 1


class TestTiming:
    def test_duration(self, scanner):
        import time
        scanner._start_timer()
        time.sleep(0.05)
        scanner._stop_timer()
        assert scanner.duration_seconds >= 0.04

    def test_no_timing(self, scanner):
        assert scanner.duration_seconds == 0.0


class TestExitCode:
    def test_exit_1_on_critical(self, scanner):
        scanner._add(
            rule_id="X-001", name="Crit", category="C",
            severity="CRITICAL", file_path="x", line_num=0,
            line_content="", description="D", recommendation="R",
        )
        assert scanner.exit_code() == 1

    def test_exit_1_on_high(self, scanner):
        scanner._add(
            rule_id="X-002", name="High", category="C",
            severity="HIGH", file_path="x", line_num=0,
            line_content="", description="D", recommendation="R",
        )
        assert scanner.exit_code() == 1

    def test_exit_0_on_medium_only(self, scanner):
        scanner._add(
            rule_id="X-003", name="Med", category="C",
            severity="MEDIUM", file_path="x", line_num=0,
            line_content="", description="D", recommendation="R",
        )
        assert scanner.exit_code() == 0

    def test_exit_0_no_findings(self, scanner):
        assert scanner.exit_code() == 0


class TestJsonExport:
    def test_save_json(self, scanner, sample_findings, tmp_dir):
        scanner.findings = list(sample_findings)
        scanner.targets_scanned = ["10.0.0.1"]
        path = str(tmp_dir / "report.json")
        scanner.save_json(path)

        with open(path) as fh:
            data = json.load(fh)

        assert data["total_findings"] == 5
        assert len(data["findings"]) == 5
        assert data["targets"]["scanned"] == ["10.0.0.1"]


class TestCsvExport:
    def test_save_csv(self, scanner, sample_findings, tmp_dir):
        scanner.findings = list(sample_findings)
        path = str(tmp_dir / "report.csv")
        scanner.save_csv(path)

        content = Path(path).read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 6  # header + 5 findings
        assert "rule_id" in lines[0]


class TestPrintReport:
    def test_print_report_runs(self, scanner, sample_findings, capsys):
        scanner.findings = list(sample_findings)
        scanner.targets_scanned = ["10.0.0.1"]
        scanner.print_report()
        out = capsys.readouterr().out
        assert "Test Scanner" in out
        assert "Total findings" in out
