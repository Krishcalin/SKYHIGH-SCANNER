"""Tests for the baseline / diff scanning module."""

import json
import pytest

from skyhigh_scanner.core.finding import Finding
from skyhigh_scanner.core.baseline import (
    _finding_key,
    _finding_key_from_dict,
    load_baseline,
    compute_diff,
    diff_summary,
    print_diff_report,
)


def _make_finding(**kwargs):
    defaults = dict(
        rule_id="TEST-001", name="Test Finding", category="Test",
        severity="HIGH", file_path="10.0.0.1", line_num=0,
        line_content="test config", description="A test finding.",
        recommendation="Fix it.", target_type="test",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_dict(**kwargs):
    defaults = dict(
        rule_id="TEST-001", name="Test Finding", category="Test",
        severity="HIGH", file_path="10.0.0.1", line_num=0,
        line_content="test config", description="A test finding.",
        recommendation="Fix it.",
    )
    defaults.update(kwargs)
    return defaults


# ── Finding keys ──────────────────────────────────────────────────────

class TestFindingKey:
    def test_basic_key(self):
        f = _make_finding()
        key = _finding_key(f)
        assert key == "TEST-001|10.0.0.1|test config"

    def test_different_rule_id(self):
        f1 = _make_finding(rule_id="A-001")
        f2 = _make_finding(rule_id="A-002")
        assert _finding_key(f1) != _finding_key(f2)

    def test_dict_key_matches_finding_key(self):
        f = _make_finding()
        d = _make_dict()
        assert _finding_key(f) == _finding_key_from_dict(d)

    def test_dict_key_missing_fields(self):
        key = _finding_key_from_dict({})
        assert key == "||"


# ── load_baseline ─────────────────────────────────────────────────────

class TestLoadBaseline:
    def test_load_flat_list(self, tmp_path):
        f = tmp_path / "baseline.json"
        data = [_make_dict(), _make_dict(rule_id="TEST-002")]
        f.write_text(json.dumps(data))
        result = load_baseline(str(f))
        assert len(result) == 2

    def test_load_findings_key(self, tmp_path):
        f = tmp_path / "baseline.json"
        data = {"findings": [_make_dict()], "summary": {}}
        f.write_text(json.dumps(data))
        result = load_baseline(str(f))
        assert len(result) == 1

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_baseline("/nonexistent/baseline.json")

    def test_invalid_format(self, tmp_path):
        f = tmp_path / "baseline.json"
        f.write_text('"just a string"')
        with pytest.raises(ValueError, match="Invalid baseline"):
            load_baseline(str(f))

    def test_empty_findings(self, tmp_path):
        f = tmp_path / "baseline.json"
        f.write_text(json.dumps({"findings": []}))
        result = load_baseline(str(f))
        assert result == []


# ── compute_diff ──────────────────────────────────────────────────────

class TestComputeDiff:
    def test_all_new(self):
        current = [_make_finding(rule_id="NEW-001")]
        baseline = []
        diff = compute_diff(current, baseline)
        assert len(diff["new"]) == 1
        assert len(diff["fixed"]) == 0
        assert len(diff["unchanged"]) == 0

    def test_all_fixed(self):
        current = []
        baseline = [_make_dict(rule_id="OLD-001")]
        diff = compute_diff(current, baseline)
        assert len(diff["new"]) == 0
        assert len(diff["fixed"]) == 1
        assert len(diff["unchanged"]) == 0

    def test_all_unchanged(self):
        current = [_make_finding()]
        baseline = [_make_dict()]
        diff = compute_diff(current, baseline)
        assert len(diff["new"]) == 0
        assert len(diff["fixed"]) == 0
        assert len(diff["unchanged"]) == 1

    def test_mixed(self):
        current = [
            _make_finding(rule_id="KEEP-001"),
            _make_finding(rule_id="NEW-001", line_content="new thing"),
        ]
        baseline = [
            _make_dict(rule_id="KEEP-001"),
            _make_dict(rule_id="OLD-001", line_content="old thing"),
        ]
        diff = compute_diff(current, baseline)
        assert len(diff["new"]) == 1
        assert diff["new"][0].rule_id == "NEW-001"
        assert len(diff["fixed"]) == 1
        assert diff["fixed"][0]["rule_id"] == "OLD-001"
        assert len(diff["unchanged"]) == 1

    def test_identity_by_target(self):
        """Same rule_id but different targets = different findings."""
        current = [_make_finding(file_path="10.0.0.1")]
        baseline = [_make_dict(file_path="10.0.0.2")]
        diff = compute_diff(current, baseline)
        assert len(diff["new"]) == 1
        assert len(diff["fixed"]) == 1

    def test_empty_both(self):
        diff = compute_diff([], [])
        assert diff == {"new": [], "fixed": [], "unchanged": []}


# ── diff_summary ──────────────────────────────────────────────────────

class TestDiffSummary:
    def test_summary_counts(self):
        diff = {
            "new": [_make_finding(rule_id="A"), _make_finding(rule_id="B")],
            "fixed": [_make_dict(rule_id="C")],
            "unchanged": [_make_finding(rule_id="D")],
        }
        s = diff_summary(diff)
        assert s["new"] == 2
        assert s["fixed"] == 1
        assert s["unchanged"] == 1
        assert s["total_current"] == 3
        assert s["total_baseline"] == 2

    def test_empty_summary(self):
        s = diff_summary({"new": [], "fixed": [], "unchanged": []})
        assert s == {"new": 0, "fixed": 0, "unchanged": 0,
                     "total_current": 0, "total_baseline": 0}


# ── print_diff_report ─────────────────────────────────────────────────

class TestPrintDiffReport:
    def test_output_contains_counts(self, capsys):
        diff = {
            "new": [_make_finding(rule_id="NEW-001")],
            "fixed": [_make_dict(rule_id="OLD-001")],
            "unchanged": [],
        }
        print_diff_report(diff)
        captured = capsys.readouterr()
        assert "NEW" in captured.err
        assert "FIXED" in captured.err
        assert "NEW-001" in captured.err
        assert "OLD-001" in captured.err

    def test_no_new_no_fixed(self, capsys):
        diff = {"new": [], "fixed": [], "unchanged": [_make_finding()]}
        print_diff_report(diff)
        captured = capsys.readouterr()
        assert "Unchanged" in captured.err
        assert "[NEW]" not in captured.err
        assert "[FIXED]" not in captured.err

    def test_baseline_comparison_header(self, capsys):
        diff = {"new": [], "fixed": [], "unchanged": []}
        print_diff_report(diff)
        captured = capsys.readouterr()
        assert "Baseline Comparison" in captured.err
