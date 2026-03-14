"""Tests for vulnerability_management.core.finding."""

import json

from vulnerability_management.core.finding import Finding


class TestFinding:
    def test_required_fields(self):
        f = Finding(
            rule_id="X-001", name="Test", category="Cat",
            severity="HIGH", file_path="/tmp/x", line_num=10,
            line_content="bad_code()", description="Desc",
            recommendation="Fix",
        )
        assert f.rule_id == "X-001"
        assert f.severity == "HIGH"
        assert f.cwe is None
        assert f.cve is None
        assert f.cisa_kev is False

    def test_optional_fields(self, sample_finding):
        assert sample_finding.cwe == "CWE-200"
        assert sample_finding.cve == "CVE-2024-99999"
        assert sample_finding.cvss == 7.5
        assert sample_finding.cisa_kev is True
        assert sample_finding.target_type == "generic"

    def test_to_dict_strips_none(self):
        f = Finding(
            rule_id="X-001", name="Test", category="Cat",
            severity="LOW", file_path="x", line_num=0,
            line_content="", description="D", recommendation="R",
        )
        d = f.to_dict()
        assert "cwe" not in d
        assert "cve" not in d
        assert "cvss" not in d
        assert "epss" not in d
        assert "fix_version" not in d
        # cisa_kev=False is not None, so it should be present
        assert d["cisa_kev"] is False

    def test_to_dict_keeps_values(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["rule_id"] == "TEST-001"
        assert d["cve"] == "CVE-2024-99999"
        assert d["cvss"] == 7.5
        assert d["cisa_kev"] is True

    def test_to_json_valid(self, sample_finding):
        j = sample_finding.to_json()
        parsed = json.loads(j)
        assert parsed["rule_id"] == "TEST-001"

    def test_one_liner_with_kev(self, sample_finding):
        line = sample_finding.one_liner()
        assert "[HIGH]" in line
        assert "TEST-001" in line
        assert "(CVE-2024-99999)" in line
        assert "[KEV]" in line

    def test_one_liner_without_kev(self):
        f = Finding(
            rule_id="X-002", name="Plain", category="C",
            severity="MEDIUM", file_path="host", line_num=0,
            line_content="", description="D", recommendation="R",
        )
        line = f.one_liner()
        assert "[KEV]" not in line
        assert "[MEDIUM]" in line

    def test_str(self, sample_finding):
        assert str(sample_finding) == sample_finding.one_liner()

    def test_repr(self, sample_finding):
        r = repr(sample_finding)
        assert "Finding(" in r
        assert "TEST-001" in r
        assert "HIGH" in r

    def test_to_dict_roundtrip(self, sample_finding):
        """to_dict output should be JSON-serialisable and parsable."""
        d = sample_finding.to_dict()
        j = json.dumps(d)
        parsed = json.loads(j)
        assert parsed == d
