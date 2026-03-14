"""Seed file validation tests.

These tests verify the integrity and consistency of the bundled CVE seed
JSON files — no duplicate CVE IDs, valid JSON, correct schema, etc.
"""

import json
from pathlib import Path

import pytest

SEED_DIR = Path(__file__).parent.parent / "vulnerability_management" / "cve_data" / "seed"
BENCHMARK_DIR = Path(__file__).parent.parent / "vulnerability_management" / "benchmarks"

REQUIRED_CVE_FIELDS = {"cve_id", "platform", "severity", "published", "name"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _load_seed_files():
    """Load all seed JSON files and return (filename, entries) pairs."""
    results = []
    for path in sorted(SEED_DIR.glob("*.json")):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = data.get("cves", [])
        results.append((path.name, data))
    return results


# Skip all tests if seed dir doesn't exist
pytestmark = pytest.mark.skipif(
    not SEED_DIR.exists(), reason="Seed directory not found"
)


class TestSeedFileIntegrity:
    """Validate each seed JSON file individually."""

    @pytest.fixture(scope="class")
    def all_seeds(self):
        return _load_seed_files()

    def test_all_files_valid_json(self):
        """Every .json file in seed/ must parse without error."""
        for path in SEED_DIR.glob("*.json"):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)  # will raise on invalid JSON
            assert isinstance(data, (list, dict)), f"{path.name}: root must be list or dict"

    def test_required_fields_present(self, all_seeds):
        """Every CVE entry must have required fields."""
        for filename, entries in all_seeds:
            for entry in entries:
                cve_id = entry.get("cve_id", "UNKNOWN")
                for field in REQUIRED_CVE_FIELDS:
                    assert field in entry, (
                        f"{filename}: {cve_id} missing required field '{field}'"
                    )

    def test_valid_severity_values(self, all_seeds):
        """Severity must be one of CRITICAL/HIGH/MEDIUM/LOW/INFO."""
        for filename, entries in all_seeds:
            for entry in entries:
                sev = entry.get("severity", "")
                assert sev in VALID_SEVERITIES, (
                    f"{filename}: {entry.get('cve_id')}: invalid severity '{sev}'"
                )

    def test_cve_id_format(self, all_seeds):
        """CVE IDs must match CVE-YYYY-NNNNN format."""
        import re
        pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
        for filename, entries in all_seeds:
            for entry in entries:
                cve_id = entry.get("cve_id", "")
                assert pattern.match(cve_id), (
                    f"{filename}: invalid CVE ID format '{cve_id}'"
                )

    def test_cvss_range(self, all_seeds):
        """CVSS v3 scores must be between 0.0 and 10.0 if present."""
        for filename, entries in all_seeds:
            for entry in entries:
                cvss = entry.get("cvss_v3")
                if cvss is not None:
                    assert 0.0 <= cvss <= 10.0, (
                        f"{filename}: {entry['cve_id']}: CVSS {cvss} out of range"
                    )

    def test_epss_range(self, all_seeds):
        """EPSS scores must be between 0.0 and 1.0 if present."""
        for filename, entries in all_seeds:
            for entry in entries:
                epss = entry.get("epss_score")
                if epss is not None:
                    assert 0.0 <= epss <= 1.0, (
                        f"{filename}: {entry['cve_id']}: EPSS {epss} out of range"
                    )

    def test_cisa_kev_boolean(self, all_seeds):
        """cisa_kev field must be a boolean if present."""
        for filename, entries in all_seeds:
            for entry in entries:
                kev = entry.get("cisa_kev")
                if kev is not None:
                    assert isinstance(kev, bool), (
                        f"{filename}: {entry['cve_id']}: cisa_kev must be bool, got {type(kev)}"
                    )


class TestNoDuplicateCves:
    """Ensure no CVE ID is duplicated where it shouldn't be."""

    def test_no_duplicates_within_file(self):
        """Same CVE ID must not appear twice in the same seed file."""
        for filename, entries in _load_seed_files():
            seen = set()
            for entry in entries:
                cve_id = entry.get("cve_id", "")
                assert cve_id not in seen, (
                    f"{filename}: duplicate CVE {cve_id} within same file"
                )
                seen.add(cve_id)

    def test_no_same_platform_duplicates_across_files(self):
        """Same CVE ID + platform combo must not appear across files.

        Note: The same CVE may legitimately affect multiple platforms
        (e.g. CVE-2023-44487 HTTP/2 Rapid Reset affects IIS, .NET,
        Node.js, and Java). Cross-platform duplicates are allowed;
        same-platform duplicates are not.
        """
        seen: dict[tuple[str, str], str] = {}  # (cve_id, platform) → filename
        for filename, entries in _load_seed_files():
            for entry in entries:
                cve_id = entry.get("cve_id", "")
                platform = entry.get("platform", "")
                key = (cve_id, platform)
                if key in seen:
                    pytest.fail(
                        f"Duplicate {cve_id} for platform '{platform}': "
                        f"found in both '{seen[key]}' and '{filename}'"
                    )
                seen[key] = filename


class TestSeedFileCounts:
    """Smoke test: verify expected number of seed files and CVEs."""

    def test_minimum_seed_files(self):
        files = list(SEED_DIR.glob("*.json"))
        assert len(files) >= 20, f"Expected 20+ seed files, found {len(files)}"

    def test_minimum_total_cves(self):
        total = sum(len(entries) for _, entries in _load_seed_files())
        assert total >= 400, f"Expected 400+ CVEs, found {total}"


class TestBenchmarkFiles:
    """Validate CIS benchmark JSON files."""

    @pytest.mark.skipif(not BENCHMARK_DIR.exists(), reason="Benchmark dir not found")
    def test_benchmark_files_valid_json(self):
        for path in BENCHMARK_DIR.glob("*.json"):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            assert isinstance(data, (list, dict)), f"{path.name}: invalid structure"
