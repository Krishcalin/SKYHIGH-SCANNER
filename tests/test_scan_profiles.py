"""Tests for the scan profiles feature."""

import pytest

from skyhigh_scanner.core.scan_profiles import (
    CATEGORIES,
    DEFAULT_PROFILE,
    PROFILES,
    ScanProfile,
    get_profile,
    list_profiles,
)
from skyhigh_scanner.core.scanner_base import ScannerBase

# ── Profile definitions ───────────────────────────────────────────────

class TestScanProfileDataclass:
    def test_profile_has_required_fields(self):
        p = ScanProfile(
            name="test", description="A test",
            enabled_categories=frozenset({"cve", "auth"}),
        )
        assert p.name == "test"
        assert p.description == "A test"
        assert p.severity_floor is None

    def test_is_enabled_true(self):
        p = ScanProfile(
            name="t", description="",
            enabled_categories=frozenset({"cve", "auth"}),
        )
        assert p.is_enabled("cve") is True
        assert p.is_enabled("auth") is True

    def test_is_enabled_false(self):
        p = ScanProfile(
            name="t", description="",
            enabled_categories=frozenset({"cve"}),
        )
        assert p.is_enabled("auth") is False
        assert p.is_enabled("patches") is False

    def test_severity_floor(self):
        p = ScanProfile(
            name="t", description="",
            enabled_categories=frozenset({"cve"}),
            severity_floor="HIGH",
        )
        assert p.severity_floor == "HIGH"

    def test_frozen(self):
        p = ScanProfile(
            name="t", description="",
            enabled_categories=frozenset({"cve"}),
        )
        with pytest.raises(AttributeError):
            p.name = "changed"


# ── Profile registry ──────────────────────────────────────────────────

class TestProfileRegistry:
    def test_all_profiles_present(self):
        expected = {"quick", "standard", "full", "compliance", "cve-only"}
        assert set(PROFILES.keys()) == expected

    def test_get_profile_valid(self):
        for name in PROFILES:
            p = get_profile(name)
            assert p.name == name

    def test_get_profile_unknown(self):
        with pytest.raises(ValueError, match="Unknown scan profile"):
            get_profile("nonexistent")

    def test_default_profile_is_standard(self):
        assert DEFAULT_PROFILE == "standard"

    def test_list_profiles_sorted(self):
        profiles = list_profiles()
        names = [p.name for p in profiles]
        assert names == sorted(names)
        assert len(profiles) == len(PROFILES)


# ── Profile category coverage ─────────────────────────────────────────

class TestProfileCategories:
    def test_quick_has_cve_and_auth(self):
        p = get_profile("quick")
        assert p.is_enabled("cve")
        assert p.is_enabled("auth")
        assert p.is_enabled("crypto")

    def test_quick_excludes_slow_checks(self):
        p = get_profile("quick")
        assert not p.is_enabled("patches")
        assert not p.is_enabled("services")

    def test_quick_has_severity_floor(self):
        p = get_profile("quick")
        assert p.severity_floor == "HIGH"

    def test_standard_excludes_patches(self):
        p = get_profile("standard")
        assert not p.is_enabled("patches")
        assert p.is_enabled("cve")
        assert p.is_enabled("auth")
        assert p.is_enabled("services")

    def test_standard_no_severity_floor(self):
        p = get_profile("standard")
        assert p.severity_floor is None

    def test_full_includes_everything(self):
        p = get_profile("full")
        for cat in CATEGORIES:
            assert p.is_enabled(cat), f"full profile should enable '{cat}'"

    def test_compliance_excludes_cve(self):
        p = get_profile("compliance")
        assert not p.is_enabled("cve")
        assert not p.is_enabled("patches")
        assert p.is_enabled("auth")
        assert p.is_enabled("firewall")
        assert p.is_enabled("logging")

    def test_cve_only_has_only_cve(self):
        p = get_profile("cve-only")
        assert p.is_enabled("cve")
        non_cve = CATEGORIES - {"cve"}
        for cat in non_cve:
            assert not p.is_enabled(cat), f"cve-only should not enable '{cat}'"


# ── ScannerBase integration ───────────────────────────────────────────

class _TestScanner(ScannerBase):
    """Minimal concrete scanner for testing."""
    SCANNER_NAME = "Test Scanner"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def scan(self):
        pass


class TestScannerBaseProfile:
    def test_default_profile_is_standard(self):
        s = _TestScanner()
        assert s.profile.name == "standard"

    def test_custom_profile(self):
        p = get_profile("quick")
        s = _TestScanner(profile=p)
        assert s.profile.name == "quick"

    def test_check_enabled_delegates(self):
        p = get_profile("cve-only")
        s = _TestScanner(profile=p)
        assert s._check_enabled("cve") is True
        assert s._check_enabled("auth") is False

    def test_summary_includes_profile(self):
        s = _TestScanner()
        summary = s.summary()
        assert summary["profile"] == "standard"

    def test_summary_with_quick_profile(self):
        p = get_profile("quick")
        s = _TestScanner(profile=p)
        assert s.summary()["profile"] == "quick"


# ── CLI integration ───────────────────────────────────────────────────

class TestCliProfileArg:
    def test_profile_default(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24"])
        assert args.profile == "standard"

    @pytest.mark.parametrize("profile", [
        "quick", "standard", "full", "compliance", "cve-only",
    ])
    def test_profile_choices(self, profile):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24", "--profile", profile])
        assert args.profile == profile

    def test_invalid_profile_rejected(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["linux", "-r", "10.0.0.0/24", "--profile", "invalid"])

    def test_profile_with_all_scan_types(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        for cmd in ("auto", "windows", "linux", "cisco", "webserver", "middleware", "database"):
            args = parser.parse_args([cmd, "-r", "10.0.0.1", "--profile", "quick"])
            assert args.profile == "quick"

    def test_profile_combined_with_severity(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "linux", "-r", "10.0.0.0/24",
            "--profile", "full",
            "--severity", "CRITICAL",
        ])
        assert args.profile == "full"
        assert args.severity == "CRITICAL"

    def test_profile_with_output_flags(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "linux", "-r", "10.0.0.1",
            "--profile", "compliance",
            "--json", "out.json",
            "--compliance",
        ])
        assert args.profile == "compliance"
        assert args.json_file == "out.json"
        assert args.compliance is True


# ── Severity floor interaction ─────────────────────────────────────────

class TestSeverityFloor:
    def test_quick_profile_severity_floor_overrides_default(self):
        """quick profile has severity_floor=HIGH, so LOW findings should be filtered."""
        p = get_profile("quick")
        s = _TestScanner(profile=p)

        # Add findings at all severities
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            s._add(
                rule_id=f"SF-{sev[:3]}-001", name=f"{sev} finding",
                category="Test", severity=sev,
                file_path="t", line_num=0, line_content="",
                description="d", recommendation="r",
            )

        assert len(s.findings) == 5

        # Apply profile floor
        floor = p.severity_floor or "LOW"
        s.filter_severity(floor)

        remaining_severities = {f.severity for f in s.findings}
        assert remaining_severities == {"CRITICAL", "HIGH"}

    def test_standard_profile_no_severity_floor(self):
        """standard profile has no severity floor — CLI default (LOW) applies."""
        p = get_profile("standard")
        s = _TestScanner(profile=p)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            s._add(
                rule_id=f"NF-{sev[:3]}-001", name=f"{sev} finding",
                category="Test", severity=sev,
                file_path="t", line_num=0, line_content="",
                description="d", recommendation="r",
            )

        # CLI default is LOW; profile has no floor override
        floor = p.severity_floor or "LOW"
        s.filter_severity(floor)

        # INFO is below LOW, so 4 findings remain
        remaining = {f.severity for f in s.findings}
        assert remaining == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_explicit_severity_stricter_than_profile(self):
        """If user passes --severity CRITICAL, it should be even stricter than profile floor."""
        p = get_profile("quick")  # floor = HIGH
        s = _TestScanner(profile=p)

        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            s._add(
                rule_id=f"ES-{sev[:3]}-001", name=f"{sev} finding",
                category="Test", severity=sev,
                file_path="t", line_num=0, line_content="",
                description="d", recommendation="r",
            )

        # User explicitly requests CRITICAL only
        s.filter_severity("CRITICAL")
        assert len(s.findings) == 1
        assert s.findings[0].severity == "CRITICAL"
