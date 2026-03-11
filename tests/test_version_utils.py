"""Tests for skyhigh_scanner.core.version_utils."""

import pytest

from skyhigh_scanner.core.version_utils import (
    parse_ver,
    version_in_range,
    compare_versions,
    is_eol,
)


# ── parse_ver ─────────────────────────────────────────────────────────

class TestParseVer:
    def test_simple_version(self):
        assert parse_ver("1.2.3") == (1, 2, 3)

    def test_four_part(self):
        assert parse_ver("10.0.19045.4651") == (10, 0, 19045, 4651)

    def test_underscore_separator(self):
        assert parse_ver("1.8.0_381") == (1, 8, 0, 381)

    def test_hyphen_suffix(self):
        assert parse_ver("8.1.27-1ubuntu3") == (8, 1, 27, 1, 3)

    def test_single_number(self):
        assert parse_ver("17") == (17,)

    def test_empty_string(self):
        assert parse_ver("") == (0,)

    def test_non_numeric(self):
        assert parse_ver("abc") == (0,)

    def test_mixed_alpha_numeric(self):
        assert parse_ver("v2.4.52") == (2, 4, 52)

    def test_tilde_separator(self):
        assert parse_ver("1.0~beta1") == (1, 0, 1)

    def test_plus_separator(self):
        assert parse_ver("3.0+git20240101") == (3, 0, 20240101)


# ── version_in_range ──────────────────────────────────────────────────

class TestVersionInRange:
    def test_in_range_basic(self):
        assert version_in_range("15.5", ">=15.0,<15.9") is True

    def test_below_range(self):
        assert version_in_range("14.9", ">=15.0,<15.9") is False

    def test_at_lower_bound_inclusive(self):
        assert version_in_range("15.0", ">=15.0,<15.9") is True

    def test_at_upper_bound_exclusive(self):
        assert version_in_range("15.9", ">=15.0,<15.9") is False

    def test_at_upper_bound_inclusive(self):
        assert version_in_range("12.4.3", ">=12.0,<=12.4.3") is True

    def test_less_than_only(self):
        assert version_in_range("17.3.7", "<17.3.8") is True
        assert version_in_range("17.3.8", "<17.3.8") is False

    def test_greater_than(self):
        assert version_in_range("2.0", ">1.0") is True
        assert version_in_range("1.0", ">1.0") is False

    def test_equality(self):
        assert version_in_range("1.0.1", "==1.0.1") is True
        assert version_in_range("1.0.2", "==1.0.1") is False
        # Note: letter-only suffixes like "f" in "1.0.1f" are stripped
        # by parse_ver (no digits), so "1.0.1f" parses to (1,0,1) == "1.0.1"
        assert version_in_range("1.0.1f", "==1.0.1") is True

    def test_single_equals(self):
        assert version_in_range("3.0", "=3.0") is True

    def test_empty_version(self):
        assert version_in_range("", ">=1.0") is False

    def test_empty_range(self):
        assert version_in_range("1.0", "") is False

    def test_both_empty(self):
        assert version_in_range("", "") is False

    def test_real_world_numeric_ranges(self):
        # Numeric version ranges work correctly
        assert version_in_range("2.4.50", ">=2.4.0,<2.4.52") is True
        assert version_in_range("2.4.52", ">=2.4.0,<2.4.52") is False
        assert version_in_range("2.3.9", ">=2.4.0,<2.4.52") is False

    def test_openssl_letter_suffix_limitation(self):
        # OpenSSL-style letter suffixes (1.0.1a, 1.0.1g) are stripped
        # by parse_ver since the letter has no digits. All of "1.0.1a"
        # through "1.0.1z" parse to (1, 0, 1). This is a known
        # limitation — seed data should use numeric ranges instead.
        assert parse_ver("1.0.1a") == parse_ver("1.0.1g")  # both → (1,0,1)

    def test_whitespace_handling(self):
        assert version_in_range("2.0", " >= 1.0 , < 3.0 ") is True


# ── compare_versions ──────────────────────────────────────────────────

class TestCompareVersions:
    def test_less_than(self):
        assert compare_versions("1.0", "2.0") == -1

    def test_equal(self):
        assert compare_versions("1.0.0", "1.0.0") == 0

    def test_greater_than(self):
        assert compare_versions("2.1", "2.0") == 1

    def test_different_lengths(self):
        assert compare_versions("1.0", "1.0.0") == -1

    def test_patch_level(self):
        assert compare_versions("2.4.51", "2.4.52") == -1


# ── is_eol ────────────────────────────────────────────────────────────

class TestIsEol:
    EOL_MAP = {
        "5.6": "2021-02-01",
        "7.0": "2019-01-10",
        "7.4": "2022-11-28",
    }

    def test_match(self):
        assert is_eol("7.0.33", self.EOL_MAP) == "2019-01-10"

    def test_no_match(self):
        assert is_eol("8.2.0", self.EOL_MAP) is None

    def test_prefix_match(self):
        assert is_eol("5.6.40", self.EOL_MAP) == "2021-02-01"

    def test_exact_prefix(self):
        assert is_eol("7.4", self.EOL_MAP) == "2022-11-28"

    def test_empty_version(self):
        assert is_eol("", self.EOL_MAP) is None
