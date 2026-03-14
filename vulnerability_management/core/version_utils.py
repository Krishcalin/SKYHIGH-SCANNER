"""
Version parsing and range-matching utilities.

Used by every scanner to compare detected software versions against CVE
affected-version ranges.

Range syntax examples:
  ">=15.0,<15.9"       → 15.0 ≤ v < 15.9
  "<17.3.8"            → v < 17.3.8
  ">=12.0,<=12.4.3"   → 12.0 ≤ v ≤ 12.4.3
"""

from __future__ import annotations

import re


def parse_ver(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints.

    Examples:
        "17.3.8"       → (17, 3, 8)
        "1.8.0_381"    → (1, 8, 0, 381)
        "10.0.19045.4651" → (10, 0, 19045, 4651)
        "8.1.27-1ubuntu3" → (8, 1, 27, 1)
    """
    if not version_str:
        return (0,)
    # Replace common separators with dots, then extract numeric parts
    normalised = re.sub(r"[_\-+~]", ".", str(version_str))
    parts = re.findall(r"\d+", normalised)
    if not parts:
        return (0,)
    return tuple(int(p) for p in parts)


def version_in_range(version: str, range_str: str) -> bool:
    """Check whether *version* satisfies a comma-separated range expression.

    Each sub-expression is one of:
        <V   <=V   >V   >=V   ==V   =V

    All sub-expressions must be satisfied (AND logic).

    Args:
        version:   The version string to test (e.g. "15.6.3").
        range_str: Comma-separated conditions (e.g. ">=15.0,<15.9").

    Returns:
        True if *version* matches every condition.
    """
    if not version or not range_str:
        return False

    ver = parse_ver(version)

    for cond in range_str.split(","):
        cond = cond.strip()
        if not cond:
            continue

        m = re.match(r"^(<=?|>=?|==?)\s*(.+)$", cond)
        if not m:
            continue

        op, target_str = m.group(1), m.group(2).strip()
        target = parse_ver(target_str)

        if op in ("==", "="):
            if ver != target:
                return False
        elif op == "<":
            if not (ver < target):
                return False
        elif op == "<=":
            if not (ver <= target):
                return False
        elif op == ">":
            if not (ver > target):
                return False
        elif op == ">=" and not (ver >= target):
            return False

    return True


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Returns:
        -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
    """
    a, b = parse_ver(v1), parse_ver(v2)
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def is_eol(version: str, eol_versions: dict[str, str]) -> str | None:
    """Check if a version matches a known end-of-life branch.

    Args:
        version: Detected version string.
        eol_versions: Mapping of version prefix → EOL date string.
                      e.g. {"5.6": "2021-02-01", "7.0": "2019-01-10"}

    Returns:
        EOL date string if matched, None otherwise.
    """
    for prefix, eol_date in eol_versions.items():
        if version.startswith(prefix):
            return eol_date
    return None
