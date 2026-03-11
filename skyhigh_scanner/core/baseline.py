"""
Baseline / diff scanning support.

Compares current scan findings against a previous baseline to identify:
  - NEW findings (not in baseline)
  - FIXED findings (in baseline but no longer present)
  - UNCHANGED findings (still present)

Usage:
  1. Run a scan with --json baseline.json to create a baseline
  2. Run again with --baseline baseline.json to compare
  3. Output shows only new/fixed findings with diff labels

Finding identity is based on (rule_id, file_path/target, line_content).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

from .finding import Finding


def _finding_key(f: Finding) -> str:
    """Generate a stable identity key for a finding."""
    return f"{f.rule_id}|{f.file_path}|{f.line_content}"


def _finding_key_from_dict(d: dict) -> str:
    """Generate identity key from a JSON-loaded finding dict."""
    return f"{d.get('rule_id', '')}|{d.get('file_path', '')}|{d.get('line_content', '')}"


def load_baseline(path: str) -> List[dict]:
    """Load a baseline JSON file.

    Args:
        path: Path to a previously saved JSON scan report.

    Returns:
        List of finding dicts from the baseline.

    Raises:
        FileNotFoundError: If baseline file doesn't exist.
        ValueError: If file format is invalid.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    with open(p, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Support both flat list and {"findings": [...]} format
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        findings = data.get("findings", [])
        if isinstance(findings, list):
            return findings

    raise ValueError(f"Invalid baseline format in {path}")


def compute_diff(
    current: List[Finding],
    baseline: List[dict],
) -> Dict[str, list]:
    """Compare current findings against a baseline.

    Args:
        current: Current scan findings (Finding objects).
        baseline: Previous scan findings (dicts from JSON).

    Returns:
        Dict with keys:
            "new": List of Finding objects present now but not in baseline.
            "fixed": List of dicts present in baseline but not now.
            "unchanged": List of Finding objects present in both.
    """
    baseline_keys: Set[str] = {_finding_key_from_dict(d) for d in baseline}
    current_keys: Set[str] = {_finding_key(f) for f in current}

    new_findings = [f for f in current if _finding_key(f) not in baseline_keys]
    unchanged = [f for f in current if _finding_key(f) in baseline_keys]
    fixed = [d for d in baseline if _finding_key_from_dict(d) not in current_keys]

    return {
        "new": new_findings,
        "fixed": fixed,
        "unchanged": unchanged,
    }


def diff_summary(diff: Dict[str, list]) -> Dict[str, int]:
    """Summarize a diff result.

    Returns:
        Dict with counts: new, fixed, unchanged, total_current, total_baseline.
    """
    return {
        "new": len(diff["new"]),
        "fixed": len(diff["fixed"]),
        "unchanged": len(diff["unchanged"]),
        "total_current": len(diff["new"]) + len(diff["unchanged"]),
        "total_baseline": len(diff["fixed"]) + len(diff["unchanged"]),
    }


def print_diff_report(diff: Dict[str, list]) -> None:
    """Print a human-readable diff report to stderr."""
    import sys

    summary = diff_summary(diff)
    print(f"\n{'─' * 60}", file=sys.stderr)
    print(f"  Baseline Comparison", file=sys.stderr)
    print(f"{'─' * 60}", file=sys.stderr)
    print(f"  Baseline findings : {summary['total_baseline']}", file=sys.stderr)
    print(f"  Current findings  : {summary['total_current']}", file=sys.stderr)
    print(f"  New findings      : \033[31m{summary['new']}\033[0m", file=sys.stderr)
    print(f"  Fixed findings    : \033[32m{summary['fixed']}\033[0m", file=sys.stderr)
    print(f"  Unchanged         : {summary['unchanged']}", file=sys.stderr)
    print(f"{'─' * 60}", file=sys.stderr)

    if diff["new"]:
        print(f"\n  \033[1m\033[31m[NEW] Findings not in baseline:\033[0m", file=sys.stderr)
        for f in diff["new"]:
            sev = f.severity
            print(f"    [{sev}] {f.rule_id}: {f.name} @ {f.file_path}",
                  file=sys.stderr)

    if diff["fixed"]:
        print(f"\n  \033[1m\033[32m[FIXED] Findings resolved since baseline:\033[0m",
              file=sys.stderr)
        for d in diff["fixed"]:
            sev = d.get("severity", "?")
            print(f"    [{sev}] {d.get('rule_id', '?')}: {d.get('name', '?')} "
                  f"@ {d.get('file_path', '?')}", file=sys.stderr)

    print(file=sys.stderr)
