"""
Abstract base class for all SkyHigh scanner modules.

Every scanner (Windows, Linux, Cisco, WebServer, Middleware, Database)
inherits from ``ScannerBase`` and implements the ``scan()`` method.
"""

from __future__ import annotations

import sys
import time
import json
from abc import ABC, abstractmethod
from collections import Counter
from datetime import datetime, timezone
from typing import List, Optional

from .finding import Finding


class ScannerBase(ABC):
    """Base class providing shared infrastructure for all scanners."""

    # ── Severity ordering & ANSI colours ─────────────────────────────
    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",   # bright red
        "HIGH":     "\033[31m",   # red
        "MEDIUM":   "\033[33m",   # yellow
        "LOW":      "\033[36m",   # cyan
        "INFO":     "\033[37m",   # white
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    GREEN = "\033[32m"
    DIM   = "\033[2m"

    # Subclasses should override these
    SCANNER_NAME: str = "SkyHigh Scanner"
    SCANNER_VERSION: str = "1.0.0"
    TARGET_TYPE: str = "generic"        # windows | linux | cisco | webserver | middleware | database

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.targets_scanned: List[str] = []
        self.targets_failed: List[str] = []
        self._start_time: float = 0.0
        self._end_time: float = 0.0

    # ── Abstract ─────────────────────────────────────────────────────
    @abstractmethod
    def scan(self) -> None:
        """Execute the scan. Must be implemented by every scanner."""

    # ── Finding management ───────────────────────────────────────────
    def _add(self, rule_id: str, name: str, category: str, severity: str,
             file_path: str, line_num: int, line_content: str,
             description: str, recommendation: str,
             cwe: str = None, cve: str = None, **kwargs) -> None:
        """Create and append a Finding."""
        f = Finding(
            rule_id=rule_id,
            name=name,
            category=category,
            severity=severity,
            file_path=file_path,
            line_num=line_num,
            line_content=line_content,
            description=description,
            recommendation=recommendation,
            cwe=cwe,
            cve=cve,
            target_type=self.TARGET_TYPE,
            **kwargs,
        )
        self.findings.append(f)
        if self.verbose:
            self._vprint(f"  {f.one_liner()}")

    def _add_finding(self, finding: Finding) -> None:
        """Append a pre-built Finding object."""
        if finding.target_type is None:
            finding.target_type = self.TARGET_TYPE
        self.findings.append(finding)
        if self.verbose:
            self._vprint(f"  {finding.one_liner()}")

    # ── Output helpers ───────────────────────────────────────────────
    def _vprint(self, msg: str) -> None:
        """Print only in verbose mode."""
        if self.verbose:
            print(f"{self.DIM}[v] {msg}{self.RESET}", file=sys.stderr)

    def _warn(self, msg: str) -> None:
        """Print a warning (always visible)."""
        print(f"\033[33m[!] {msg}{self.RESET}", file=sys.stderr)

    def _info(self, msg: str) -> None:
        """Print an info message (always visible)."""
        print(f"{self.GREEN}[*] {msg}{self.RESET}", file=sys.stderr)

    def _error(self, msg: str) -> None:
        """Print an error (always visible)."""
        print(f"\033[91m[-] {msg}{self.RESET}", file=sys.stderr)

    # ── Timing ───────────────────────────────────────────────────────
    def _start_timer(self) -> None:
        self._start_time = time.time()

    def _stop_timer(self) -> None:
        self._end_time = time.time()

    @property
    def duration_seconds(self) -> float:
        if self._end_time and self._start_time:
            return round(self._end_time - self._start_time, 2)
        return 0.0

    # ── Filtering ────────────────────────────────────────────────────
    def filter_severity(self, min_severity: str) -> None:
        """Remove findings below *min_severity*."""
        cutoff = self.SEVERITY_ORDER.get(min_severity.upper(), 5)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 5) <= cutoff
        ]

    # ── Summary ──────────────────────────────────────────────────────
    def summary(self) -> dict:
        """Return scan summary statistics."""
        counts = Counter(f.severity for f in self.findings)
        categories = Counter(f.category for f in self.findings)
        kev_count = sum(1 for f in self.findings if f.cisa_kev)
        epss_values = [f.epss for f in self.findings if f.epss is not None]
        epss_high = sum(1 for v in epss_values if v >= 0.5)
        return {
            "scanner": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "target_type": self.TARGET_TYPE,
            "generated": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": self.duration_seconds,
            "targets_scanned": len(self.targets_scanned),
            "targets_failed": len(self.targets_failed),
            "total_findings": len(self.findings),
            "kev_findings": kev_count,
            "epss_high_risk": epss_high,
            "epss_populated": len(epss_values),
            "severity_counts": {
                "CRITICAL": counts.get("CRITICAL", 0),
                "HIGH": counts.get("HIGH", 0),
                "MEDIUM": counts.get("MEDIUM", 0),
                "LOW": counts.get("LOW", 0),
                "INFO": counts.get("INFO", 0),
            },
            "category_counts": dict(categories.most_common()),
        }

    # ── Console report ───────────────────────────────────────────────
    def print_report(self) -> None:
        """Print coloured console report."""
        s = self.summary()
        total = s["total_findings"]

        print(f"\n{'='*70}")
        print(f" {self.BOLD}{self.SCANNER_NAME} v{self.SCANNER_VERSION} - Scan Report{self.RESET}")
        print(f"{'='*70}")
        print(f" Targets scanned : {s['targets_scanned']}")
        print(f" Targets failed  : {s['targets_failed']}")
        print(f" Scan duration   : {s['scan_duration_seconds']}s")
        print(f" Total findings  : {total}")
        if s["kev_findings"]:
            print(f" \033[91mCISA KEV (Actively Exploited): {s['kev_findings']}{self.RESET}")
        if s["epss_high_risk"]:
            print(f" \033[33mEPSS High Risk (≥50%): {s['epss_high_risk']}{self.RESET}")
        print(f"{'-'*70}")

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cnt = s["severity_counts"][sev]
            if cnt:
                colour = self.SEVERITY_COLOR.get(sev, "")
                print(f"  {colour}{sev:10s}{self.RESET}: {cnt}")

        print(f"{'-'*70}")

        # Sort: CRITICAL first, then HIGH, etc.
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99)
        )

        for f in sorted_findings:
            sev_colour = self.SEVERITY_COLOR.get(f.severity, "")
            kev_badge = f" {self.BOLD}\033[91m[ACTIVELY EXPLOITED]{self.RESET}" if f.cisa_kev else ""
            cve_str = f" ({f.cve})" if f.cve else ""

            print(f"\n  {sev_colour}[{f.severity}]{self.RESET} {self.BOLD}{f.rule_id}{self.RESET}: "
                  f"{f.name}{cve_str}{kev_badge}")
            print(f"    Target : {f.file_path}")
            if f.line_content:
                print(f"    Detail : {f.line_content}")
            print(f"    Desc   : {f.description}")
            print(f"    Fix    : {f.recommendation}")
            if f.cwe:
                print(f"    CWE    : {f.cwe}")
            if f.cvss:
                print(f"    CVSS   : {f.cvss}")
            if f.epss is not None:
                print(f"    EPSS   : {f.epss * 100:.1f}%")

        print(f"\n{'='*70}\n")

    # ── JSON export ──────────────────────────────────────────────────
    def save_json(self, path: str) -> None:
        """Export findings to a JSON file."""
        data = self.summary()
        data["targets"] = {
            "scanned": self.targets_scanned,
            "failed": self.targets_failed,
        }
        data["findings"] = [f.to_dict() for f in self.findings]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        self._info(f"JSON report saved to {path}")

    # ── CSV export ───────────────────────────────────────────────────
    def save_csv(self, path: str) -> None:
        """Export findings to a CSV file."""
        import csv
        fields = [
            "rule_id", "severity", "name", "category", "cve", "cwe",
            "file_path", "line_content", "description", "recommendation",
            "cvss", "epss", "cisa_kev", "target_type",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for f in self.findings:
                writer.writerow(f.to_dict())
        self._info(f"CSV report saved to {path}")

    # ── Exit code ────────────────────────────────────────────────────
    def exit_code(self) -> int:
        """Return 1 if CRITICAL or HIGH findings exist, 0 otherwise."""
        for f in self.findings:
            if f.severity in ("CRITICAL", "HIGH"):
                return 1
        return 0
