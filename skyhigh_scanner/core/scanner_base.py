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

from .compliance import enrich_findings, compliance_summary, format_controls, FRAMEWORKS
from .finding import Finding
from .scan_profiles import ScanProfile, get_profile, DEFAULT_PROFILE


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

    def __init__(self, verbose: bool = False, profile: ScanProfile = None):
        self.verbose = verbose
        self.profile: ScanProfile = profile or get_profile(DEFAULT_PROFILE)
        self.findings: List[Finding] = []
        self.targets_scanned: List[str] = []
        self.targets_failed: List[str] = []
        self._start_time: float = 0.0
        self._end_time: float = 0.0

    # ── Abstract ─────────────────────────────────────────────────────
    @abstractmethod
    def scan(self) -> None:
        """Execute the scan. Must be implemented by every scanner."""

    # ── Profile gate ────────────────────────────────────────────────
    def _check_enabled(self, category: str) -> bool:
        """Return True if *category* is enabled by the active scan profile."""
        return self.profile.is_enabled(category)

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

    # ── Compliance enrichment ─────────────────────────────────────────
    def enrich_compliance(self) -> int:
        """Map all findings to compliance framework controls.

        Returns:
            Number of findings enriched.
        """
        return enrich_findings(self.findings)

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
        compliance_mapped = sum(1 for f in self.findings if f.compliance)
        comp_summary = compliance_summary(self.findings) if compliance_mapped else {}
        return {
            "scanner": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "target_type": self.TARGET_TYPE,
            "profile": self.profile.name,
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
            "compliance_mapped": compliance_mapped,
            "compliance": comp_summary,
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
            if f.compliance:
                print(f"    Compliance: {format_controls(f.compliance)}")

        # Compliance summary
        if s.get("compliance_mapped"):
            print(f"\n{'-'*70}")
            print(f" {self.BOLD}Compliance Mapping{self.RESET} "
                  f"({s['compliance_mapped']}/{total} findings mapped)")
            for fw_key, fw_label in FRAMEWORKS.items():
                controls = s.get("compliance", {}).get(fw_key, {})
                if controls:
                    top = list(controls.items())[:5]
                    top_str = ", ".join(f"{c} ({n})" for c, n in top)
                    print(f"  {fw_label}: {top_str}")

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
            "nist_800_53", "iso_27001", "pci_dss", "cis_controls",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for f in self.findings:
                row = f.to_dict()
                # Flatten compliance into per-framework columns
                comp = row.pop("compliance", None) or {}
                for fw in ("nist_800_53", "iso_27001", "pci_dss", "cis_controls"):
                    row[fw] = ", ".join(comp.get(fw, []))
                writer.writerow(row)
        self._info(f"CSV report saved to {path}")

    # ── SARIF export ─────────────────────────────────────────────────
    def save_sarif(self, path: str) -> None:
        """Export findings in SARIF v2.1.0 format.

        SARIF (Static Analysis Results Interchange Format) is an OASIS
        standard consumed by GitHub Code Scanning, VS Code SARIF Viewer,
        Azure DevOps, and many other tools.
        """
        SARIF_SEVERITY = {
            "CRITICAL": "error",
            "HIGH":     "error",
            "MEDIUM":   "warning",
            "LOW":      "note",
            "INFO":     "note",
        }

        # Build rule descriptors (deduplicated by rule_id)
        rules_map: dict = {}
        for f in self.findings:
            if f.rule_id not in rules_map:
                props = {}
                if f.cwe:
                    props["tags"] = [f.cwe]
                if f.cvss is not None:
                    props["security-severity"] = str(f.cvss)
                rule = {
                    "id": f.rule_id,
                    "name": f.name,
                    "shortDescription": {"text": f.name},
                    "fullDescription": {"text": f.description},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html"
                               if f.cwe and f.cwe.startswith("CWE-") else None,
                    "help": {
                        "text": f.recommendation,
                        "markdown": f"**Recommendation:** {f.recommendation}",
                    },
                    "defaultConfiguration": {
                        "level": SARIF_SEVERITY.get(f.severity, "note"),
                    },
                }
                if props:
                    rule["properties"] = props
                # Strip None values
                rule = {k: v for k, v in rule.items() if v is not None}
                rules_map[f.rule_id] = rule

        rules = list(rules_map.values())
        rule_index = {r["id"]: i for i, r in enumerate(rules)}

        # Build results
        results = []
        for f in self.findings:
            result = {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": SARIF_SEVERITY.get(f.severity, "note"),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": max(f.line_num, 1)},
                    },
                }],
            }

            # Fingerprint for deduplication
            result["fingerprints"] = {
                "skyhigh/v1": f"{f.rule_id}:{f.file_path}:{f.line_num}",
            }

            # Fixes / recommendations
            if f.recommendation:
                result["fixes"] = [{
                    "description": {"text": f.recommendation},
                }]

            # Properties bag for extra metadata
            props = {}
            if f.category:
                props["category"] = f.category
            if f.cve:
                props["cve"] = f.cve
            if f.cisa_kev:
                props["cisa_kev"] = True
            if f.epss is not None:
                props["epss"] = f.epss
            if f.fix_version:
                props["fix_version"] = f.fix_version
            if f.compliance:
                props["compliance"] = f.compliance
            if props:
                result["properties"] = props

            results.append(result)

        # Assemble SARIF envelope
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.SCANNER_NAME,
                        "version": self.SCANNER_VERSION,
                        "semanticVersion": self.SCANNER_VERSION,
                        "informationUri": "https://github.com/Krishcalin/SKYHIGH-SCANNER",
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.fromtimestamp(
                        self._start_time, tz=timezone.utc
                    ).isoformat() if self._start_time else None,
                    "endTimeUtc": datetime.fromtimestamp(
                        self._end_time, tz=timezone.utc
                    ).isoformat() if self._end_time else None,
                }],
            }],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, ensure_ascii=False)
        self._info(f"SARIF report saved to {path}")

    # ── Exit code ────────────────────────────────────────────────────
    def exit_code(self) -> int:
        """Return 1 if CRITICAL or HIGH findings exist, 0 otherwise."""
        for f in self.findings:
            if f.severity in ("CRITICAL", "HIGH"):
                return 1
        return 0
