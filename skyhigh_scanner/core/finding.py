"""
Shared Finding class used by every scanner module.

The ``file_path`` field is overloaded:
  - SAST scanners  → source file path
  - Live scanners  → target IP / hostname / URL

The ``line_content`` field is overloaded:
  - SAST scanners  → matching source line
  - Live scanners  → config value / version string / API response snippet
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    """A single vulnerability / misconfiguration finding."""

    rule_id: str
    name: str
    category: str
    severity: str                       # CRITICAL | HIGH | MEDIUM | LOW
    file_path: str                      # target identifier
    line_num: int                       # 0 for live scanners
    line_content: str                   # config value / version string
    description: str
    recommendation: str
    cwe: str | None = None           # e.g. CWE-287
    cve: str | None = None           # e.g. CVE-2024-38063
    target_type: str | None = None   # windows | linux | cisco | webserver | middleware | database
    cvss: float | None = None        # CVSS v3 base score
    cisa_kev: bool = False              # True if in CISA Known Exploited Vulnerabilities
    epss: float | None = None        # Exploit Prediction Scoring System (0.0-1.0)
    fix_version: str | None = None   # Version that fixes the issue
    fix_kb: str | None = None        # Windows KB number
    advisory: str | None = None      # Vendor advisory ID
    compliance: dict[str, list[str]] | None = None  # {framework: [controls]}

    # DAST evidence — proof-of-concept request/response data
    evidence: list[dict] | None = None  # [{method, url, status, payload, proof}]

    # ── Serialisation ────────────────────────────────────────────────
    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary."""
        d = asdict(self)
        # Strip None values for compact output
        return {k: v for k, v in d.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    # ── Display ──────────────────────────────────────────────────────
    def one_liner(self) -> str:
        """Single-line summary for console output."""
        kev = " [KEV]" if self.cisa_kev else ""
        cve_str = f" ({self.cve})" if self.cve else ""
        return (
            f"[{self.severity}] {self.rule_id}: {self.name}{cve_str}{kev} "
            f"— {self.file_path}"
        )

    def __str__(self) -> str:
        return self.one_liner()

    def __repr__(self) -> str:
        return (
            f"Finding(rule_id={self.rule_id!r}, severity={self.severity!r}, "
            f"name={self.name!r})"
        )
