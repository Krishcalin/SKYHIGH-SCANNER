"""
SQLite-backed CVE database engine.

Provides fast version-to-CVE matching for all supported platforms.
The database is populated via ``cve_sync.py`` (NVD API + vendor feeds)
or from bundled seed JSON files for offline use.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import List, Optional

from .finding import Finding
from .version_utils import parse_ver, version_in_range

# Default database path
_DEFAULT_DB = Path(__file__).parent.parent / "cve_data" / "skyhigh_scanner.db"
_SEED_DIR = Path(__file__).parent.parent / "cve_data" / "seed"


class CVEDatabase:
    """SQLite-backed CVE lookup engine."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(_DEFAULT_DB)
        self.conn: Optional[sqlite3.Connection] = None

    # ── Connection management ────────────────────────────────────────
    def open(self) -> None:
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    # ── Schema ───────────────────────────────────────────────────────
    def _ensure_schema(self) -> None:
        """Create tables if they don't exist."""
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id          TEXT PRIMARY KEY,
                platform        TEXT NOT NULL,
                severity        TEXT NOT NULL,
                cvss_v3         REAL,
                cvss_vector     TEXT,
                cwe             TEXT,
                published       TEXT NOT NULL,
                modified        TEXT,
                name            TEXT,
                description     TEXT,
                recommendation  TEXT,
                cisa_kev        INTEGER DEFAULT 0,
                epss_score      REAL
            );

            CREATE TABLE IF NOT EXISTS affected_versions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id          TEXT NOT NULL,
                cpe_uri         TEXT,
                product         TEXT,
                version_start   TEXT,
                version_end     TEXT,
                end_inclusive    INTEGER DEFAULT 1,
                fix_version     TEXT,
                fix_kb          TEXT,
                fix_advisory    TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );

            CREATE TABLE IF NOT EXISTS linux_packages (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id          TEXT NOT NULL,
                distro          TEXT,
                release_ver     TEXT,
                package_name    TEXT,
                fixed_version   TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );

            CREATE TABLE IF NOT EXISTS sync_metadata (
                key             TEXT PRIMARY KEY,
                value           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_cves_platform
                ON cves(platform);
            CREATE INDEX IF NOT EXISTS idx_affected_product
                ON affected_versions(product);
            CREATE INDEX IF NOT EXISTS idx_affected_cve
                ON affected_versions(cve_id);
            CREATE INDEX IF NOT EXISTS idx_linux_pkg
                ON linux_packages(distro, package_name);
            CREATE INDEX IF NOT EXISTS idx_cves_kev
                ON cves(cisa_kev) WHERE cisa_kev = 1;
        """)
        self.conn.commit()

    # ── Seed data import ─────────────────────────────────────────────
    def import_seed(self, seed_dir: str = None) -> int:
        """Import seed JSON files into the database.

        Returns:
            Number of CVEs imported.
        """
        seed_path = Path(seed_dir) if seed_dir else _SEED_DIR
        if not seed_path.exists():
            return 0

        total = 0
        for json_file in seed_path.glob("*.json"):
            total += self._import_json_file(json_file)
        return total

    def _import_json_file(self, path: Path) -> int:
        """Import a single seed JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            entries = json.load(fh)

        if isinstance(entries, dict):
            entries = entries.get("cves", [])
        if not isinstance(entries, list):
            return 0

        count = 0
        cur = self.conn.cursor()
        for entry in entries:
            cve_id = entry.get("cve_id") or entry.get("cve", "")
            if not cve_id:
                continue

            # Upsert CVE
            cur.execute("""
                INSERT OR REPLACE INTO cves
                    (cve_id, platform, severity, cvss_v3, cvss_vector, cwe,
                     published, modified, name, description, recommendation,
                     cisa_kev, epss_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                entry.get("platform", ""),
                entry.get("severity", "MEDIUM"),
                entry.get("cvss", entry.get("cvss_v3")),
                entry.get("cvss_vector", ""),
                entry.get("cwe", ""),
                entry.get("published", ""),
                entry.get("modified", ""),
                entry.get("name", ""),
                entry.get("description", ""),
                entry.get("recommendation", ""),
                1 if entry.get("cisa_kev") else 0,
                entry.get("epss_score"),
            ))

            # Affected versions
            affected = entry.get("affected_versions", [])
            if isinstance(entry.get("affected"), str):
                # Simple format: ">=15.0,<15.9"
                affected = [{"range": entry["affected"],
                             "product": entry.get("product", "")}]
            for av in affected:
                cur.execute("""
                    INSERT INTO affected_versions
                        (cve_id, cpe_uri, product, version_start, version_end,
                         end_inclusive, fix_version, fix_kb, fix_advisory)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_id,
                    av.get("cpe_uri", ""),
                    av.get("product", entry.get("product", "")),
                    av.get("version_start", av.get("range", "")),
                    av.get("version_end", ""),
                    av.get("end_inclusive", 1),
                    av.get("fix_version", entry.get("fix_version", "")),
                    av.get("fix_kb", entry.get("fix_kb", "")),
                    av.get("fix_advisory", entry.get("advisory", "")),
                ))

            # Linux packages
            for lp in entry.get("linux_packages", []):
                cur.execute("""
                    INSERT INTO linux_packages
                        (cve_id, distro, release_ver, package_name, fixed_version)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    cve_id,
                    lp.get("distro", ""),
                    lp.get("release", ""),
                    lp.get("package", ""),
                    lp.get("fixed_version", ""),
                ))

            count += 1

        self.conn.commit()
        return count

    # ── CVE lookup methods ───────────────────────────────────────────
    def check_version(self, platform: str, version: str,
                      product: str = "") -> List[Finding]:
        """Match a software version against CVE database.

        Args:
            platform: Platform key (windows, linux_kernel, cisco_ios, etc.)
            version: Detected version string.
            product: Optional product name for narrowing results.

        Returns:
            List of Finding objects for matching CVEs.
        """
        if not self.conn:
            return []

        cur = self.conn.cursor()
        query = """
            SELECT c.*, av.product, av.version_start, av.version_end,
                   av.end_inclusive, av.fix_version, av.fix_kb, av.fix_advisory
            FROM cves c
            JOIN affected_versions av ON c.cve_id = av.cve_id
            WHERE c.platform = ?
        """
        params: list = [platform]
        if product:
            query += " AND av.product LIKE ?"
            params.append(f"%{product}%")

        cur.execute(query, params)
        findings = []

        for row in cur.fetchall():
            range_str = row["version_start"]  # may contain range like ">=15.0,<15.9"
            if not range_str:
                continue

            if version_in_range(version, range_str):
                findings.append(Finding(
                    rule_id=f"{platform.upper()}-CVE",
                    name=row["name"] or f"Vulnerability {row['cve_id']}",
                    category="Known CVE",
                    severity=row["severity"],
                    file_path="",  # caller sets this to target IP
                    line_num=0,
                    line_content=f"version={version}",
                    description=row["description"] or "",
                    recommendation=row["recommendation"] or f"Update to {row['fix_version'] or 'latest version'}",
                    cwe=row["cwe"],
                    cve=row["cve_id"],
                    cvss=row["cvss_v3"],
                    cisa_kev=bool(row["cisa_kev"]),
                    fix_version=row["fix_version"],
                    fix_kb=row["fix_kb"],
                    advisory=row["fix_advisory"],
                ))

        return findings

    def check_linux_package(self, distro: str, release: str,
                            package_name: str, installed_version: str) -> List[Finding]:
        """Check a Linux package version against known CVEs."""
        if not self.conn:
            return []

        cur = self.conn.cursor()
        cur.execute("""
            SELECT c.*, lp.fixed_version
            FROM cves c
            JOIN linux_packages lp ON c.cve_id = lp.cve_id
            WHERE lp.distro = ? AND lp.package_name = ?
              AND (lp.release_ver = ? OR lp.release_ver = '')
        """, (distro, package_name, release))

        findings = []
        installed_parsed = parse_ver(installed_version)

        for row in cur.fetchall():
            fixed = row["fixed_version"]
            if fixed and installed_parsed < parse_ver(fixed):
                findings.append(Finding(
                    rule_id=f"LNX-CVE",
                    name=row["name"] or f"Vulnerable package: {package_name}",
                    category="Known CVE",
                    severity=row["severity"],
                    file_path="",
                    line_num=0,
                    line_content=f"{package_name}={installed_version} (fix: {fixed})",
                    description=row["description"] or "",
                    recommendation=f"Update {package_name} to >= {fixed}",
                    cwe=row["cwe"],
                    cve=row["cve_id"],
                    cvss=row["cvss_v3"],
                    cisa_kev=bool(row["cisa_kev"]),
                    fix_version=fixed,
                ))

        return findings

    # ── CISA KEV flagging ────────────────────────────────────────────
    def flag_kev_findings(self, findings: List[Finding]) -> int:
        """Flag findings that match CISA Known Exploited Vulnerabilities.

        Returns:
            Number of findings flagged.
        """
        if not self.conn:
            return 0

        cur = self.conn.cursor()
        cur.execute("SELECT cve_id FROM cves WHERE cisa_kev = 1")
        kev_set = {row["cve_id"] for row in cur.fetchall()}

        count = 0
        for f in findings:
            if f.cve and f.cve in kev_set and not f.cisa_kev:
                f.cisa_kev = True
                count += 1
        return count

    # ── Statistics ───────────────────────────────────────────────────
    def stats(self) -> dict:
        """Return CVE counts per platform."""
        if not self.conn:
            return {}

        cur = self.conn.cursor()
        cur.execute("SELECT platform, COUNT(*) as cnt FROM cves GROUP BY platform")
        platform_counts = {row["platform"]: row["cnt"] for row in cur.fetchall()}

        cur.execute("SELECT COUNT(*) as cnt FROM cves")
        total = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) as cnt FROM cves WHERE cisa_kev = 1")
        kev = cur.fetchone()["cnt"]

        return {"total": total, "kev": kev, "platforms": platform_counts}
