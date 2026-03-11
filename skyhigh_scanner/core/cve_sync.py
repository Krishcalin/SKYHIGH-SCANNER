"""
CVE database synchronisation from NVD API 2.0, vendor feeds, and CISA KEV.

Usage:
    python -m skyhigh_scanner cve-sync --api-key YOUR_KEY --since 2010
    python -m skyhigh_scanner cve-sync --incremental
    python -m skyhigh_scanner cve-import --seed-dir cve_data/seed/
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from .cve_database import CVEDatabase

# ── CPE match strings for target platforms ───────────────────────────
CPE_QUERIES = {
    # Operating Systems
    "windows_10":              "cpe:2.3:o:microsoft:windows_10:*",
    "windows_11":              "cpe:2.3:o:microsoft:windows_11:*",
    "windows_server_2012":     "cpe:2.3:o:microsoft:windows_server_2012:*",
    "windows_server_2016":     "cpe:2.3:o:microsoft:windows_server_2016:*",
    "windows_server_2019":     "cpe:2.3:o:microsoft:windows_server_2019:*",
    "windows_server_2022":     "cpe:2.3:o:microsoft:windows_server_2022:*",
    "linux_kernel":            "cpe:2.3:o:linux:linux_kernel:*",
    "cisco_ios":               "cpe:2.3:o:cisco:ios:*",
    "cisco_ios_xe":            "cpe:2.3:o:cisco:ios_xe:*",
    "cisco_nx_os":             "cpe:2.3:o:cisco:nx-os:*",

    # Web Servers
    "apache_httpd":            "cpe:2.3:a:apache:http_server:*",
    "nginx":                   "cpe:2.3:a:f5:nginx:*",
    "iis":                     "cpe:2.3:a:microsoft:internet_information_services:*",
    "tomcat":                  "cpe:2.3:a:apache:tomcat:*",
    "weblogic":                "cpe:2.3:a:oracle:weblogic_server:*",
    "websphere":               "cpe:2.3:a:ibm:websphere_application_server:*",

    # Java Ecosystem
    "oracle_jdk":              "cpe:2.3:a:oracle:jdk:*",
    "oracle_jre":              "cpe:2.3:a:oracle:jre:*",
    "jboss_eap":               "cpe:2.3:a:redhat:jboss_enterprise_application_platform:*",
    "wildfly":                 "cpe:2.3:a:redhat:wildfly:*",
    "spring_framework":        "cpe:2.3:a:vmware:spring_framework:*",
    "spring_boot":             "cpe:2.3:a:vmware:spring_boot:*",
    "log4j":                   "cpe:2.3:a:apache:log4j:*",

    # .NET Ecosystem
    "dotnet_framework":        "cpe:2.3:a:microsoft:.net_framework:*",
    "dotnet":                  "cpe:2.3:a:microsoft:.net:*",
    "aspnet_core":             "cpe:2.3:a:microsoft:asp.net_core:*",

    # PHP Ecosystem
    "php":                     "cpe:2.3:a:php:php:*",
    "laravel":                 "cpe:2.3:a:laravel:laravel:*",

    # MERN / Node.js
    "nodejs":                  "cpe:2.3:a:nodejs:node.js:*",
    "expressjs":               "cpe:2.3:a:expressjs:express:*",
    "mongodb":                 "cpe:2.3:a:mongodb:mongodb:*",

    # LAMP — MySQL
    "mysql":                   "cpe:2.3:a:oracle:mysql:*",
    "mariadb":                 "cpe:2.3:a:mariadb:mariadb:*",

    # Oracle Database
    "oracle_db":               "cpe:2.3:a:oracle:database_server:*",

    # Common packages
    "openssh":                 "cpe:2.3:a:openbsd:openssh:*",
    "openssl":                 "cpe:2.3:a:openssl:openssl:*",
    "sudo":                    "cpe:2.3:a:sudo_project:sudo:*",
    "glibc":                   "cpe:2.3:a:gnu:glibc:*",

    # Additional platforms (Phase 2)
    "cisco_asa":               "cpe:2.3:o:cisco:adaptive_security_appliance_software:*",
    "cisco_ftd":               "cpe:2.3:a:cisco:firepower_threat_defense:*",
    "exchange_server":         "cpe:2.3:a:microsoft:exchange_server:*",
    "polkit":                  "cpe:2.3:a:polkit_project:polkit:*",
    "bash":                    "cpe:2.3:a:gnu:bash:*",
    "systemd":                 "cpe:2.3:a:systemd_project:systemd:*",
    "curl":                    "cpe:2.3:a:haxx:curl:*",
    "struts":                  "cpe:2.3:a:apache:struts:*",
    "windows_server_2025":     "cpe:2.3:o:microsoft:windows_server_2025:*",
}


class CVESync:
    """Synchronise CVE data from NVD API 2.0 and vendor feeds."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Rate limits: 5 req/30s without key, 50 req/30s with key
    RATE_NO_KEY = 6.0       # seconds between requests
    RATE_WITH_KEY = 0.6     # seconds between requests

    def __init__(self, db: CVEDatabase, api_key: str = None, verbose: bool = False):
        if not HAS_REQUESTS:
            raise ImportError("CVE sync requires 'requests'. Install: pip install requests")
        self.db = db
        self.api_key = api_key
        self.verbose = verbose
        self._rate_delay = self.RATE_WITH_KEY if api_key else self.RATE_NO_KEY
        self._session = requests.Session()
        if api_key:
            self._session.headers["apiKey"] = api_key

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"\033[2m[cve-sync] {msg}\033[0m", file=sys.stderr)

    # NVD API limits date ranges to 120 days
    NVD_MAX_RANGE_DAYS = 120

    # ── NVD API sync ─────────────────────────────────────────────────
    def sync_platform(self, platform: str, cpe_string: str,
                      since_year: int = 2010) -> int:
        """Fetch all CVEs for a platform from NVD API by publication date.

        Returns:
            Number of CVEs imported.
        """
        self._log(f"Syncing {platform} ({cpe_string})...")
        start_date = f"{since_year}-01-01T00:00:00.000"
        return self._fetch_nvd_paginated(
            platform, cpe_string,
            date_key_start="pubStartDate", date_start=start_date,
            date_key_end="pubEndDate", date_end="2026-12-31T23:59:59.999",
        )

    def sync_platform_modified(self, platform: str, cpe_string: str,
                               since: str, until: str) -> int:
        """Fetch CVEs for a platform modified within a date range.

        Args:
            since: ISO 8601 start datetime (e.g. '2025-01-15T00:00:00.000').
            until: ISO 8601 end datetime.

        Returns:
            Number of CVEs imported/updated.
        """
        self._log(f"Incremental sync {platform} ({since[:10]} → {until[:10]})...")
        return self._fetch_nvd_paginated(
            platform, cpe_string,
            date_key_start="lastModStartDate", date_start=since,
            date_key_end="lastModEndDate", date_end=until,
        )

    def _fetch_nvd_paginated(self, platform: str, cpe_string: str,
                             date_key_start: str, date_start: str,
                             date_key_end: str, date_end: str) -> int:
        """Paginated NVD API fetch with configurable date parameters."""
        start_index = 0
        total_imported = 0
        results_per_page = 2000

        while True:
            params = {
                "cpeName": cpe_string,
                date_key_start: date_start,
                date_key_end: date_end,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }

            try:
                resp = self._session.get(self.NVD_API_BASE, params=params, timeout=60)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                self._log(f"  Error fetching {platform} at index {start_index}: {e}")
                break

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            count = self._process_nvd_results(platform, vulnerabilities)
            total_imported += count
            start_index += results_per_page

            self._log(f"  {platform}: {total_imported}/{total_results} CVEs processed")

            if start_index >= total_results:
                break

            time.sleep(self._rate_delay)

        return total_imported

    def _process_nvd_results(self, platform: str, vulnerabilities: list) -> int:
        """Process NVD API response and insert into database."""
        cur = self.db.conn.cursor()
        count = 0

        for vuln_wrapper in vulnerabilities:
            cve_data = vuln_wrapper.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # Extract CVSS v3.1
            metrics = cve_data.get("metrics", {})
            cvss_data = None
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    break

            cvss_score = cvss_data.get("baseScore") if cvss_data else None
            cvss_vector = cvss_data.get("vectorString", "") if cvss_data else ""
            severity = self._cvss_to_severity(cvss_score)

            # CWE
            weaknesses = cve_data.get("weaknesses", [])
            cwe = ""
            for w in weaknesses:
                for desc in w.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe = desc["value"]
                        break

            # Description
            descriptions = cve_data.get("descriptions", [])
            desc_text = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break

            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            # Insert CVE (preserve existing EPSS and KEV flags)
            cur.execute("""
                INSERT INTO cves
                    (cve_id, platform, severity, cvss_v3, cvss_vector, cwe,
                     published, modified, name, description, recommendation,
                     cisa_kev, epss_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
                ON CONFLICT(cve_id) DO UPDATE SET
                    platform = excluded.platform,
                    severity = excluded.severity,
                    cvss_v3 = excluded.cvss_v3,
                    cvss_vector = excluded.cvss_vector,
                    cwe = excluded.cwe,
                    published = excluded.published,
                    modified = excluded.modified,
                    name = excluded.name,
                    description = excluded.description
            """, (cve_id, platform, severity, cvss_score, cvss_vector, cwe,
                  published, modified, cve_id, desc_text, ""))

            # Extract affected version configurations
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if not cpe_match.get("vulnerable"):
                            continue
                        cpe_uri = cpe_match.get("criteria", "")
                        cpe_match.get("versionStartIncluding",
                                    cpe_match.get("versionStartExcluding", ""))
                        ver_end = cpe_match.get("versionEndIncluding",
                                  cpe_match.get("versionEndExcluding", ""))
                        end_inc = 1 if "versionEndIncluding" in cpe_match else 0

                        # Build a range string
                        range_parts = []
                        if "versionStartIncluding" in cpe_match:
                            range_parts.append(f">={cpe_match['versionStartIncluding']}")
                        elif "versionStartExcluding" in cpe_match:
                            range_parts.append(f">{cpe_match['versionStartExcluding']}")
                        if "versionEndIncluding" in cpe_match:
                            range_parts.append(f"<={cpe_match['versionEndIncluding']}")
                        elif "versionEndExcluding" in cpe_match:
                            range_parts.append(f"<{cpe_match['versionEndExcluding']}")

                        range_str = ",".join(range_parts) if range_parts else ""

                        cur.execute("""
                            INSERT INTO affected_versions
                                (cve_id, cpe_uri, product, version_start,
                                 version_end, end_inclusive)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (cve_id, cpe_uri, platform, range_str, ver_end, end_inc))

            count += 1

        self.db.conn.commit()
        return count

    @staticmethod
    def _cvss_to_severity(score: float | None) -> str:
        if score is None:
            return "MEDIUM"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    # ── Full sync ────────────────────────────────────────────────────
    def sync_all(self, since_year: int = 2010,
                 platforms: list[str] | None = None) -> dict[str, int]:
        """Sync platforms from NVD API by publication date.

        Args:
            since_year: Fetch CVEs published since this year.
            platforms: Optional list of platform keys to sync. If None,
                       syncs all platforms in CPE_QUERIES.

        Returns:
            Dict of platform → CVE count (plus _cisa_kev_flagged, _epss_enriched).
        """
        targets = self._resolve_platforms(platforms)
        results = {}
        total = len(targets)

        for i, (platform, cpe) in enumerate(targets, 1):
            print(f"[{i}/{total}] Syncing {platform}...", file=sys.stderr)
            count = self.sync_platform(platform, cpe, since_year)
            results[platform] = count
            print(f"  → {count} CVEs", file=sys.stderr)
            self._save_platform_sync_ts(platform)

        # Overlay CISA KEV and EPSS
        kev_count = self.sync_cisa_kev()
        results["_cisa_kev_flagged"] = kev_count

        epss_count = self.sync_epss()
        results["_epss_enriched"] = epss_count

        # Save full-sync timestamp
        self._save_sync_ts("last_full_sync")

        return results

    def sync_incremental(self, platforms: list[str] | None = None) -> dict[str, int]:
        """Sync only CVEs modified since the last sync.

        Uses NVD ``lastModStartDate``/``lastModEndDate`` parameters to fetch
        only CVEs that were created or updated since the previous sync.
        The NVD API limits date ranges to 120 days, so this method
        automatically splits wider gaps into 120-day windows.

        Args:
            platforms: Optional list of platform keys. If None, syncs all.

        Returns:
            Dict of platform → CVE count (plus _cisa_kev_flagged, _epss_enriched).
        """
        last_sync_iso = self._get_sync_ts("last_full_sync")
        if not last_sync_iso:
            print("[!] No previous sync found. Run full sync first.", file=sys.stderr)
            return {}

        # Parse last sync timestamp
        last_sync = self._parse_iso(last_sync_iso)
        if last_sync is None:
            print(f"[!] Invalid last sync timestamp: {last_sync_iso}", file=sys.stderr)
            return {}

        now = datetime.now(timezone.utc)
        elapsed = now - last_sync
        self._log(f"Incremental sync since {last_sync_iso} ({elapsed.days} days ago)")

        # Build 120-day windows
        windows = self._build_date_windows(last_sync, now)

        targets = self._resolve_platforms(platforms)
        results: dict[str, int] = {}
        total = len(targets)

        for i, (platform, cpe) in enumerate(targets, 1):
            platform_total = 0
            print(f"[{i}/{total}] Incremental sync {platform} "
                  f"({len(windows)} window{'s' if len(windows) != 1 else ''})...",
                  file=sys.stderr)

            for win_start, win_end in windows:
                since_str = win_start.strftime("%Y-%m-%dT%H:%M:%S.000")
                until_str = win_end.strftime("%Y-%m-%dT%H:%M:%S.000")
                count = self.sync_platform_modified(platform, cpe, since_str, until_str)
                platform_total += count

            results[platform] = platform_total
            print(f"  → {platform_total} CVEs updated", file=sys.stderr)
            self._save_platform_sync_ts(platform)

        # Overlay CISA KEV and EPSS
        kev_count = self.sync_cisa_kev()
        results["_cisa_kev_flagged"] = kev_count

        epss_count = self.sync_epss()
        results["_epss_enriched"] = epss_count

        # Update sync timestamp
        self._save_sync_ts("last_full_sync")

        return results

    # ── Platform & date helpers ───────────────────────────────────────

    def _resolve_platforms(self, platforms: list[str] | None) -> list[tuple[str, str]]:
        """Resolve platform list to [(platform, cpe_string)] pairs."""
        if platforms:
            resolved = []
            for p in platforms:
                if p in CPE_QUERIES:
                    resolved.append((p, CPE_QUERIES[p]))
                else:
                    print(f"[!] Unknown platform '{p}' — skipping", file=sys.stderr)
            return resolved
        return list(CPE_QUERIES.items())

    def _build_date_windows(self, start: datetime,
                            end: datetime) -> list[tuple[datetime, datetime]]:
        """Split a date range into <= 120-day windows for NVD API."""
        windows = []
        cursor = start
        max_delta = timedelta(days=self.NVD_MAX_RANGE_DAYS)
        while cursor < end:
            window_end = min(cursor + max_delta, end)
            windows.append((cursor, window_end))
            cursor = window_end
        return windows

    def _save_sync_ts(self, key: str) -> None:
        """Save a sync timestamp to metadata."""
        cur = self.db.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO sync_metadata (key, value) VALUES (?, ?)",
            (key, datetime.now(timezone.utc).isoformat()),
        )
        self.db.conn.commit()

    def _save_platform_sync_ts(self, platform: str) -> None:
        """Save per-platform sync timestamp."""
        self._save_sync_ts(f"last_sync_{platform}")

    def _get_sync_ts(self, key: str) -> str | None:
        """Read a sync timestamp from metadata."""
        cur = self.db.conn.cursor()
        cur.execute("SELECT value FROM sync_metadata WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else None

    def get_last_sync(self) -> str | None:
        """Return ISO timestamp of the last full or incremental sync."""
        return self._get_sync_ts("last_full_sync")

    def get_platform_last_sync(self, platform: str) -> str | None:
        """Return ISO timestamp of the last sync for a specific platform."""
        return self._get_sync_ts(f"last_sync_{platform}")

    @staticmethod
    def _parse_iso(iso_str: str) -> datetime | None:
        """Parse an ISO 8601 timestamp string to a timezone-aware datetime."""
        try:
            # Handle both with and without timezone info
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None

    # ── CISA KEV sync ────────────────────────────────────────────────
    def sync_cisa_kev(self) -> int:
        """Download CISA Known Exploited Vulnerabilities and flag matching CVEs.

        Returns:
            Number of CVEs flagged.
        """
        self._log("Syncing CISA KEV catalog...")
        try:
            resp = self._session.get(self.CISA_KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self._log(f"  Failed to fetch CISA KEV: {e}")
            return 0

        vulnerabilities = data.get("vulnerabilities", [])
        cur = self.db.conn.cursor()
        count = 0

        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "")
            if cve_id:
                cur.execute("UPDATE cves SET cisa_kev = 1 WHERE cve_id = ?", (cve_id,))
                if cur.rowcount > 0:
                    count += 1

        self.db.conn.commit()
        self._log(f"  Flagged {count} CVEs as CISA KEV")
        return count

    # ── EPSS sync from FIRST.org ────────────────────────────────────
    EPSS_API_BASE = "https://api.first.org/data/v1/epss"
    EPSS_BATCH_SIZE = 100  # max CVEs per request

    def sync_epss(self) -> int:
        """Fetch EPSS scores from FIRST.org API for all CVEs in the database.

        Returns:
            Number of CVEs updated with EPSS scores.
        """
        self._log("Fetching EPSS scores from FIRST.org API...")
        cur = self.db.conn.cursor()
        cur.execute("SELECT cve_id FROM cves")
        all_cves = [row["cve_id"] for row in cur.fetchall()]

        if not all_cves:
            self._log("  No CVEs in database to enrich")
            return 0

        total_updated = 0
        for i in range(0, len(all_cves), self.EPSS_BATCH_SIZE):
            batch = all_cves[i:i + self.EPSS_BATCH_SIZE]
            cve_list = ",".join(batch)

            try:
                resp = self._session.get(
                    self.EPSS_API_BASE,
                    params={"cve": cve_list},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                self._log(f"  Error fetching EPSS batch {i // self.EPSS_BATCH_SIZE + 1}: {e}")
                continue

            epss_map = {}
            for entry in data.get("data", []):
                cve_id = entry.get("cve")
                score = entry.get("epss")
                if cve_id and score is not None:
                    try:
                        epss_map[cve_id] = float(score)
                    except (ValueError, TypeError):
                        continue

            if epss_map:
                count = self.db.enrich_epss(epss_map)
                total_updated += count

            self._log(f"  EPSS batch {i // self.EPSS_BATCH_SIZE + 1}: "
                      f"{len(epss_map)} scores fetched, {total_updated} total updated")

            # Be polite to the API
            if i + self.EPSS_BATCH_SIZE < len(all_cves):
                time.sleep(1.0)

        self._log(f"  EPSS enrichment complete: {total_updated} CVEs updated")

        # Save EPSS sync timestamp
        cur.execute("""
            INSERT OR REPLACE INTO sync_metadata (key, value)
            VALUES ('last_epss_sync', ?)
        """, (datetime.now(timezone.utc).isoformat(),))
        self.db.conn.commit()

        return total_updated

    # ── Vendor feed sync stubs ───────────────────────────────────────
    def sync_msrc(self) -> int:
        """Sync Microsoft Security Response Center feed (MSRC API)."""
        # TODO: Implement MSRC CVRF API integration
        self._log("MSRC sync not yet implemented")
        return 0

    def sync_cisco_psirt(self, client_id: str = None,
                         client_secret: str = None) -> int:
        """Sync Cisco PSIRT OpenVuln API."""
        # TODO: Implement Cisco OpenVuln API integration
        self._log("Cisco PSIRT sync not yet implemented")
        return 0

    def sync_ubuntu_usn(self) -> int:
        """Sync Ubuntu Security Notices."""
        # TODO: Implement Ubuntu USN feed
        self._log("Ubuntu USN sync not yet implemented")
        return 0

    def sync_redhat_rhsa(self) -> int:
        """Sync Red Hat Security Advisories."""
        # TODO: Implement RHSA API
        self._log("Red Hat RHSA sync not yet implemented")
        return 0
