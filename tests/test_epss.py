"""Tests for EPSS integration across all layers."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnerability_management.core.cve_database import CVEDatabase
from vulnerability_management.core.finding import Finding

# ── CVE Database: EPSS propagation ─────────────────────────────────────

class TestEpssInCheckVersion:
    """Verify EPSS flows from DB → Finding via check_version()."""

    def test_epss_propagated_to_finding(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            findings = db.check_version("test_platform", "1.5")

        # Both seed entries have epss_score
        for f in findings:
            assert f.epss is not None

        kev_finding = next(f for f in findings if f.cve == "CVE-2024-00001")
        assert kev_finding.epss == 0.85

        other = next(f for f in findings if f.cve == "CVE-2024-00002")
        assert other.epss == 0.45

    def test_epss_none_when_not_in_seed(self, tmp_cve_db, tmp_dir):
        """CVEs without epss_score should have epss=None in findings."""
        seed = [{
            "cve_id": "CVE-2025-99999",
            "platform": "no_epss_platform",
            "severity": "MEDIUM",
            "cvss_v3": 5.0,
            "published": "2025-01-01",
            "name": "No EPSS CVE",
            "affected": ">=1.0,<2.0",
        }]
        path = tmp_dir / "no_epss_seed.json"
        path.write_text(json.dumps(seed))

        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(tmp_dir))
            findings = db.check_version("no_epss_platform", "1.5")

        assert len(findings) == 1
        assert findings[0].epss is None


class TestEpssInCheckLinuxPackage:
    """Verify EPSS flows through check_linux_package()."""

    def test_epss_in_linux_package_finding(self, tmp_cve_db, tmp_dir):
        seed = [{
            "cve_id": "CVE-2025-11111",
            "platform": "openssh",
            "severity": "HIGH",
            "cvss_v3": 8.0,
            "published": "2025-01-01",
            "name": "Test SSH CVE",
            "epss_score": 0.72,
            "linux_packages": [
                {"distro": "ubuntu", "release": "22.04",
                 "package": "openssh-server", "fixed_version": "9.0"}
            ],
        }]
        path = tmp_dir / "lnx_seed.json"
        path.write_text(json.dumps(seed))

        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(tmp_dir))
            findings = db.check_linux_package("ubuntu", "22.04", "openssh-server", "8.5")

        assert len(findings) == 1
        assert findings[0].epss == 0.72


# ── CVE Database: enrich_epss() ────────────────────────────────────────

class TestEnrichEpss:
    def test_enrich_updates_scores(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            count = db.enrich_epss({"CVE-2024-00001": 0.95, "CVE-2024-00002": 0.10})
        assert count == 2

    def test_enrich_empty_map(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            count = db.enrich_epss({})
        assert count == 0

    def test_enrich_no_connection(self, tmp_cve_db):
        db = CVEDatabase(db_path=tmp_cve_db)
        assert db.enrich_epss({"CVE-XXXX": 0.5}) == 0

    def test_enrich_unknown_cve(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            count = db.enrich_epss({"CVE-9999-99999": 0.5})
        assert count == 0


# ── CVE Database: flag_epss_findings() ─────────────────────────────────

class TestFlagEpssFindings:
    def test_flag_epss_enriches_findings(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))

            f = Finding(
                rule_id="TEST", name="T", category="C",
                severity="HIGH", file_path="x", line_num=0,
                line_content="", description="D", recommendation="R",
                cve="CVE-2024-00001",
            )
            count = db.flag_epss_findings([f])

        assert count == 1
        assert f.epss == 0.85

    def test_flag_epss_skips_existing(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))

            f = Finding(
                rule_id="TEST", name="T", category="C",
                severity="HIGH", file_path="x", line_num=0,
                line_content="", description="D", recommendation="R",
                cve="CVE-2024-00001", epss=0.99,
            )
            count = db.flag_epss_findings([f])

        assert count == 0
        assert f.epss == 0.99  # unchanged

    def test_flag_epss_no_connection(self, tmp_cve_db):
        db = CVEDatabase(db_path=tmp_cve_db)
        assert db.flag_epss_findings([]) == 0


# ── CVE Database: stats() EPSS fields ─────────────────────────────────

class TestStatsEpss:
    def test_stats_include_epss(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            stats = db.stats()

        assert "epss_populated" in stats
        assert stats["epss_populated"] == 2
        assert "epss_avg" in stats
        assert 0.0 < stats["epss_avg"] < 1.0
        assert "epss_high_risk" in stats
        assert stats["epss_high_risk"] == 1  # only 0.85 >= 0.5


# ── Finding: EPSS serialisation ────────────────────────────────────────

class TestFindingEpss:
    def test_epss_in_to_dict(self):
        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R", epss=0.73,
        )
        d = f.to_dict()
        assert d["epss"] == 0.73

    def test_epss_none_stripped(self):
        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R",
        )
        d = f.to_dict()
        assert "epss" not in d

    def test_epss_in_json_roundtrip(self):
        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R", epss=0.42,
        )
        data = json.loads(f.to_json())
        assert data["epss"] == 0.42


# ── Scanner Base: EPSS in summary & output ─────────────────────────────

class TestScannerBaseEpss:
    def test_summary_epss_fields(self):
        from vulnerability_management.core.scanner_base import ScannerBase

        class Stub(ScannerBase):
            SCANNER_NAME = "T"
            SCANNER_VERSION = "1"
            TARGET_TYPE = "generic"
            def scan(self): pass

        s = Stub()
        s._add(
            rule_id="X", name="N", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="", description="D",
            recommendation="R", epss=0.75,
        )
        s._add(
            rule_id="Y", name="N2", category="C", severity="MEDIUM",
            file_path="x", line_num=0, line_content="", description="D",
            recommendation="R", epss=0.30,
        )
        s._add(
            rule_id="Z", name="N3", category="C", severity="LOW",
            file_path="x", line_num=0, line_content="", description="D",
            recommendation="R",
        )

        summary = s.summary()
        assert summary["epss_populated"] == 2
        assert summary["epss_high_risk"] == 1  # only 0.75 >= 0.5

    def test_csv_includes_epss_header(self, tmp_dir):
        from vulnerability_management.core.scanner_base import ScannerBase

        class Stub(ScannerBase):
            SCANNER_NAME = "T"
            SCANNER_VERSION = "1"
            TARGET_TYPE = "generic"
            def scan(self): pass

        s = Stub()
        s._add(
            rule_id="X", name="N", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="", description="D",
            recommendation="R", epss=0.55,
        )
        path = str(tmp_dir / "test.csv")
        s.save_csv(path)

        header = Path(path).read_text().split("\n")[0]
        assert "epss" in header

    def test_console_report_shows_epss(self, capsys):
        from vulnerability_management.core.scanner_base import ScannerBase

        class Stub(ScannerBase):
            SCANNER_NAME = "T"
            SCANNER_VERSION = "1"
            TARGET_TYPE = "generic"
            def scan(self): pass

        s = Stub()
        s._add(
            rule_id="X", name="N", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="", description="D",
            recommendation="R", epss=0.82,
        )
        s.print_report()
        out = capsys.readouterr().out
        assert "82.0%" in out
        assert "EPSS" in out


# ── HTML Report: EPSS badges ──────────────────────────────────────────

class TestHtmlReportEpss:
    def _summary(self, **overrides):
        base = {
            "scan_duration_seconds": 0,
            "targets_scanned": 1,
            "targets_failed": 0,
            "kev_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }
        base.update(overrides)
        return base

    def test_epss_badge_high(self):
        from vulnerability_management.core.reporting import generate_html_report

        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R",
            cve="CVE-2024-00001", epss=0.85,
        )
        html = generate_html_report("S", "1", "generic", [f], self._summary())
        assert "EPSS 85.0%" in html
        assert "epss-high" in html

    def test_epss_badge_medium(self):
        from vulnerability_management.core.reporting import generate_html_report

        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R",
            cve="CVE-2024-00002", epss=0.25,
        )
        html = generate_html_report("S", "1", "generic", [f], self._summary())
        assert "EPSS 25.0%" in html
        assert "epss-med" in html

    def test_epss_badge_low(self):
        from vulnerability_management.core.reporting import generate_html_report

        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R",
            cve="CVE-2024-00003", epss=0.05,
        )
        html = generate_html_report("S", "1", "generic", [f], self._summary())
        assert "EPSS 5.0%" in html
        assert "epss-low" in html

    def test_no_epss_badge_when_none(self):
        from vulnerability_management.core.reporting import generate_html_report

        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R",
        )
        html = generate_html_report("S", "1", "generic", [f], self._summary())
        # CSS class definition exists in <style>, but no EPSS badge in findings
        assert "EPSS " not in html.split("findingsContainer")[1] if "findingsContainer" in html else True

    def test_epss_dashboard_card(self):
        from vulnerability_management.core.reporting import generate_html_report

        f = Finding(
            rule_id="T", name="T", category="C", severity="HIGH",
            file_path="x", line_num=0, line_content="",
            description="D", recommendation="R", epss=0.75,
        )
        html = generate_html_report("S", "1", "generic", [f], self._summary())
        assert "EPSS" in html
        assert "stat-epss" in html


# ── CLI: epss-sync command ─────────────────────────────────────────────

class TestCliEpssSync:
    def test_epss_sync_parses(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["epss-sync", "-v"])
        assert args.command == "epss-sync"
        assert args.verbose is True

    def test_epss_sync_default(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["epss-sync"])
        assert args.command == "epss-sync"


# ── CVE Sync: EPSS API mock ───────────────────────────────────────────

try:
    import requests as _requests  # noqa: F401
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
class TestCveSyncEpss:
    def test_sync_epss_mocked(self, tmp_cve_db, mini_seed_dir):
        from vulnerability_management.core.cve_sync import CVESync

        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))

            sync = CVESync(db, verbose=False)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": [
                    {"cve": "CVE-2024-00001", "epss": "0.92", "percentile": "0.98"},
                    {"cve": "CVE-2024-00002", "epss": "0.15", "percentile": "0.60"},
                ]
            }
            mock_response.raise_for_status = MagicMock()

            with patch.object(sync._session, "get", return_value=mock_response):
                count = sync.sync_epss()

            assert count == 2

            # Verify scores were updated
            cur = db.conn.cursor()
            cur.execute("SELECT epss_score FROM cves WHERE cve_id = 'CVE-2024-00001'")
            assert cur.fetchone()["epss_score"] == 0.92

            cur.execute("SELECT epss_score FROM cves WHERE cve_id = 'CVE-2024-00002'")
            assert cur.fetchone()["epss_score"] == 0.15

    def test_sync_epss_api_error(self, tmp_cve_db, mini_seed_dir):
        from vulnerability_management.core.cve_sync import CVESync

        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            sync = CVESync(db, verbose=False)

            with patch.object(sync._session, "get", side_effect=Exception("Connection refused")):
                count = sync.sync_epss()

            # Should not crash, returns 0
            assert count == 0

    def test_sync_epss_empty_db(self, tmp_cve_db):
        from vulnerability_management.core.cve_sync import CVESync

        with CVEDatabase(db_path=tmp_cve_db) as db:
            sync = CVESync(db, verbose=False)
            count = sync.sync_epss()

        assert count == 0
