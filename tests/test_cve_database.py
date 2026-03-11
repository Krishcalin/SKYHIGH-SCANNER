"""Tests for skyhigh_scanner.core.cve_database."""

import json
from pathlib import Path

import pytest

from skyhigh_scanner.core.cve_database import CVEDatabase


class TestCVEDatabaseInit:
    def test_open_close(self, tmp_cve_db):
        db = CVEDatabase(db_path=tmp_cve_db)
        db.open()
        assert db.conn is not None
        db.close()
        assert db.conn is None

    def test_context_manager(self, tmp_cve_db):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            assert db.conn is not None
        assert db.conn is None

    def test_schema_created(self, tmp_cve_db):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            cur = db.conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"] for row in cur.fetchall()}
            assert "cves" in tables
            assert "affected_versions" in tables
            assert "linux_packages" in tables
            assert "sync_metadata" in tables


class TestSeedImport:
    def test_import_array_format(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            count = db.import_seed(str(mini_seed_dir))
        assert count == 2

    def test_import_dict_wrapper(self, tmp_cve_db, tmp_dir):
        """Test JSON files with {"cves": [...]} wrapper."""
        wrapped = {"cves": [
            {
                "cve_id": "CVE-2025-00001",
                "platform": "wrapped",
                "severity": "MEDIUM",
                "cvss_v3": 5.0,
                "published": "2025-01-01",
                "name": "Wrapped CVE",
                "description": "Test",
                "recommendation": "Update",
                "affected": ">=1.0,<2.0",
            }
        ]}
        path = tmp_dir / "wrapped_seed.json"
        path.write_text(json.dumps(wrapped))

        with CVEDatabase(db_path=tmp_cve_db) as db:
            count = db.import_seed(str(tmp_dir))
        assert count >= 1

    def test_import_nonexistent_dir(self, tmp_cve_db):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            count = db.import_seed("/nonexistent/path/that/doesnt/exist")
        assert count == 0

    def test_import_upsert(self, tmp_cve_db, mini_seed_dir):
        """Importing the same file twice should not duplicate."""
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            db.import_seed(str(mini_seed_dir))
            cur = db.conn.cursor()
            cur.execute("SELECT COUNT(*) as cnt FROM cves")
            assert cur.fetchone()["cnt"] == 2


class TestVersionLookup:
    def test_check_version_match(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            findings = db.check_version("test_platform", "1.5")
        assert len(findings) == 2  # both CVEs have affected >=1.0,<2.0 and >=1.0,<3.0

    def test_check_version_no_match(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            findings = db.check_version("test_platform", "5.0")
        assert len(findings) == 0

    def test_check_version_wrong_platform(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            findings = db.check_version("nonexistent_platform", "1.5")
        assert len(findings) == 0

    def test_check_version_no_connection(self, tmp_cve_db):
        db = CVEDatabase(db_path=tmp_cve_db)
        findings = db.check_version("test_platform", "1.5")
        assert findings == []

    def test_finding_fields(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            findings = db.check_version("test_platform", "1.5")

        cve_ids = {f.cve for f in findings}
        assert "CVE-2024-00001" in cve_ids
        assert "CVE-2024-00002" in cve_ids

        kev_finding = next(f for f in findings if f.cve == "CVE-2024-00001")
        assert kev_finding.cisa_kev is True
        assert kev_finding.cvss == 8.1
        assert kev_finding.severity == "HIGH"


class TestKevFlagging:
    def test_flag_kev_findings(self, tmp_cve_db, mini_seed_dir):
        from skyhigh_scanner.core.finding import Finding

        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))

            f = Finding(
                rule_id="TEST", name="T", category="C",
                severity="HIGH", file_path="x", line_num=0,
                line_content="", description="D", recommendation="R",
                cve="CVE-2024-00001",
            )
            count = db.flag_kev_findings([f])

        assert count == 1
        assert f.cisa_kev is True

    def test_flag_kev_no_connection(self, tmp_cve_db):
        db = CVEDatabase(db_path=tmp_cve_db)
        assert db.flag_kev_findings([]) == 0


class TestStats:
    def test_stats(self, tmp_cve_db, mini_seed_dir):
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            stats = db.stats()

        assert stats["total"] == 2
        assert stats["kev"] == 1
        assert stats["platforms"]["test_platform"] == 2

    def test_stats_no_connection(self, tmp_cve_db):
        db = CVEDatabase(db_path=tmp_cve_db)
        assert db.stats() == {}


class TestRealSeedImport:
    """Import the actual seed files from the project to verify they parse."""

    def test_import_all_real_seeds(self, tmp_cve_db):
        seed_dir = Path(__file__).parent.parent / "skyhigh_scanner" / "cve_data" / "seed"
        if not seed_dir.exists():
            pytest.skip("Seed directory not found")

        with CVEDatabase(db_path=tmp_cve_db) as db:
            count = db.import_seed(str(seed_dir))

        assert count > 400, f"Expected 400+ CVEs, got {count}"
